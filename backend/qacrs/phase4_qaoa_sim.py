"""Phase 4a: QAOA on all 40 scenarios (noiseless simulation), depth p = 1, 2, 3.

    cd ~/ACRS/backend && python -m qacrs.phase4_qaoa_sim

The simulator here is a small exact state-vector simulator written with numpy (same maths as Qiskit's
Statevector; Lesson 2 gave the identical 98.1% both ways). It is used because it runs all 40 scenarios x 3
depths in a few minutes. Phase 4b runs selected scenarios on the real IBM QPU with Qiskit.

Steps per scenario:
  1. Build the QUBO (Phase 3). Machines that must NEVER be isolated are fixed to x = 0 and removed, so the
     hard rule cannot be broken and the quantum part gets fewer qubits (constraint elimination).
  2. QAOA: start in all decisions at once, apply cost layer + mixer p times, tune the 2p angles (COBYLA).
  3. Measure how good the final quantum state is:
       p_best     chance ONE measurement gives an optimal decision
       hit_100    chance that at least one of 100 measurements is optimal (each one is checked classically,
                  so in practice we keep the cheapest one; this is how the hybrid uses QAOA)
       ratio      approximation ratio of the average answer (1.0 = always optimal, 0 = always worst)
       random     chance a random guess is optimal (the baseline)
Brute force is used ONLY to grade QAOA (to know what "optimal" is), never inside QAOA.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from qacrs.network import build as build_net, scenarios
from qacrs.qubo_builder import Qubo, build

OUT = Path(__file__).parent / "results"
DEPTHS = (1, 2, 3)
RESTARTS = 6


def fix_zero(q: Qubo, drop: set[str]) -> Qubo:
    """Set x = 0 for the machines in `drop` and remove them (any term containing them becomes 0)."""
    keep = [i for i, n in enumerate(q.names) if n not in drop]
    new = {old: k for k, old in enumerate(keep)}
    return Qubo([q.names[i] for i in keep], q.const,
                {new[i]: a for i, a in q.lin.items() if i in new},
                {(new[i], new[j]): b for (i, j), b in q.quad.items() if i in new and j in new})


def mixer(psi: np.ndarray, n: int, beta: float) -> np.ndarray:
    """Apply RX(2 beta) to every qubit of the state vector."""
    c, s = np.cos(beta), -1j * np.sin(beta)
    for i in range(n):
        v = psi.reshape(-1, 2, 2 ** i)
        a, b = v[:, 0, :].copy(), v[:, 1, :].copy()
        v[:, 0, :], v[:, 1, :] = c * a + s * b, s * a + c * b
    return psi


def qaoa_state(cost: np.ndarray, n: int, gammas, betas) -> np.ndarray:
    psi = np.full(2 ** n, 2 ** (-n / 2), dtype=complex)        # Hadamard on every qubit
    for g, b in zip(gammas, betas):
        psi = psi * np.exp(-1j * g * cost)                      # cost layer (diagonal)
        psi = mixer(psi, n, b)
    return np.abs(psi) ** 2


def run_qaoa(q: Qubo, p: int, warm=None, seed=0):
    vals = q.all_values()
    scale = sum(abs(a) for a in q.lin.values()) + sum(abs(b) for b in q.quad.values()) or 1.0
    cost = (vals - q.const) / scale                             # scaling known WITHOUT brute force
    rng = np.random.default_rng(seed)
    f = lambda t: float(qaoa_state(cost, q.n, t[:p], t[p:]) @ cost)
    starts = [rng.uniform(0, np.pi, 2 * p) for _ in range(RESTARTS)]
    if warm is not None:                                        # reuse the depth p-1 angles (warm start)
        g, b = warm[: p - 1], warm[p - 1:]
        starts.append(np.concatenate([g, [g[-1]], b, [b[-1]]]))
    best = min((minimize(f, s, method="COBYLA", options={"maxiter": 300}) for s in starts), key=lambda r: r.fun)
    return best.x, qaoa_state(cost, q.n, best.x[:p], best.x[p:]), vals


def grade(probs: np.ndarray, vals: np.ndarray) -> dict:
    lo, hi = vals.min(), vals.max()
    opt = np.isclose(vals, lo)
    p_best = float(probs[opt].sum())
    mean = float(probs @ vals)
    return {"p_best": round(p_best, 4), "hit_100": round(1 - (1 - p_best) ** 100, 4),
            "ratio": round((hi - mean) / (hi - lo), 4) if hi > lo else 1.0,
            "random": round(opt.sum() / len(vals), 4)}


def main():
    rows = []; t0 = time.perf_counter()
    for net in (build_net(1), build_net(2)):
        never = {m.name for m in net.machines if not m.isolatable}
        for sc in scenarios(net):
            q = fix_zero(build(net, sc), never)
            row = {"scenario": sc.id, "qubits": q.n}
            if q.n == 0:
                row["note"] = "nothing can be isolated: restrict only, no quantum step needed"
                rows.append(row); continue
            warm = None
            for p in DEPTHS:
                t = time.perf_counter()
                warm, probs, vals = run_qaoa(q, p, warm)
                row[f"p{p}"] = grade(probs, vals) | {"seconds": round(time.perf_counter() - t, 2)}
            rows.append(row)
            g = row[f"p{DEPTHS[-1]}"]
            print(f"{sc.id:12} {q.n:>2} qubits   p_best " +
                  "  ".join(f"p{p}={row[f'p{p}']['p_best']:.0%}" for p in DEPTHS) +
                  f"   random={g['random']:.1%}   hit_100={g['hit_100']:.0%}")

    done = [r for r in rows if r["qubits"]]
    print(f"\n{len(done)} scenarios with a quantum step ({len(rows) - len(done)} need none). Total {time.perf_counter() - t0:.0f} s\n")
    print(f"{'qubits':>8}{'count':>7}" + "".join(f"{'p_best p' + str(p):>13}" for p in DEPTHS) + f"{'random':>9}{'hit_100':>9}")
    by = {}
    for r in done: by.setdefault(r["qubits"], []).append(r)
    summary = {}
    for n in sorted(by):
        rs = by[n]; m = lambda k, p: float(np.mean([r[f'p{p}'][k] for r in rs]))
        summary[n] = {"count": len(rs), **{f"p_best_p{p}": round(m('p_best', p), 4) for p in DEPTHS},
                      "random": round(m('random', DEPTHS[-1]), 4), "hit_100": round(m('hit_100', DEPTHS[-1]), 4)}
        s = summary[n]
        print(f"{n:>8}{len(rs):>7}" + "".join(f"{s[f'p_best_p{p}']:>13.1%}" for p in DEPTHS) + f"{s['random']:>9.1%}{s['hit_100']:>9.1%}")
    allp = lambda k: float(np.mean([r[f"p{DEPTHS[-1]}"][k] for r in done]))
    print(f"\nAverage over all: p_best {allp('p_best'):.1%} vs random {allp('random'):.1%};  "
          f"optimum found within 100 shots in {sum(r[f'p{DEPTHS[-1]}']['hit_100'] > 0.99 for r in done)}/{len(done)} scenarios (>99% chance)")

    OUT.mkdir(exist_ok=True)
    (OUT / "phase4_qaoa_sim.json").write_text(json.dumps({
        "note": "Noiseless exact state-vector simulation (numpy). Brute force used only to grade.",
        "by_qubits": summary, "rows": rows}, indent=1))
    print("Saved: qacrs/results/phase4_qaoa_sim.json")


if __name__ == "__main__":
    main()
