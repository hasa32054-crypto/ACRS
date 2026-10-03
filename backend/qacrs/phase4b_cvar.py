"""Phase 4b: make QAOA stronger on the hard scenarios (7+ qubits) with CVaR, and compare before / after.

    cd ~/ACRS/backend && python -m qacrs.phase4b_cvar

Before (Phase 4a): tune the angles to lower the AVERAGE cost of all measurements.
After  (CVaR):      tune the angles to lower the average cost of only the BEST alpha = 10% of measurements.
Why it fits Q-ACRS: the hybrid measures many times and the classical check keeps the cheapest safe answer, so
only the good tail matters, not the average (Barkoutsos et al., "Improving Variational Quantum Optimization
using CVaR", 2020 - to be checked before citing).

Same scenarios, same simulator, same depths, same number of restarts; only the objective changes.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from qacrs.network import build as build_net, scenarios
from qacrs.phase4_qaoa_sim import RESTARTS, fix_zero, grade, qaoa_state
from qacrs.qubo_builder import build

OUT = Path(__file__).parent / "results"
ALPHA, DEPTHS, MIN_QUBITS = 0.10, (1, 2, 3), 7


def objective(kind: str, cost: np.ndarray):
    order = np.argsort(cost, kind="stable"); sorted_cost = cost[order]
    def mean(probs): return float(probs @ cost)
    def cvar(probs):
        p = probs[order]; c = np.cumsum(p)
        take = np.clip(ALPHA - (c - p), 0, p)                 # probability mass taken from each state, best first
        return float(take @ sorted_cost) / ALPHA
    return mean if kind == "mean" else cvar


def tune(q, p, kind, warm=None, seed=0):
    vals = q.all_values()
    scale = sum(abs(a) for a in q.lin.values()) + sum(abs(b) for b in q.quad.values()) or 1.0
    cost = (vals - q.const) / scale
    obj = objective(kind, cost)
    f = lambda t: obj(qaoa_state(cost, q.n, t[:p], t[p:]))
    rng = np.random.default_rng(seed)
    starts = [rng.uniform(0, np.pi, 2 * p) for _ in range(RESTARTS)]
    if warm is not None:
        g, b = warm[: p - 1], warm[p - 1:]
        starts.append(np.concatenate([g, [g[-1]], b, [b[-1]]]))
    best = min((minimize(f, s, method="COBYLA", options={"maxiter": 300}) for s in starts), key=lambda r: r.fun)
    return best.x, qaoa_state(cost, q.n, best.x[:p], best.x[p:]), vals


def main():
    rows = []; t0 = time.perf_counter()
    print(f"Hard scenarios only ({MIN_QUBITS}+ qubits). p_best = chance ONE measurement is optimal.\n")
    print(f"{'scenario':12}{'qubits':>7}  {'mean p1/p2/p3':>22}  {'CVaR p1/p2/p3':>22}{'random':>9}")
    for net in (build_net(1), build_net(2)):
        never = {m.name for m in net.machines if not m.isolatable}
        for sc in scenarios(net):
            q = fix_zero(build(net, sc), never)
            if q.n < MIN_QUBITS: continue
            row = {"scenario": sc.id, "qubits": q.n}
            for kind in ("mean", "cvar"):
                warm = None
                for p in DEPTHS:
                    warm, probs, vals = tune(q, p, kind, warm)
                    row[f"{kind}_p{p}"] = grade(probs, vals)
            rows.append(row)
            fmt = lambda k: "/".join(f"{row[f'{k}_p{p}']['p_best']:.0%}" for p in DEPTHS)
            print(f"{sc.id:12}{q.n:>7}  {fmt('mean'):>22}  {fmt('cvar'):>22}{row['mean_p1']['random']:>9.2%}", flush=True)

    P = DEPTHS[-1]
    avg = lambda k, m: float(np.mean([r[f"{k}_p{P}"][m] for r in rows]))
    ok = lambda k: sum(r[f"{k}_p{P}"]["hit_100"] > 0.99 for r in rows)
    print(f"\n{len(rows)} hard scenarios, depth p={P}:")
    print(f"{'':24}{'mean (before)':>15}{'CVaR (after)':>15}")
    print(f"{'p_best (one shot)':24}{avg('mean', 'p_best'):>15.1%}{avg('cvar', 'p_best'):>15.1%}")
    print(f"{'optimum in 100 shots':24}{ok('mean'):>12}/{len(rows)}{ok('cvar'):>12}/{len(rows)}")
    print(f"{'random guess':24}{avg('mean', 'random'):>15.2%}")
    by = {}
    for r in rows: by.setdefault(r["qubits"], []).append(r)
    print(f"\n{'qubits':>7}{'mean p_best':>13}{'CVaR p_best':>13}{'gain':>8}")
    summary = {}
    for n in sorted(by):
        a = np.mean([r[f"mean_p{P}"]["p_best"] for r in by[n]]); b = np.mean([r[f"cvar_p{P}"]["p_best"] for r in by[n]])
        summary[n] = {"count": len(by[n]), "mean_p_best": round(float(a), 4), "cvar_p_best": round(float(b), 4)}
        print(f"{n:>7}{a:>13.1%}{b:>13.1%}{b / a if a else float('nan'):>7.1f}x")
    print(f"\nTime: {time.perf_counter() - t0:.0f} s")
    OUT.mkdir(exist_ok=True)
    (OUT / "phase4b_cvar.json").write_text(json.dumps({
        "note": f"Noiseless simulation. Only the objective changes (mean vs CVaR alpha={ALPHA}).",
        "by_qubits": summary, "rows": rows}, indent=1))
    print("Saved: qacrs/results/phase4b_cvar.json")


if __name__ == "__main__":
    main()
