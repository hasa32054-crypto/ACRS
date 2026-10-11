"""E9 library: a whole multi-hospital incident decision on one quantum chip. Rules: docs/qacrs/PREREGISTRATION_E9.md.

    cd backend && python -m qacrs.quantum_scale        # (re)build the design -> results/v3/ibm/e9_design.json

  * cluster(k): k copies of Hospital-60 joined by inter-site links
  * tight_qubo: v7 QUBO with never-isolate machines fixed to 0 and minimal sufficient one-hot penalties
  * components: independent sub-problems; exact_milp: exact optimum (HiGHS) used as ground truth
  * design(): per-component QAOA depth/angles chosen by lowest expected cost on the noiseless simulator
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from dataclasses import replace
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp, minimize
from scipy.sparse import lil_matrix

from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs.network import Network, Scenario, Service, check
from qacrs.phase4_qaoa_sim import qaoa_state
from qacrs.qubo_builder import Qubo

OUT = Path(__file__).parent / "results" / "v3" / "ibm"
SITES, N_HACKED, SEED = 4, 80, 9090
GAMMA_MAX, RESTARTS, BIG_COMPONENT = 40.0, 8, 16


# ------------------------------------------------------------------ network and incident -------------------------
def cluster(k: int = SITES) -> Network:
    base = RV.hospital60()
    M, S, L = [], [], []
    for i in range(k):
        p = f"@s{i}"
        M += [replace(m, name=m.name + p) for m in base.machines]
        S += [Service(s.name + p, s.value, [r + p for r in s.replicas], [d + p for d in s.depends_on]) for s in base.services]
        L += [(a + p, b + p) for a, b in base.links]
    for i in range(k):
        j = (i + 1) % k
        L += [(f"vpn@s{i}", f"files@s{j}"), (f"hl7_1@s{i}", f"hl7_2@s{j}"), (f"pc_admin1@s{i}", f"dc2@s{j}")]
    net = Network(f"cluster{k}", M, S, L)
    check(net)
    return net


def incident(net: Network, n_hacked: int = N_HACKED, seed: int = SEED) -> Scenario:
    rng = random.Random(seed)
    names = [m.name for m in net.machines]
    return Scenario(f"{net.name}_mass{seed}", net.name, {m: rng.randint(3, 9) for m in rng.sample(names, n_hacked)},
                    f"mass incident: {n_hacked} machines across {net.name}")


# ------------------------------------------------------------------ penalty-tight QUBO ---------------------------
def tight_qubo(net: Network, sc: Scenario) -> tuple[Qubo, Qubo]:
    """Returns (tight, original). Never-isolate machines fixed to 0 (removed); each x_m*s_m penalty set to
    1 + sum |coefficients touching s_m| — enough that no optimum isolates and segments the same server."""
    q = V7.build_v7(net, sc)
    machines = {m.name: m for m in net.machines}
    fixed0 = {i for i, n in enumerate(q.names) if not n.endswith(V7.SEG) and not machines[n].isolatable}
    pen = {(i, j) for (i, j) in q.quad if q.names[j] == q.names[i] + V7.SEG or q.names[i] == q.names[j] + V7.SEG}
    keep = [i for i in range(q.n) if i not in fixed0]
    loc = {g: k for k, g in enumerate(keep)}
    lin = {loc[i]: a for i, a in q.lin.items() if i in loc}
    quad = {(loc[i], loc[j]): b for (i, j), b in q.quad.items() if i in loc and j in loc and (i, j) not in pen}
    for (i, j) in sorted(pen):
        if i in loc and j in loc:
            s = loc[j] if q.names[j].endswith(V7.SEG) else loc[i]
            quad[(loc[i], loc[j])] = 1.0 + abs(lin.get(s, 0.0)) + sum(abs(b) for (a, c), b in quad.items() if s in (a, c))
    return Qubo([q.names[i] for i in keep], q.const, lin, quad), q


def components(q: Qubo) -> list[tuple[list[int], Qubo]]:
    par = list(range(q.n))

    def f(a):
        while par[a] != a:
            par[a] = par[par[a]]; a = par[a]
        return a
    for (i, j) in q.quad:
        par[f(i)] = f(j)
    groups: dict[int, list[int]] = {}
    for i in range(q.n):
        groups.setdefault(f(i), []).append(i)
    out = []
    for idx in sorted(groups.values(), key=lambda g: (-len(g), g[0])):
        loc = {g: k for k, g in enumerate(idx)}
        out.append((idx, Qubo([q.names[i] for i in idx], 0.0, {loc[i]: a for i, a in q.lin.items() if i in loc},
                              {(loc[i], loc[j]): b for (i, j), b in q.quad.items() if i in loc and j in loc})))
    return out


def exact_milp(q: Qubo) -> tuple[float, list[int]]:
    """Exact QUBO optimum via the standard linearisation y_ij = x_i x_j, solved by HiGHS."""
    n, quad = q.n, list(q.quad.items())
    m = n + len(quad)
    if m == 0:
        return float(q.const), []
    c = np.zeros(m)
    for i, a in q.lin.items():
        c[i] += a
    cons = None
    if quad:
        A = lil_matrix((3 * len(quad), m)); lb, ub = [], []
        for k, ((i, j), b) in enumerate(quad):
            y = n + k; c[y] = b
            A[3 * k, y], A[3 * k, i] = 1, -1; lb.append(-np.inf); ub.append(0)
            A[3 * k + 1, y], A[3 * k + 1, j] = 1, -1; lb.append(-np.inf); ub.append(0)
            A[3 * k + 2, y], A[3 * k + 2, i], A[3 * k + 2, j] = 1, -1, -1; lb.append(-1); ub.append(np.inf)
        cons = LinearConstraint(A.tocsr(), lb, ub)
    r = milp(c, constraints=cons, integrality=np.ones(m), bounds=Bounds(0, 1))
    x = [int(round(v)) for v in r.x[:n]]
    return float(q.value(x)), x


# ------------------------------------------------------------------ QAOA design ----------------------------------
def scale_of(q: Qubo) -> float:
    return sum(abs(a) for a in q.lin.values()) + sum(abs(b) for b in q.quad.values()) or 1.0


def norm_cost(q: Qubo):
    vals = q.all_values()
    return vals, (vals - q.const) / scale_of(q)


def tune(q: Qubo, p: int, seed: int = 0):
    vals, cost = norm_cost(q)
    f = lambda t: float(qaoa_state(cost, q.n, t[:p], t[p:]) @ cost)
    if q.n > BIG_COMPONENT:                                   # p = 1 grid + local refinement
        grid = [(f([g, b]), g, b) for g in np.linspace(0.5, GAMMA_MAX, 24) for b in np.linspace(0.1, np.pi - 0.1, 9)]
        _, g0, b0 = min(grid)
        r = minimize(f, [g0, b0], method="COBYLA", options={"maxiter": 60})
    else:
        rng = np.random.default_rng(seed)
        r = min((minimize(f, np.concatenate([rng.uniform(0, GAMMA_MAX, p), rng.uniform(0, np.pi, p)]), method="COBYLA",
                          options={"maxiter": 400}) for _ in range(RESTARTS)), key=lambda z: z.fun)
    probs = qaoa_state(cost, q.n, r.x[:p], r.x[p:])
    opt = np.isclose(vals, vals.min())
    return {"p": p, "theta": [float(v) for v in r.x], "expected_cost_norm": float(r.fun),
            "ideal_p_opt": float(probs[opt].sum()), "n_optima": int(opt.sum()), "opt_value": float(vals.min())}


def qubo_hash(q: Qubo) -> str:
    return hashlib.sha256(json.dumps([q.names, q.const, sorted(q.lin.items()), sorted(q.quad.items())]).encode()).hexdigest()[:16]


def design() -> dict:
    t = time.perf_counter()
    net = cluster(); sc = incident(net)
    qt, q = tight_qubo(net, sc)
    e_orig, _ = exact_milp(q); e_tight, x_tight = exact_milp(qt)
    comps = components(qt)
    out = {"experiment": "E9", "network": net.name, "machines": len(net.machines), "scenario": sc.id,
           "hacked": len(sc.hacked), "vars_original": q.n, "vars_tight": qt.n, "milp_opt_original": e_orig,
           "milp_opt_tight": e_tight, "tight_equivalent": abs(e_orig - e_tight) < 1e-6, "qubo_hash": qubo_hash(qt),
           "components": []}
    for idx, cq in comps:
        row = {"vars": [qt.names[i] for i in idx], "n": cq.n, "hash": qubo_hash(cq)}
        if cq.n == 1:
            a = cq.lin.get(0, 0.0)
            row |= {"mode": "classical_singleton", "x": [1 if a < 0 else 0]}
        else:
            ps = (1,) if cq.n > BIG_COMPONENT else (1, 2, 3)
            cands = [tune(cq, p) for p in ps]
            best = min(cands, key=lambda c: c["expected_cost_norm"])          # deployable choice, optimum not used
            row |= {"mode": "qpu", **best, "candidates": [{k: c[k] for k in ("p", "expected_cost_norm", "ideal_p_opt")} for c in cands]}
            print(f"  component {cq.n:>2} qubits: p={best['p']} ideal p_opt {best['ideal_p_opt']:.3f} "
                  f"(random {best['n_optima'] / 2 ** cq.n:.4f})", flush=True)
        out["components"].append(row)
    out["qpu_qubits_total"] = sum(c["n"] for c in out["components"] if c["mode"] == "qpu")
    out["seconds"] = round(time.perf_counter() - t, 1)
    return out


if __name__ == "__main__":
    d = design()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "e9_design.json").write_text(json.dumps(d, indent=1))
    print(json.dumps({k: v for k, v in d.items() if k != "components"}, indent=1))
