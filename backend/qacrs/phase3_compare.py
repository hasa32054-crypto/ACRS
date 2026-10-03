"""Phase 3: compare three ways to respond on all 40 scenarios.

    cd ~/ACRS/backend && python -m qacrs.phase3_compare

  full_isolation   isolate every hacked machine (what many tools do)
  per_machine      decide each machine ALONE by a simple rule (isolate if risk >= 6, never isolate devices
                   that must stay up, leave core servers to humans). Sees no relationships between machines.
                   This is a simplified rule in the spirit of ACRS, NOT the full ACRS engine.
  q_acrs           the QUBO optimum (found here by exact brute force; Phase 4 finds it with QAOA)

Every decision then goes through the same classical safety check (verify).
Also checks a heuristic solver (simulated annealing) against the exact optimum.
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path

import numpy as np

from qacrs.network import build as build_net, scenarios
from qacrs.qubo_builder import build, decision_from_bits, services_down, verify

OUT = Path(__file__).parent / "results"
THRESHOLD = 6


def full_isolation(net, sc):
    return set(sc.hacked)


def per_machine(net, sc):
    m = {x.name: x for x in net.machines}
    return {h for h, r in sc.hacked.items() if r >= THRESHOLD and m[h].isolatable and not m[h].critical}


def q_acrs(net, sc):
    q = build(net, sc)
    vals = q.all_values()
    k = int(np.argmin(vals))
    x = [(k >> i) & 1 for i in range(q.n)]
    return decision_from_bits(q, x), q, float(vals[k])


def annealing(q, steps=4000, restarts=5, seed=1):
    rng = random.Random(seed); best = None
    for _ in range(restarts):
        x = [rng.randint(0, 1) for _ in range(q.n)]; e = q.value(x)
        for t in range(steps):
            T = 10 * (1 - t / steps) + 1e-3
            i = rng.randrange(q.n); x[i] ^= 1; e2 = q.value(x)
            if e2 <= e or rng.random() < np.exp((e - e2) / T): e = e2
            else: x[i] ^= 1
        if best is None or e < best: best = e
    return best


def score(net, sc, isolated):
    """Score any decision with the SAME full-network cost (without the BIG rule penalty; unsafe decisions are
    counted on their own), so the three methods are compared fairly."""
    qf = build(net, sc, full=True, hard=False)
    x = [1 if n in isolated else 0 for n in qf.names]
    left = sum(r for h, r in sc.hacked.items() if h not in isolated)
    v = verify(net, isolated)
    return {"isolated": sorted(isolated), "cost": round(qf.value(x), 2), "risk_left": left,
            "services_down": services_down(net, isolated), "violations": v["violations"],
            "two_person": v["needs_two_person"]}


def main():
    rows = []
    t0 = time.perf_counter()
    for net in (build_net(1), build_net(2)):
        for sc in scenarios(net):
            dec, q, opt = q_acrs(net, sc)
            sa = annealing(q)
            r = {"scenario": sc.id, "hacked": sc.hacked, "description": sc.description,
                 "machines": len(net.machines), "qubits": q.n,
                 "full_isolation": score(net, sc, full_isolation(net, sc)),
                 "per_machine": score(net, sc, per_machine(net, sc)),
                 "q_acrs": score(net, sc, dec),
                 "annealing_found_optimum": abs(sa - opt) < 1e-9}
            rows.append(r)
    secs = time.perf_counter() - t0

    print(f"{'scenario':12}{'qubits':>7}  {'full isolation':>20}{'per machine':>20}{'Q-ACRS':>20}")
    print(f"{'':12}{'':>7}  {'cost/down/unsafe':>20}{'cost/down/unsafe':>20}{'cost/down/unsafe':>20}")
    for r in rows[:14]:
        f = lambda s: f"{s['cost']:>8}/{len(s['services_down'])}/{len(s['violations'])}"
        print(f"{r['scenario']:12}{r['qubits']:>7}  {f(r['full_isolation']):>20}{f(r['per_machine']):>20}{f(r['q_acrs']):>20}")
    print(f"  ... {len(rows)} scenarios in total\n")

    summary = {}
    for k in ("full_isolation", "per_machine", "q_acrs"):
        s = [r[k] for r in rows]
        summary[k] = {"total_cost": round(sum(x["cost"] for x in s), 1),
                      "services_down": sum(len(x["services_down"]) for x in s),
                      "unsafe_decisions": sum(bool(x["violations"]) for x in s),
                      "risk_left": sum(x["risk_left"] for x in s),
                      "best_safe": sum(not x["violations"] and x["cost"] <= min(r[j]["cost"] for j in ("full_isolation", "per_machine", "q_acrs")
                                                                          if not r[j]["violations"]) + 1e-9
                                       for x, r in zip(s, rows))}
    print(f"{'method':16}{'total cost':>12}{'services down':>15}{'unsafe':>8}{'risk left':>11}{'best safe':>11}")
    for k, s in summary.items():
        print(f"{k:16}{s['total_cost']:>12}{s['services_down']:>15}{s['unsafe_decisions']:>8}{s['risk_left']:>11}{s['best_safe']:>6}/{len(rows)}")
    qb = [r["qubits"] for r in rows]; mach = [r["machines"] for r in rows]
    print(f"\nProblem reduction: {np.mean(mach):.1f} machines -> {np.mean(qb):.1f} qubits on average (max {max(qb)})")
    print(f"Simulated annealing found the exact optimum in {sum(r['annealing_found_optimum'] for r in rows)}/{len(rows)} scenarios")
    print(f"Q-ACRS safety check: {len(rows) - summary['q_acrs']['unsafe_decisions']}/{len(rows)} decisions pass")
    print(f"Time for all scenarios: {secs:.1f} s")

    OUT.mkdir(exist_ok=True)
    (OUT / "phase3_compare.json").write_text(json.dumps({
        "note": "Weights are design assumptions; per_machine is a simplified ACRS-style rule, not the full engine.",
        "summary": summary, "rows": rows}, indent=1))
    print("Saved: qacrs/results/phase3_compare.json")


if __name__ == "__main__":
    main()
