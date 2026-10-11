"""Phase 5 / E2: weight sensitivity (one factor at a time) and the availability trade-off curve.

    cd backend && python -m qacrs.phase5_sensitivity     -> results/v3/sensitivity.json + sensitivity.csv

Rules: docs/qacrs/PREREGISTRATION_v3.md (E2). No weight is chosen from these results; the baseline stays 1.0.
Factors scale a COPY of the network (service values, machine disruptions) or qubo_builder.SPREAD, which is
restored afterwards. Solver: exact brute force (so solution quality is always optimal).
"""
from __future__ import annotations

import copy
import csv
import json
import time
from contextlib import contextmanager
from pathlib import Path

from qacrs import escalation as E
from qacrs import qubo_builder as QB
from qacrs import safety_checks as S
from qacrs.meta import meta
from qacrs.network import build as build_net, scenarios
from qacrs.phase3_compare import per_machine, q_acrs, services_down
from qacrs.phase3b_containment import full_isolation_safe

OUT = Path(__file__).parent / "results" / "v3"
LEVELS = (0.5, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.5)
LAMBDAS = (0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0)
ROBUST_RANGE, ROBUST_MAX_CHANGED = 0.30, 4


def scaled(net, f_service=1.0, f_disruption=1.0):
    n = copy.deepcopy(net)
    for s in n.services:
        s.value = s.value * f_service
    for m in n.machines:
        m.disruption = m.disruption * f_disruption
    return n


@contextmanager
def spread(f):
    old = QB.SPREAD
    QB.SPREAD = old * f
    try:
        yield
    finally:
        QB.SPREAD = old


BASE_NETS = (build_net(1), build_net(2))
PAIRS = [(i, sc) for i, net in enumerate(BASE_NETS) for sc in scenarios(net)]


def run_config(f_service=1.0, f_disruption=1.0, f_spread=1.0) -> dict:
    nets = [scaled(n, f_service, f_disruption) for n in BASE_NETS]
    t = time.perf_counter()
    decisions, statuses, down, healthy, risk_left = {}, [], 0, 0, 0
    with spread(f_spread):
        for i, sc in PAIRS:
            net = nets[i]
            iso, _, _ = q_acrs(net, sc)
            decisions[sc.id] = sorted(iso)
            statuses.append(E.decide(net, sc, iso).status)
            down += len(services_down(net, iso))
            healthy += len(iso - set(sc.hacked))
            risk_left += sum(r for h, r in sc.hacked.items() if h not in iso)
    return {"f_service": f_service, "f_disruption": f_disruption, "f_spread": f_spread,
            "contained": statuses.count(S.CONTAINED) + statuses.count(S.PENDING),
            "pending_two_person": statuses.count(S.PENDING), "escalated": statuses.count(E.ESCALATED),
            "silent_failures": statuses.count(S.NOT_CONTAINED), "rejected": statuses.count(S.REJECTED),
            "services_down": down, "healthy_isolated": healthy, "risk_left": risk_left,
            "solve_seconds": round(time.perf_counter() - t, 3), "decisions": decisions}


def changed(a: dict, b: dict) -> list[str]:
    return sorted(k for k in a if a[k] != b[k])


def reference(method) -> dict:
    statuses, down = [], 0
    for i, sc in PAIRS:
        net = BASE_NETS[i]
        iso = set(method(net, sc))
        statuses.append(E.decide(net, sc, iso).status)
        down += len(services_down(net, iso))
    return {"contained": statuses.count(S.CONTAINED) + statuses.count(S.PENDING),
            "escalated": statuses.count(E.ESCALATED), "silent_failures": statuses.count(S.NOT_CONTAINED),
            "services_down": down}


def main():
    base = run_config()
    oat = []
    for factor in ("f_service", "f_disruption", "f_spread"):
        for lv in LEVELS:
            r = base if lv == 1.0 else run_config(**{factor: lv})
            ch = changed(base["decisions"], r["decisions"])
            oat.append({k: v for k, v in r.items() if k != "decisions"} | {"factor": factor, "level": lv,
                                                                          "changed": len(ch), "changed_ids": ch})
    verdict = {}
    for factor in ("f_service", "f_disruption", "f_spread"):
        rows = [r for r in oat if r["factor"] == factor]
        within = [r for r in rows if abs(r["level"] - 1) <= ROBUST_RANGE + 1e-9]
        worst = max(r["changed"] for r in within)
        first = next((r["level"] for r in sorted(rows, key=lambda r: abs(r["level"] - 1)) if r["changed"] > 0), None)
        verdict[factor] = {"robust": worst <= ROBUST_MAX_CHANGED, "max_changed_within_30pct": worst,
                           "closest_level_with_any_change": first}
    pareto = []
    for lam in LAMBDAS:
        r = base if lam == 1.0 else run_config(f_service=lam, f_disruption=lam)
        pareto.append({k: v for k, v in r.items() if k != "decisions"} | {"lambda": lam,
                                                                         "changed": len(changed(base["decisions"], r["decisions"]))})
    refs = {"full_isolation_safe": reference(full_isolation_safe), "per_machine": reference(per_machine)}
    res = {"meta": meta("phase5_sensitivity", ("phase5_sensitivity.py",), levels=LEVELS, lambdas=LAMBDAS,
                        robust_rule=f"<= {ROBUST_MAX_CHANGED}/40 decisions change for every level within ±30%",
                        solver="exact brute force", scenarios=len(PAIRS)),
           "baseline": {k: v for k, v in base.items() if k != "decisions"}, "one_at_a_time": oat,
           "verdict": verdict, "pareto": pareto, "references": refs}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sensitivity.json").write_text(json.dumps(res, indent=1))
    with (OUT / "sensitivity.csv").open("w", newline="") as f:
        cols = ["factor", "level", "contained", "pending_two_person", "escalated", "silent_failures", "rejected",
                "services_down", "healthy_isolated", "risk_left", "changed", "solve_seconds"]
        w = csv.DictWriter(f, cols, extrasaction="ignore"); w.writeheader(); w.writerows(oat)
        for p in pareto:
            w.writerow(p | {"factor": "lambda(service+disruption)", "level": p["lambda"]})
    print("verdict:", json.dumps(verdict, indent=1))
    print(f"{'lambda':>7}{'contained':>10}{'escalated':>10}{'silent':>7}{'svc down':>9}{'risk left':>10}{'changed':>8}")
    for p in pareto:
        print(f"{p['lambda']:>7}{p['contained']:>10}{p['escalated']:>10}{p['silent_failures']:>7}"
              f"{p['services_down']:>9}{p['risk_left']:>10}{p['changed']:>8}")
    print("references:", refs)


if __name__ == "__main__":
    main()
