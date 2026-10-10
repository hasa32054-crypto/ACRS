"""Phase 6 / E8 + E9: 500 held-out scenarios (seed 9001) and the pre-registered statistics.

    cd backend && python -m qacrs.phase6_heldout      -> results/v4/heldout.json + heldout_per_scenario.csv

Rules: docs/qacrs/PREREGISTRATION_v4.md. Nothing in the model is changed; the lock is checked before running.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from qacrs import escalation as E
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.independent_test import check_lock
from qacrs.meta import meta
from qacrs.network import build as build_net, random_scenarios, scenarios
from qacrs.phase3b_containment import METHODS
from qacrs.phase5_escalation import evaluate, summarise

OUT = Path(__file__).parent / "results" / "v4"
SEED, N_PER_NET = 9001, 250
CONTAINED = (S.CONTAINED, S.PENDING)


def heldout_pairs():
    pairs, dropped = [], []
    for net in (build_net(1), build_net(2)):
        seen = {tuple(sorted(s.hacked.items())) for s in scenarios(net)}
        for s in random_scenarios(net, N_PER_NET, SEED):
            key = tuple(sorted(s.hacked.items()))
            if key in seen:
                dropped.append(s.id); continue
            seen.add(key)
            s.id = s.id.replace("_r", "_ho")
            pairs.append((net, s))
    return pairs, dropped


def tests(rows: list[dict]) -> dict:
    q = [r["q_acrs"] for r in rows]; b = [r["full_isolation_safe"] for r in rows]
    n = len(rows)
    qc = [x["status"] in CONTAINED for x in q]; bc = [x["status"] in CONTAINED for x in b]
    qd = [len(x["services_down"]) for x in q]; bd = [len(x["services_down"]) for x in b]
    silent = sum(x["status"] == S.NOT_CONTAINED for x in q)
    q_only = sum(a and not c for a, c in zip(qc, bc)); b_only = sum(c and not a for a, c in zip(qc, bc))
    h1_ok_c = sum(qc) >= 0.8 * sum(bc); h1_ok_s = sum(qd) < sum(bd)
    lo, hi = stats.wilson(silent, n)
    w = stats.wilcoxon_less(qd, bd)
    return {
        "n": n,
        "H1_v3": {"q_contained": sum(qc), "safe_full_contained": sum(bc), "ratio": round(sum(qc) / sum(bc), 4) if sum(bc) else None,
                  "q_services_down": sum(qd), "safe_full_services_down": sum(bd),
                  "supported": h1_ok_c and h1_ok_s},
        "H2_silent_failures": {"count": silent, "rate": silent / n, "wilson95": [lo, hi], "supported": hi <= 0.02},
        "H3_services_down_wilcoxon_one_sided": w | {"supported": w["p"] < 0.05},
        "H4_containment_mcnemar": {"q_only_contained": q_only, "safe_full_only_contained": b_only,
                                   "p_two_sided": stats.mcnemar_exact(q_only, b_only),
                                   "direction": "safe full isolation contains more" if b_only > q_only else
                                                "Q-ACRS contains more" if q_only > b_only else "no difference"},
        "rates_wilson95": {m: {"contained": [sum(r[m]["status"] in CONTAINED for r in rows) / n,
                                             stats.wilson(sum(r[m]["status"] in CONTAINED for r in rows), n)],
                               "escalated": [sum(r[m]["status"] == E.ESCALATED for r in rows) / n,
                                             stats.wilson(sum(r[m]["status"] == E.ESCALATED for r in rows), n)],
                               "silent": [sum(r[m]["status"] == S.NOT_CONTAINED for r in rows) / n,
                                          stats.wilson(sum(r[m]["status"] == S.NOT_CONTAINED for r in rows), n)],
                               "rejected": [sum(r[m]["status"] == S.REJECTED for r in rows) / n,
                                            stats.wilson(sum(r[m]["status"] == S.REJECTED for r in rows), n)]}
                           for m in METHODS},
        "bootstrap95": {"containment_rate_q_minus_safe_full": stats.bootstrap_diff(qc, bc),
                        "services_down_per_scenario_q_minus_safe_full": stats.bootstrap_diff(qd, bd)},
    }


def main():
    drift = check_lock()
    if drift:
        sys.exit("REFUSED: locked code changed:\n  " + "\n  ".join(drift))
    pairs, dropped = heldout_pairs()
    rows = evaluate(pairs)
    dev_rows = evaluate([(net, s) for net in (build_net(1), build_net(2)) for s in scenarios(net)])
    res = {"meta": meta("phase6_heldout", ("phase6_heldout.py", "stats.py"), seed=SEED, per_network=N_PER_NET,
                        dropped_duplicates=dropped, lock="checked: identical to LOCK.json"),
           "summary": summarise(rows),
           "per_network": {name: summarise([r for r in rows if r["network"] == name]) for name in ("net12", "net22")},
           "tests_heldout": tests(rows), "tests_dev_secondary": tests(dev_rows), "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "heldout.json").write_text(json.dumps(res, indent=1))
    with (OUT / "heldout_per_scenario.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "network", "hacked", "method", "status", "isolate_now", "escalations",
                    "services_down", "healthy_isolated", "risk_left"])
        for r in rows:
            for m in METHODS:
                x = r[m]
                w.writerow([r["scenario"], r["network"], json.dumps(r["hacked"]), m, x["status"], " ".join(x["isolate_now"]),
                            " | ".join(e["action"] for e in x["escalations"]), " ".join(x["services_down"]),
                            " ".join(x["healthy_isolated"]), x["risk_left"]])
    t = res["tests_heldout"]
    print(f"held-out n={t['n']} (dropped {len(dropped)} duplicates)")
    for k, s in res["summary"].items():
        print(f"  {k:22} contained {s['contained']:>3}  escalated {s['escalated']:>3}  silent {s['silent_failures']:>3}  "
              f"rejected {s['status_counts'][S.REJECTED]:>3}  services down {s['services_down']:>4}")
    print(json.dumps({k: v for k, v in t.items() if k != "rates_wilson95"}, indent=1))


if __name__ == "__main__":
    main()
