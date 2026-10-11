"""Phase 5 / E1: the v3 escalation gate on the 40 development scenarios, for all four methods.

    cd backend && python -m qacrs.phase5_escalation      -> results/v3/escalation.json

Reminder (pre-registered): the gate was designed after seeing these scenarios' v2 failures, so this run only
shows that it does what it was built to do. Generalisation is tested on blind scenarios (independent_test.py).
"""
from __future__ import annotations

import json
from pathlib import Path

from qacrs import escalation as E
from qacrs import safety_checks as S
from qacrs.meta import meta
from qacrs.network import build as build_net, scenarios
from qacrs.phase3_compare import score
from qacrs.phase3b_containment import METHODS

OUT = Path(__file__).parent / "results" / "v3"


def evaluate(pairs, methods=METHODS) -> list[dict]:
    rows = []
    for net, sc in pairs:
        row = {"scenario": sc.id, "network": net.name, "hacked": sc.hacked, "description": sc.description}
        for name, fn in methods.items():
            iso = set(fn(net, sc))
            d = E.decide(net, sc, iso)
            base = score(net, sc, iso)
            row[name] = d.as_dict() | {"services_down": base["services_down"],
                                       "healthy_isolated": sorted(iso - set(sc.hacked)),
                                       "risk_left": base["risk_left"]}
        rows.append(row)
    return rows


def summarise(rows: list[dict], methods=METHODS) -> dict:
    out = {}
    for name in methods:
        r = [row[name] for row in rows]
        st = [x["status"] for x in r]
        out[name] = {"scenarios": len(r), "status_counts": {s: st.count(s) for s in E.STATUSES},
                     "contained": st.count(S.CONTAINED) + st.count(S.PENDING),
                     "silent_failures": st.count(S.NOT_CONTAINED), "escalated": st.count(E.ESCALATED),
                     "escalation_actions": sum(len(x["escalations"]) for x in r),
                     "services_down": sum(len(x["services_down"]) for x in r),
                     "healthy_isolated": sum(len(x["healthy_isolated"]) for x in r)}
    return out


def h1_v3(summary: dict) -> dict:
    q, b = summary["q_acrs"], summary["full_isolation_safe"]
    ok_c = q["contained"] >= 0.8 * b["contained"]
    ok_s = q["services_down"] < b["services_down"]
    return {"rule": "q_acrs contained >= 80% of full_isolation_safe contained AND strictly fewer services down",
            "containment_ratio": round(q["contained"] / b["contained"], 3) if b["contained"] else None,
            "containment_ok": ok_c, "fewer_services_down": ok_s, "H1_v3_supported": ok_c and ok_s,
            "healthy_isolated_reported": {"q_acrs": q["healthy_isolated"],
                                          "full_isolation_safe": b["healthy_isolated"]}}


def main():
    pairs = [(net, sc) for net in (build_net(1), build_net(2)) for sc in scenarios(net)]
    rows = evaluate(pairs)
    summ = summarise(rows)
    res = {"meta": meta("phase5_escalation", ("phase5_escalation.py",), scenarios="development (40)",
                        threshold=S.HIGH_RISK,
                        caveat="gate designed after seeing v2 failures on these scenarios"),
           "summary": summ, "h1_v3_dev_set": h1_v3(summ), "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "escalation.json").write_text(json.dumps(res, indent=1))
    print(f"{'method':22}{'contained':>10}{'escalated':>10}{'silent':>8}{'rejected':>9}{'svc down':>9}")
    for k, s in summ.items():
        print(f"{k:22}{s['contained']:>10}{s['escalated']:>10}{s['silent_failures']:>8}"
              f"{s['status_counts'][S.REJECTED]:>9}{s['services_down']:>9}")
    print("H1-v3 (dev set, not a new test):", res["h1_v3_dev_set"])


if __name__ == "__main__":
    main()
