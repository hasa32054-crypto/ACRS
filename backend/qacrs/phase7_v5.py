"""Phase 7 (v5): the twin-dilemma gate, confirmed on a FRESH held-out set (seed 9002).

    cd backend && python -m qacrs.phase7_v5      -> results/v5/v5_heldout.json

Rules: docs/qacrs/PREREGISTRATION_v5.md. 9002 = confirmatory; 9001 and development = secondary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from qacrs import escalation as E
from qacrs import escalation_v5 as E5
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.independent_test import check_lock
from qacrs.meta import meta
from qacrs.network import build as build_net, random_scenarios, scenarios
from qacrs.phase3_compare import score
from qacrs.phase3b_containment import METHODS
from qacrs.phase6_heldout import heldout_pairs, tests

OUT = Path(__file__).parent / "results" / "v5"
SEED, N_PER_NET = 9002, 250


def fresh_pairs():
    old = {}
    for net, s in heldout_pairs()[0]:
        old.setdefault(net.name, set()).add(tuple(sorted(s.hacked.items())))
    pairs, dropped = [], []
    for net in (build_net(1), build_net(2)):
        seen = {tuple(sorted(s.hacked.items())) for s in scenarios(net)} | old.get(net.name, set())
        for s in random_scenarios(net, N_PER_NET, SEED):
            key = tuple(sorted(s.hacked.items()))
            if key in seen:
                dropped.append(s.id); continue
            seen.add(key)
            s.id = s.id.replace("_r", "_v5ho")
            pairs.append((net, s))
    return pairs, dropped


def evaluate(pairs):
    rows = []
    for net, sc in pairs:
        row = {"scenario": sc.id, "network": net.name, "hacked": sc.hacked}
        for name, fn in METHODS.items():
            iso = set(fn(net, sc))
            d5 = E5.decide(net, sc, iso); d3 = E.decide(net, sc, iso); base = score(net, sc, iso)
            row[name] = d5.as_dict() | {"status_v3_gate": d3.status, "services_down": base["services_down"],
                                        "healthy_isolated": sorted(iso - set(sc.hacked)), "risk_left": base["risk_left"]}
        rows.append(row)
    return rows


def block(rows):
    n = len(rows)
    out = {"tests": tests(rows), "gate_comparison_q_acrs": {}}
    for gate, key in (("v3", "status_v3_gate"), ("v5", "status")):
        st = [r["q_acrs"][key] for r in rows]
        sil, esc = st.count(S.NOT_CONTAINED), st.count(E.ESCALATED)
        out["gate_comparison_q_acrs"][gate] = {"silent": sil, "silent_wilson95": stats.wilson(sil, n),
                                               "escalated": esc, "escalation_rate": esc / n,
                                               "escalation_wilson95": stats.wilson(esc, n)}
    out["H2_v5_supported"] = out["gate_comparison_q_acrs"]["v5"]["silent_wilson95"][1] <= 0.02
    out["g3_actions"] = sum(e["rule"] == "G3" for r in rows for e in r["q_acrs"]["escalations"])
    return out


def main():
    drift = check_lock()
    if drift:
        sys.exit("REFUSED: v4-locked code changed:\n  " + "\n  ".join(drift))
    fresh, dropped = fresh_pairs()
    r9002 = evaluate(fresh)
    r9001 = evaluate(heldout_pairs()[0])
    rdev = evaluate([(net, s) for net in (build_net(1), build_net(2)) for s in scenarios(net)])
    res = {"meta": meta("phase7_v5", ("escalation_v5.py", "phase7_v5.py"), seed=SEED, per_network=N_PER_NET,
                        dropped_duplicates=dropped),
           "confirmatory_9002": block(r9002) | {"n": len(r9002)},
           "secondary_9001": block(r9001) | {"n": len(r9001)},
           "secondary_dev": block(rdev) | {"n": len(rdev)},
           "rows_9002": r9002}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v5_heldout.json").write_text(json.dumps(res, indent=1))
    for k in ("confirmatory_9002", "secondary_9001", "secondary_dev"):
        g = res[k]["gate_comparison_q_acrs"]
        print(f"{k:18} n={res[k]['n']:>3}  silent v3 {g['v3']['silent']:>2} -> v5 {g['v5']['silent']:>2} "
              f"(v5 Wilson95 upper {g['v5']['silent_wilson95'][1]:.3f})  escalation rate v3 {g['v3']['escalation_rate']:.3f} "
              f"-> v5 {g['v5']['escalation_rate']:.3f}  H2-v5 {res[k]['H2_v5_supported']}")
    t = res["confirmatory_9002"]["tests"]
    print("9002 H1:", t["H1_v3"], "\nH3:", t["H3_services_down_wilcoxon_one_sided"], "\nH4:", t["H4_containment_mcnemar"])
    for r in r9002:
        if r["q_acrs"]["status"] == S.NOT_CONTAINED:
            print("SILENT", r["scenario"], r["hacked"], r["q_acrs"]["reasons"])


if __name__ == "__main__":
    main()
