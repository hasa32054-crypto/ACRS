"""Phase 9 (v7): graded containment (SEGMENT) on FRESH data, with a strong same-action baseline.

    cd backend && python -m qacrs.phase9_v7     -> results/v7/v7.json, v7_sensitivity.json

Rules: docs/qacrs/PREREGISTRATION_v7.md. Primary set: attack chains seed 7008; secondary: random seed 9003.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path

from qacrs import escalation as E
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.meta import meta
from qacrs.network import build as build_net, random_scenarios, scenarios
from qacrs.phase6_heldout import heldout_pairs
from qacrs.phase7_v5 import fresh_pairs
from qacrs.phase8_ood import chain_scenarios, ood_pairs

OUT = Path(__file__).parent / "results" / "v7"
CHAIN_SEED, RAND_SEED, N_CHAIN, N_RAND = 7008, 9003, 200, 250
CONTAINED = (S.CONTAINED, S.PENDING)


def prior_keys():
    keys = {}
    for net, s in heldout_pairs()[0] + fresh_pairs()[0] + ood_pairs()[0]:
        keys.setdefault(net.name, set()).add(tuple(sorted(s.hacked.items())))
    for d in (1, 2):
        net = build_net(d)
        for s in scenarios(net):
            keys.setdefault(net.name, set()).add(tuple(sorted(s.hacked.items())))
    return keys


def fresh_sets():
    prior = prior_keys()
    out, dropped = {"chains_7008": [], "random_9003": []}, {"chains_7008": 0, "random_9003": 0}
    for d in (1, 2):
        net = build_net(d)
        for name, gen in (("chains_7008", lambda: chain_scenarios(net, N_CHAIN, CHAIN_SEED)),
                          ("random_9003", lambda: random_scenarios(net, N_RAND, RAND_SEED))):
            seen = set(prior.get(net.name, set()))
            for s in gen():
                k = tuple(sorted(s.hacked.items()))
                if k in seen:
                    dropped[name] += 1; continue
                seen.add(k)
                s.id = s.id + ("_c7" if name.startswith("chains") else "_r9")
                out[name].append((net, s))
    return out, dropped


def run_set(pairs):
    rows = []
    for net, sc in pairs:
        row = {"scenario": sc.id, "network": net.name, "hacked": sc.hacked, "description": sc.description}
        for m in V7.METHODS_V7:
            row[m] = V7.evaluate(net, sc, m)
        rows.append(row)
    return rows


def summary(rows):
    out = {}
    for m in V7.METHODS_V7:
        st = [r[m]["status"] for r in rows]
        out[m] = {"n": len(rows), "contained_v7": sum(s in CONTAINED for s in st),
                  "fully_automatic": st.count(S.CONTAINED), "pending_two_person": st.count(S.PENDING),
                  "escalated": st.count(E.ESCALATED), "silent": st.count(S.NOT_CONTAINED),
                  "rejected": st.count(S.REJECTED),
                  "contained_v2_rules": sum(r[m]["status_v2_rules"] in CONTAINED for r in rows),
                  "services_down": sum(len(r[m]["services_down"]) for r in rows),
                  "healthy_isolated": sum(len(r[m]["healthy_isolated"]) for r in rows),
                  "segment_used": sum(bool(r[m]["segment_now"]) for r in rows),
                  "risk_left": round(sum(r[m]["risk_left"] for r in rows), 1)}
    return out


def tests(rows):
    n = len(rows)
    s = summary(rows)
    q7, fis, rs = s["q_acrs_v7"], s["full_isolation_safe"], s["rule_segment"]
    a7 = [r["q_acrs_v7"]["status"] == S.CONTAINED for r in rows]
    a5 = [r["q_acrs_v5"]["status"] == S.CONTAINED for r in rows]
    only7 = sum(a and not b for a, b in zip(a7, a5)); only5 = sum(b and not a for a, b in zip(a7, a5))
    p_h6 = float(stats.st.binomtest(only7, only7 + only5, 0.5, alternative="greater").pvalue) if only7 + only5 else 1.0
    w = stats.wilcoxon_less([len(r["q_acrs_v7"]["services_down"]) for r in rows],
                            [len(r["rule_segment"]["services_down"]) for r in rows])
    lo, hi = stats.wilson(q7["silent"], n)
    return {
        "H1_v7": {"ratio": round(q7["contained_v7"] / fis["contained_v7"], 4) if fis["contained_v7"] else None,
                  "services_down": [q7["services_down"], fis["services_down"]],
                  "supported": q7["contained_v7"] >= 0.8 * fis["contained_v7"] and q7["services_down"] < fis["services_down"]},
        "H6_fully_automatic_vs_v5": {"v7_only": only7, "v5_only": only5, "p_one_sided": p_h6,
                                     "v7": q7["fully_automatic"], "v5": s["q_acrs_v5"]["fully_automatic"],
                                     "supported": p_h6 < 0.05},
        "H7_services_vs_rule_segment": w | {"v7": q7["services_down"], "rule_segment": rs["services_down"],
                                             "supported": w["p"] < 0.05},
        "H8_containment_vs_rule_segment": {"ratio": round(q7["contained_v7"] / rs["contained_v7"], 4) if rs["contained_v7"] else None,
                                           "supported": q7["contained_v7"] >= 0.9 * rs["contained_v7"]},
        "H2_v7_silent": {"count": q7["silent"], "wilson95": [lo, hi], "supported": hi <= 0.02},
        "escalation_rate": {"v7": q7["escalated"] / n, "v5": s["q_acrs_v5"]["escalated"] / n,
                            "v7_wilson95": stats.wilson(q7["escalated"], n)},
    }


def sensitivity(pairs):
    out = []
    for rho in (0.1, 0.2, 0.3, 0.5, 0.7):
        for dseg in (0.5, 1.0, 2.0):
            st, down, auto = [], 0, 0
            for net, sc in pairs:
                iso, seg, _, _ = V7.q_acrs_v7(net, sc, rho, dseg)
                d = V7.decide_v7(net, sc, iso, seg)
                st.append(d.status); auto += d.status == S.CONTAINED
                down += len(V7.services_down_v7(net, iso, seg, set(sc.hacked)))
            out.append({"rho": rho, "d_seg": dseg, "contained_v7": sum(x in CONTAINED for x in st),
                        "fully_automatic": auto, "escalated": st.count(E.ESCALATED),
                        "silent": st.count(S.NOT_CONTAINED), "services_down": down})
    return out


def main():
    sets, dropped = fresh_sets()
    res = {"meta": meta("phase9_v7", ("qubo_v7.py", "phase9_v7.py"), chain_seed=CHAIN_SEED, rand_seed=RAND_SEED,
                        rho=V7.RHO, d_seg=V7.D_SEG, dropped_duplicates=dropped)}
    for name, pairs in sets.items():
        rows = run_set(pairs)
        res[name] = {"n": len(rows), "summary": summary(rows), "tests": tests(rows), "rows": rows}
        t = res[name]["tests"]
        print(f"\n== {name}  n={len(rows)} (dropped {dropped[name]})")
        for m, x in res[name]["summary"].items():
            print(f"  {m:20} contained {x['contained_v7']:>3} (v2 rules {x['contained_v2_rules']:>3})  auto {x['fully_automatic']:>3}  "
                  f"2p {x['pending_two_person']:>3}  esc {x['escalated']:>3}  silent {x['silent']:>2}  rej {x['rejected']}  "
                  f"svc down {x['services_down']:>3}  seg used {x['segment_used']:>3}")
        for k, v in t.items():
            print(f"  {k}: {v}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v7.json").write_text(json.dumps(res, indent=1))
    sens = sensitivity(sets["chains_7008"])
    (OUT / "v7_sensitivity.json").write_text(json.dumps({"meta": meta("phase9_v7_sensitivity", ("qubo_v7.py",)),
                                                         "note": "exploratory; no parameter chosen from it",
                                                         "grid": sens}, indent=1))
    print("\nsensitivity (chains):")
    for g in sens:
        print(f"  rho {g['rho']:<4} d_seg {g['d_seg']:<4} contained {g['contained_v7']:>3} auto {g['fully_automatic']:>3} "
              f"esc {g['escalated']:>3} silent {g['silent']:>2} svc down {g['services_down']:>3}")


if __name__ == "__main__":
    main()
