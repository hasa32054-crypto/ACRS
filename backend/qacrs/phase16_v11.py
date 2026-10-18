"""Phase 16 (v11 pilot): replay REAL incidents 2016-2026 on the UNCHANGED v9 engine.

    cd backend && python -m qacrs.phase16_v11        -> qacrs/results/v11/v11.json

Rules: docs/qacrs/PREREGISTRATION_v11.md (committed before this file, hash recorded in the output).
This script does nothing but: load the conversion files in qacrs/v11/incidents/*.json, run the frozen engine ONCE per
detection moment, run the baselines, and write the results. No weight, threshold or rule is changed.

Pre-registered outputs (R1-R3) are under "registered". Everything under "exploratory" was NOT pre-registered and is
reported as a pilot observation only:
  * cost_of_delay   - for incidents with >= 2 detection moments: what ACRS does at the FIRST moment vs the LAST one
  * weight_stability - does the ACRS decision set change when service values / disruptions are scaled x0.5 and x1.5
  * methods         - rule_segment and q_acrs_v5 on the same scenarios, for context

PILOT CAVEAT (stated in the output): the converter for this run is Claude (Anthropic), not an independent human, and it
had seen earlier ACRS results. The pre-registration requires a human converter who has not; this run is therefore
"v11-pilot", not the registered v11.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path

from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.network import Machine, Network, Scenario, Service, check

HERE = Path(__file__).parent
INC = HERE / "v11" / "incidents"
OUT = HERE / "results" / "v11"
PREREG = HERE.parent.parent / "docs" / "qacrs" / "PREREGISTRATION_v11.md"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ------------------------------------------------------------------ load ------------------------------------------
def load(p: Path) -> tuple[dict, Network | None, list[Scenario]]:
    d = json.loads(p.read_text(encoding="utf-8"))
    if d.get("dropped"):
        return d, None, []
    name = p.stem
    net = Network(name,
                  [Machine(m["name"], m["role"], bool(m.get("isolatable", True)), bool(m.get("critical", False)),
                           int(m.get("disruption", 1))) for m in d["machines"]],
                  [Service(s["name"], int(s["value"]), list(s["replicas"]), list(s.get("depends_on", [])))
                   for s in d["services"]],
                  [(a, b) for a, b in d["links"]])
    check(net)
    scs = [Scenario(f"{name}/{m['id']}", name, {k: int(v) for k, v in m["hacked"].items()}, m["description"])
           for m in d["detection_moments"]]
    for sc in scs:
        errs = S.validate_scenario(net, sc)
        assert not errs, (sc.id, errs)
    return d, net, scs


# ------------------------------------------------------------------ one run ---------------------------------------
def run_one(net: Network, sc: Scenario) -> dict:
    hacked = set(sc.hacked)
    t = time.perf_counter()
    iso, seg, method = H.solve(net, sc)
    d = V7.decide_v7(net, sc, iso, seg)
    ms = 1000 * (time.perf_counter() - t)
    fi, fs_ = V7.m_full_isolation_safe(net, sc)
    fd = V7.decide_v7(net, sc, fi, fs_)
    machines = {m.name: m for m in net.machines}
    # what happens if the two-person reviewers approve EVERY escalation as written (G1/G3 isolate, G2 segment)
    iso_a, seg_a = set(iso), set(seg)
    for e in d.escalations:
        if e["rule"] in ("G1", "G3"):
            iso_a.add(e["target"]); seg_a.discard(e["target"])
        elif e["rule"] == "G2":
            seg_a.add(e["target"])
    da = V7.decide_v7(net, sc, iso_a, seg_a)
    return {
        "scenario": sc.id, "description": sc.description, "hacked": sc.hacked, "solver": method,
        "n_machines": len(net.machines), "n_services": len(net.services), "n_links": len(net.links),
        "consistency_flags": H.consistency_flags(net, sc),
        "acrs": {
            "status": d.status, "isolate": sorted(iso), "segment": sorted(seg),
            "restrict_only": sorted(h for h in hacked if h not in iso and h not in seg),
            "healthy_isolated": sorted(iso - hacked),
            "services_down": V7.services_down_v7(net, iso, seg, hacked),
            "escalations": d.escalations, "reasons": d.reasons,
            "needs_two_person": d.needs_two_person, "owner_review": d.owner_review,
            "never_isolatable_hacked": sorted(h for h in hacked if not machines[h].isolatable),
            "decision_ms": round(ms, 2),
        },
        "if_all_escalations_approved": {
            "status": da.status, "isolate": sorted(iso_a), "segment": sorted(seg_a),
            "services_down": V7.services_down_v7(net, iso_a, seg_a, hacked),
        },
        "full_isolation": {
            "status": fd.status, "isolate": sorted(fi), "services_down": V7.services_down_v7(net, fi, set(), hacked),
            "reasons": fd.reasons, "needs_two_person": fd.needs_two_person,
        },
        "no_action": {"services_down": [], "risk_left": sum(sc.hacked.values()),
                      "open_paths_to_critical": [list(p) for p in V7.open_paths_v7(net, sc, set(), set())]},
    }


def exploratory_methods(net, sc) -> dict:
    out = {}
    for m in ("rule_segment", "q_acrs_v5"):
        try:
            out[m] = {k: V7.evaluate(net, sc, m)[k] for k in ("status", "isolate_now", "segment_now", "services_down")}
        except Exception as e:  # noqa: BLE001 - context only
            out[m] = {"error": str(e)}
    return out


def weight_stability(net, sc, base_iso, base_seg) -> dict:
    out = {}
    for f in (0.5, 1.5):
        n = copy.deepcopy(net)
        for s in n.services:
            s.value = s.value * f
        for m in n.machines:
            m.disruption = m.disruption * f
        iso, seg, _ = H.solve(n, sc)
        out[f"x{f}"] = {"same_decision": (set(iso), set(seg)) == (set(base_iso), set(base_seg)),
                        "isolate": sorted(iso), "segment": sorted(seg),
                        "status": V7.decide_v7(n, sc, iso, seg).status}
    return out


# ------------------------------------------------------------------ main ------------------------------------------
def main() -> None:
    t0 = time.time()
    files = sorted(INC.glob("*.json"))
    incidents, runs, dropped = [], [], []
    for p in files:
        d, net, scs = load(p)
        if net is None:
            dropped.append({"file": p.name, "incident": d.get("incident"), "reason": d.get("drop_reason", "")})
            continue
        rec = {"file": p.name, "sha256": sha(p), "incident": d["incident"], "year": d["year"], "sector": d["sector"],
               "narrative_before": d.get("narrative_before", ""), "sources": d.get("sources", []),
               "ambiguities": d.get("ambiguities", []), "attack_path": d.get("attack_path", []),
               "n_machines": len(net.machines), "n_services": len(net.services), "n_links": len(net.links),
               "never_isolate": [m.name for m in net.machines if not m.isolatable],
               "critical": [m.name for m in net.machines if m.critical], "moments": []}
        for sc in scs:
            r = run_one(net, sc)
            r["exploratory"] = {"methods": exploratory_methods(net, sc),
                                "weight_stability": weight_stability(net, sc, r["acrs"]["isolate"], r["acrs"]["segment"])}
            rec["moments"].append(r); runs.append(r)
        incidents.append(rec)

    # ---------------- registered targets
    n = len(runs)
    unsafe = sum(r["acrs"]["status"] == S.REJECTED for r in runs)
    silent = sum(r["acrs"]["status"] == S.NOT_CONTAINED for r in runs)
    cont = sum(r["acrs"]["status"] in (S.CONTAINED, S.PENDING) for r in runs)
    esc = sum(r["acrs"]["status"] == "ESCALATED" for r in runs)
    r2_pool = [r for r in runs if len(r["full_isolation"]["services_down"]) >= 1]
    r2_ok = [r for r in r2_pool if len(r["acrs"]["services_down"]) < len(r["full_isolation"]["services_down"])]
    r2_miss = [{"scenario": r["scenario"], "acrs_down": r["acrs"]["services_down"],
                "full_down": r["full_isolation"]["services_down"]} for r in r2_pool if r not in r2_ok]
    r3_miss = [{"scenario": r["scenario"], "status": r["acrs"]["status"], "reasons": r["acrs"]["reasons"],
                "escalations": [e["action"] for e in r["acrs"]["escalations"]]}
               for r in runs if r["acrs"]["status"] not in (S.CONTAINED, S.PENDING)]
    registered = {
        "n_scenarios": n, "n_incidents": len(incidents), "dropped": dropped,
        "status_counts": {s: sum(r["acrs"]["status"] == s for r in runs)
                          for s in (S.CONTAINED, S.PENDING, "ESCALATED", S.NOT_CONTAINED, S.REJECTED)},
        "R1": {"unsafe": unsafe, "silent": silent, "met": unsafe == 0 and silent == 0},
        "R2": {"pool": len(r2_pool), "fewer_services_down": len(r2_ok),
               "wilson95": stats.wilson(len(r2_ok), len(r2_pool)) if r2_pool else None,
               "met": len(r2_ok) == len(r2_pool), "misses": r2_miss},
        "R3": {"contained_or_pending": cont, "n": n, "ratio": (cont / n) if n else None,
               "wilson95": stats.wilson(cont, n) if n else None, "met": n > 0 and cont / n >= 0.8,
               "escalated_to_humans_not_counted": esc, "misses": r3_miss},
        "services_down_total": {"acrs": sum(len(r["acrs"]["services_down"]) for r in runs),
                                "full_isolation": sum(len(r["full_isolation"]["services_down"]) for r in runs)},
        "healthy_isolated_total": sum(len(r["acrs"]["healthy_isolated"]) for r in runs),
        "decision_ms": {"median": sorted(r["acrs"]["decision_ms"] for r in runs)[n // 2] if n else None,
                        "max": max((r["acrs"]["decision_ms"] for r in runs), default=None)},
    }

    # ---------------- exploratory (NOT pre-registered)
    delay = []
    for rec in incidents:
        if len(rec["moments"]) >= 2:
            a, z = rec["moments"][0], rec["moments"][-1]
            delay.append({"incident": rec["incident"], "first": a["scenario"], "last": z["scenario"],
                          "first_alerts": len(a["hacked"]), "last_alerts": len(z["hacked"]),
                          "acrs_first": {"status": a["acrs"]["status"], "isolate": a["acrs"]["isolate"],
                                         "services_down": a["acrs"]["services_down"]},
                          "acrs_last": {"status": z["acrs"]["status"], "isolate": z["acrs"]["isolate"],
                                        "services_down": z["acrs"]["services_down"]},
                          "full_isolation_last_services_down": z["full_isolation"]["services_down"]})
    stab = [r["exploratory"]["weight_stability"] for r in runs]
    appr = [r for r in runs if len(r["full_isolation"]["services_down"]) >= 1]
    appr_ok = [r for r in appr
               if len(r["if_all_escalations_approved"]["services_down"]) < len(r["full_isolation"]["services_down"])]
    rs_down = sum(len(r["exploratory"]["methods"]["rule_segment"].get("services_down", [])) for r in runs)
    burst = [r["scenario"] for r in runs if any("burst" in f for f in r["consistency_flags"])]
    exploratory = {
        "note": "NOT pre-registered. Pilot observations only.",
        "caveat_services_down": "ACRS's registered 'services down' counts only its AUTOMATIC actions; 11/16 real "
                                "scenarios were escalated, so the infected service hosts were left running pending "
                                "a human decision. The honest comparison is 'if_all_escalations_approved'.",
        "services_down_if_all_escalations_approved": sum(len(r["if_all_escalations_approved"]["services_down"])
                                                         for r in runs),
        "R2_if_all_escalations_approved": {"pool": len(appr), "fewer_services_down": len(appr_ok),
                                           "wilson95": stats.wilson(len(appr_ok), len(appr)) if appr else None,
                                           "ties_or_worse": [r["scenario"] for r in appr if r not in appr_ok]},
        "rule_segment_services_down_total": rs_down,
        "guard_burst_flag_on_real_detonations": burst,
        "cost_of_delay": delay,
        "weight_stability": {"x0.5_same": sum(s["x0.5"]["same_decision"] for s in stab),
                             "x1.5_same": sum(s["x1.5"]["same_decision"] for s in stab), "n": len(stab)},
        "methods": {m: {s: sum(r["exploratory"]["methods"][m].get("status") == s for r in runs)
                        for s in (S.CONTAINED, S.PENDING, "ESCALATED", S.NOT_CONTAINED, S.REJECTED)}
                    for m in ("rule_segment", "q_acrs_v5")},
    }

    res = {"meta": {"experiment": "v11-pilot", "converter": "Claude (Anthropic) — NOT an independent human; pilot only",
                    "prereg_sha256": sha(PREREG) if PREREG.exists() else None, "script_sha256": sha(Path(__file__)),
                    "engine": "v9 unchanged (hassan.solve + qubo_v7.decide_v7)", "threshold": S.HIGH_RISK,
                    "rho": V7.RHO, "d_seg": V7.D_SEG, "seconds": round(time.time() - t0, 1)},
            "registered": registered, "exploratory": exploratory, "incidents": incidents}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v11.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(registered, indent=1, ensure_ascii=False))
    print(f"saved {OUT / 'v11.json'} in {res['meta']['seconds']} s")


if __name__ == "__main__":
    main()
