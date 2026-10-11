"""Phase 12 (v8 D, E, F): explainability coverage, hospital realism, scale and solvers.

    cd backend && python -m qacrs.phase12_realism_scale      -> results/v8/realism_scale.json

Rules: docs/qacrs/PREREGISTRATION_v8.md sections D, E, F.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from qacrs import escalation as E
from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.meta import meta
from qacrs.network import Scenario, build as build_net
from qacrs.phase11_executor import all_pairs
from qacrs.phase3_compare import annealing
from qacrs.phase8_ood import chain_scenarios, ood_pairs
from qacrs.phase9_v7 import fresh_sets

OUT = Path(__file__).parent / "results" / "v8"
R = Path(__file__).parent / "results"


def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def explain_coverage(pairs):
    engines, ok, n = {}, 0, 0
    for net, sc in pairs:
        d = engines.setdefault(net.name, H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9))).decide(sc)
        n += 1
        ok += bool(d.card.get("en")) and bool(d.card.get("ar")) and "services_saved_vs_full_isolation" in d.card and bool(d.status)
    return {"decisions": n, "cards_complete_bilingual_with_counterfactual": ok, "target_met": ok == n}


def mitre(pairs):
    nets_pairs = pairs + [(RV.hospital60(), s) for s in chain_scenarios(RV.hospital60(), 50, 7101)]
    tagged = sum(all(v for v in RV.mitre_tags(n, s).values()) and len(RV.mitre_tags(n, s)) == len(s.hacked) for n, s in nets_pairs)
    counts = {}
    for n, s in nets_pairs:
        for ts in RV.mitre_tags(n, s).values():
            for t in ts:
                counts[t] = counts.get(t, 0) + 1
    return {"scenarios": len(nets_pairs), "fully_tagged": tagged, "technique_counts": dict(sorted(counts.items())),
            "target_met": tagged == len(nets_pairs)}


def patient_minutes_report():
    v7 = json.loads((R / "v7" / "v7.json").read_text())
    out = {}
    for k in ("chains_7008", "random_9003"):
        rows = v7[k]["rows"]
        pm = {m: sum(RV.patient_minutes(r[m]["services_down"]) for r in rows)
              for m in ("full_isolation_safe", "rule_segment", "q_acrs_v5", "q_acrs_v7")}
        out[k] = {"patient_minutes": pm, "saved_vs_full_isolation_q_acrs_v7": pm["full_isolation_safe"] - pm["q_acrs_v7"],
                  "scenarios": len(rows)}
    out["assumptions"] = {"patients_per_hour": RV.PATIENTS_PER_HOUR, "outage_min": RV.OUTAGE_MIN,
                          "formula": "patients arriving during the outage x mean wait (outage/2)"}
    return out


def hospital60_eval(n=200, seed=7101):
    net = RV.hospital60()
    eng = H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9))
    st, lat, unsafe, down, full_down, methods = [], [], 0, 0, 0, {}
    pm_h = pm_f = 0.0
    for sc in chain_scenarios(net, n, seed):
        t = time.perf_counter(); iso, seg, method = H.solve(net, sc); lat.append(1000 * (time.perf_counter() - t))
        methods[method] = methods.get(method, 0) + 1
        d = V7.decide_v7(net, sc, iso, seg); st.append(d.status)
        unsafe += d.status == S.REJECTED
        dn = V7.services_down_v7(net, iso, seg, set(sc.hacked)); down += len(dn)
        fi = V7.m_full_isolation_safe(net, sc)[0]; fdn = V7.services_down_v7(net, fi, set(), set(sc.hacked))
        full_down += len(fdn); pm_h += RV.patient_minutes(dn); pm_f += RV.patient_minutes(fdn)
    lo, hi = stats.wilson(st.count(S.NOT_CONTAINED), len(st))
    return {"machines": len(net.machines), "services": len(net.services), "links": len(net.links), "scenarios": len(st),
            "status_counts": {s: st.count(s) for s in set(st)}, "unsafe": unsafe,
            "silent_wilson95": [lo, hi], "services_down": down, "full_isolation_safe_services_down": full_down,
            "patient_minutes": {"hassan": pm_h, "full_isolation_safe": pm_f},
            "decision_ms": {"median": pct(lat, .5), "p95": pct(lat, .95), "max": max(lat)}, "solver_used": methods,
            "target_met": unsafe == 0 and hi <= 0.02 and pct(lat, .95) < 1000}


def ransomware(pairs_small):
    out = {}
    for net in (build_net(1), RV.hospital60()):
        scen = chain_scenarios(net, 100, 7202)
        res = {"hassan_v7": [], "full_isolation_safe": [], "no_action": []}
        for sc in scen:
            init = {sc.description.split(": ", 1)[1].split(" | ")[0].split(" -> ")[0]}   # the entry machine only
            res["hassan_v7"].append(RV.spread(net, init, V7.m_q_acrs_v7))
            res["full_isolation_safe"].append(RV.spread(net, init, V7.m_full_isolation_safe))
            res["no_action"].append(RV.spread(net, init, None))
        out[net.name] = {k: {"mean_encrypted": float(np.mean([x["encrypted"] for x in v])),
                             "mean_services_unavailable": float(np.mean([len(x["services_unavailable"]) for x in v])),
                             "mean_isolated": float(np.mean([x["isolated"] for x in v]))} for k, v in res.items()}
    out["model"] = "1 hop per tick along links; decision at tick 2 on the infected set (risk 8); 10 ticks; restricted machines keep spreading"
    return out


def anticipatory():
    fs, _ = fresh_sets()
    pairs = ood_pairs()[0] + fs["chains_7008"]
    res = {"q_acrs_v7": 0, "q_acrs_v5": 0, "rule_segment": 0}; n = 0
    for net, sc in pairs:
        chain = sc.description.split(": ", 1)[1].split(" | ")[0].split(" -> ")
        if len(chain) < 2:
            continue
        hidden, prev = chain[-1], chain[-2]
        vis = {m: r for m, r in sc.hacked.items() if m != hidden}
        if not vis or prev not in vis:
            continue
        v = Scenario(sc.id + "_vis", sc.network, vis, sc.description)
        n += 1
        for m in res:
            iso, seg = V7.METHODS_V7[m](net, v)
            res[m] += RV.next_hop_blocked(net, v, prev, hidden, iso, seg)
    return {"chains_with_hidden_hop": n, "next_hop_already_blocked": res,
            "share": {k: v / n for k, v in res.items()} if n else {}}


def scale_200():
    net = build_net(20)
    lat, methods, bad = [], {}, 0
    for sc in chain_scenarios(net, 20, 7303):
        t = time.perf_counter(); iso, seg, m = H.solve(net, sc); lat.append(1000 * (time.perf_counter() - t))
        methods[m] = methods.get(m, 0) + 1
        bad += V7.check_v7(net, sc, iso, seg).status == S.REJECTED
    return {"machines": len(net.machines), "scenarios": 20, "solver_used": methods, "rejected": bad,
            "decision_ms": {"median": pct(lat, .5), "p95": pct(lat, .95), "max": max(lat)}, "target_met": pct(lat, .95) < 1000}


def portfolio_agreement(pairs):
    agree = n = 0
    for net, sc in pairs:
        q = V7.build_v7(net, sc)
        if q.n > H.EXACT_MAX_VARS:
            continue
        exact = float(q.all_values().min())
        sa = annealing(q, steps=6000, restarts=3, seed=0)
        n += 1; agree += abs(sa - exact) < 1e-9
    return {"scenarios": n, "annealing_equals_exact": agree, "target_met": agree == n}


def hybrid_cross_check():
    d = json.loads((R / "v3" / "qaoa_seeds" / "seed0.json").read_text())
    rows = [r for r in d["rows"] if r.get("qubits", 0) > 0]
    dis = [r["scenario"] for r in rows if not r["qaoa_mean_100"]["hit"]]
    return {"scenarios": len(rows), "qaoa_best_of_100_disagrees_with_exact": len(dis), "disagreeing": dis,
            "executed_disagreements": 0, "rule": "disagreement -> human decision; never executed"}


def noise_sweep():
    """Rebased on the STORED Lesson-3 ideal value (98.14%, qiskit-tuned p=2 circuit). The first version re-tuned a
    numpy circuit and reached only 51% ideal, i.e. it was not the Lesson-3 circuit; that run is kept in git history."""
    l3 = json.loads((Path(__file__).parent / "results" / "lesson3_ibm.json").read_text())
    p_ideal, measured, p_rand = l3["hit_ideal"], l3["hit_real"], l3["hit_random"]
    probs = np.full(8, (1 - p_ideal) / 6)
    opt = np.zeros(8, bool)
    for x in l3["best_decisions"]:
        opt[sum(b << i for i, b in enumerate(x))] = True
    probs[opt] = p_ideal / opt.sum()
    rows = []
    for eps in np.round(np.arange(0, 0.051, 0.0025), 4):
        for ro in (0.0, 0.005, 0.01, 0.02):
            pg = (1 - eps) ** 2 * probs + (1 - (1 - eps) ** 2) / 8          # depolarizing after each of 2 two-qubit gates
            conf = np.zeros((8, 8))
            for a in range(8):
                for b in range(8):
                    flips = bin(a ^ b).count("1"); conf[b, a] = (ro ** flips) * ((1 - ro) ** (3 - flips))
            pm = conf @ pg
            rows.append({"two_qubit_error": float(eps), "readout_error": ro, "p_best": round(float(pm[opt].sum()), 4)})
    close = min(rows, key=lambda r: abs(r["p_best"] - measured))
    no_ro = min((r for r in rows if r["readout_error"] == 0), key=lambda r: abs(r["p_best"] - measured))
    return {"p_best_ideal_stored": p_ideal, "p_best_random": p_rand, "recorded_hardware_p_best": measured,
            "closest_setting": close, "closest_with_readout_0": no_ro, "grid": rows,
            "note": "simple global-depolarizing + independent readout model on the stored ideal distribution "
                    "(non-optimal mass spread evenly); an inference about effective error, not a device characterisation; "
                    "several (gate, readout) pairs fit about equally well"}

def regret_escalation(tau=5.0):
    fs, _ = fresh_sets()
    out = {}
    for name in ("chains_7008", "random_9003"):
        esc = kept = became_silent = 0
        for net, sc in fs[name]:
            iso, seg, q, best = V7.q_acrs_v7(net, sc)
            d = V7.decide_v7(net, sc, iso, seg)
            if d.status != E.ESCALATED:
                continue
            esc += 1
            alt_iso = set(iso) | {e["target"] for e in d.escalations if e["target"] in sc.hacked}
            alt_iso = {m for m in alt_iso if net.machine(m).isolatable}
            k_alt = sum(1 << i for i, nm in enumerate(q.names) if nm in alt_iso or (nm.endswith(V7.SEG) and nm[:-len(V7.SEG)] in seg - alt_iso))
            regret = float(q.value([(k_alt >> i) & 1 for i in range(q.n)])) - best
            if regret > tau:
                kept += 1
            else:
                became_silent += 1
        out[name] = {"escalations_v7": esc, "kept_by_regret_rule": kept, "dropped_would_be_silent": became_silent,
                     "tau": tau}
    out["note"] = "dropping an escalation means accepting documented risk automatically, which the containment rules count as a silent failure; reported, not adopted"
    return out


def main():
    pairs = all_pairs()
    t = time.perf_counter()
    res = {"meta": meta("phase12_realism_scale", ("realism_v8.py", "hassan.py", "phase12_realism_scale.py"))}
    for name, fn in (("explainability", lambda: explain_coverage(pairs)), ("mitre", lambda: mitre(pairs)),
                     ("patient_minutes", patient_minutes_report), ("hospital60", hospital60_eval),
                     ("ransomware_spread", lambda: ransomware(pairs)), ("anticipatory", anticipatory),
                     ("scale_200", scale_200), ("portfolio_agreement", lambda: portfolio_agreement(pairs)),
                     ("hybrid_cross_check", hybrid_cross_check), ("noise_sweep", noise_sweep),
                     ("regret_escalation", regret_escalation)):
        t0 = time.perf_counter(); res[name] = fn()
        short = {k: v for k, v in res[name].items() if k not in ("grid", "technique_counts", "disagreeing")} if isinstance(res[name], dict) else res[name]
        print(f"== {name} ({time.perf_counter() - t0:.1f}s): {json.dumps(short, default=str)[:900]}", flush=True)
    res["meta"]["seconds"] = round(time.perf_counter() - t, 1)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "realism_scale.json").write_text(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()
