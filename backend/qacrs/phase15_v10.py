"""Phase 15 (v10): cross-sector generalisation, classical solver comparison, MITRE ATT&CK coverage.
Rules: docs/qacrs/PREREGISTRATION_v10.md (committed before this file and before any result).

    cd backend && python -m qacrs.phase15_v10        -> results/v10/v10.json

The v9 engine is used unchanged (hassan.solve + qubo_v7.decide_v7, exactly as phase14_v9.fresh_claims).
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path

import numpy as np

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import quantum_scale as QS
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs import sectors_v10 as SEC
from qacrs import stats
from qacrs.meta import meta
from qacrs.network import random_scenarios
from qacrs.phase8_ood import chain_scenarios

OUT = Path(__file__).parent / "results" / "v10"


def dedup(scs):
    seen, out, dropped = set(), [], 0
    for s in scs:
        k = tuple(sorted(s.hacked.items()))
        if k in seen:
            dropped += 1; continue
        seen.add(k); out.append(s)
    return out, dropped


def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


# ------------------------------------------------------------------ A. cross-sector -------------------------------
def evaluate(net, scs):
    n = len(scs); st = {}; unsafe = silent = cont = cont_full = 0
    down_a, down_f, ms = [], [], []
    for sc in scs:
        t = time.perf_counter()
        iso, seg, _ = H.solve(net, sc)
        d = V7.decide_v7(net, sc, iso, seg)
        ms.append(1000 * (time.perf_counter() - t))
        st[d.status] = st.get(d.status, 0) + 1
        unsafe += d.status == S.REJECTED; silent += d.status == S.NOT_CONTAINED
        cont += d.status in (S.CONTAINED, S.PENDING)
        fi, fs_ = V7.m_full_isolation_safe(net, sc)
        cont_full += V7.decide_v7(net, sc, fi, fs_).status in (S.CONTAINED, S.PENDING)
        down_a.append(len(V7.services_down_v7(net, iso, seg, set(sc.hacked))))
        down_f.append(len(V7.services_down_v7(net, fi, set(), set(sc.hacked))))
    ratio = cont / cont_full if cont_full else None
    w = stats.wilcoxon_less(down_a, down_f) if any(a != b for a, b in zip(down_a, down_f)) else None
    return {"n": n, "status": st, "contained": cont, "contained_full_isolation": cont_full,
            "containment_ratio_vs_full_isolation": ratio, "unsafe": unsafe, "silent": silent,
            "silent_wilson95": stats.wilson(silent, n), "services_down": sum(down_a),
            "full_isolation_services_down": sum(down_f), "scenarios_with_any_service_down": sum(x > 0 for x in down_a),
            "wilcoxon_services_down_less": w, "decision_ms": {"median": pct(ms, .5), "p95": pct(ms, .95)}}


def sector_test():
    out = {}
    for name, f in SEC.SECTORS.items():
        net = f()
        chains, dc = dedup(chain_scenarios(net, SEC.N_CHAIN, SEC.CHAIN_SEEDS[name]))
        rand, dr = dedup(random_scenarios(net, SEC.N_RAND, SEC.RAND_SEEDS[name]))
        ec, er = evaluate(net, chains), evaluate(net, rand)
        r = ec["containment_ratio_vs_full_isolation"] or 0
        w = ec["wilcoxon_services_down_less"]
        g1_down = (w is None and ec["services_down"] == 0 and ec["full_isolation_services_down"] == 0) or \
                  (w is not None and w.get("p", 1) < 0.05 and ec["services_down"] < ec["full_isolation_services_down"])
        out[name] = {"machines": len(net.machines), "services": len(net.services), "links": len(net.links),
                     "never_isolate": sum(not m.isolatable for m in net.machines),
                     "chains": ec, "random": er, "dropped_duplicates": {"chains": dc, "random": dr},
                     "G1": {"ratio_ge_0_80": r >= 0.80, "zero_unsafe": ec["unsafe"] == 0,
                            "fewer_services_down": g1_down, "wilcoxon_applicable": w is not None,
                            "pass": r >= 0.80 and ec["unsafe"] == 0 and g1_down},
                     "G2": {"pass": r >= 0.90 and ec["services_down"] == 0 and ec["silent"] == 0 and ec["unsafe"] == 0}}
        print(f"  {name}: G1={out[name]['G1']['pass']} G2={out[name]['G2']['pass']} ratio={r:.3f} "
              f"down={ec['services_down']} vs {ec['full_isolation_services_down']} unsafe={ec['unsafe']} silent={ec['silent']}",
              flush=True)
    return out


# ------------------------------------------------------------------ B. solver comparison --------------------------
def greedy(q):
    x = [0] * q.n; v = q.value(x)
    while True:
        best, bi = v, -1
        for i in range(q.n):
            x[i] ^= 1; e = q.value(x); x[i] ^= 1
            if e < best - 1e-12:
                best, bi = e, i
        if bi < 0:
            return v
        x[bi] ^= 1; v = best


def annealing(q, seed=0, steps=6000):
    rng = random.Random(seed); x = [0] * q.n; e = q.value(x); be = e
    for t in range(steps):
        T = 10 * (1 - t / steps) + 1e-3
        i = rng.randrange(q.n); x[i] ^= 1; e2 = q.value(x)
        if e2 <= e or rng.random() < pow(2.718281828, (e - e2) / T):
            e = e2; be = min(be, e)
        else:
            x[i] ^= 1
    return be


def random_best(q, k=1000, seed=0):
    rng = random.Random(seed)
    return min(q.value([rng.getrandbits(1) for _ in range(q.n)]) for _ in range(k))


def engine_value(net, sc, q):
    iso, seg, _ = H.solve(net, sc)
    x = [1 if (nm in iso or (nm.endswith(V7.SEG) and nm[:-len(V7.SEG)] in seg)) else 0 for nm in q.names]
    return q.value(x)


def solver_compare(problem_sets):
    methods = ("exact_milp", "engine", "greedy", "annealing", "random_1000")
    rows = {m: {"opt": 0, "gaps": [], "ms": []} for m in methods}
    n = 0; sizes = []
    for net, sc in problem_sets:
        q = V7.build_v7(net, sc); sizes.append(q.n)
        t = time.perf_counter(); ref, _ = QS.exact_milp(q); ms_milp = 1000 * (time.perf_counter() - t)
        if q.n <= H.EXACT_MAX_VARS:
            ref = min(ref, float(q.all_values().min()))
        n += 1
        for m in methods:
            t = time.perf_counter()
            if m == "exact_milp":
                v = ref; dt = ms_milp
            else:
                v = {"engine": lambda: engine_value(net, sc, q), "greedy": lambda: greedy(q),
                     "annealing": lambda: annealing(q), "random_1000": lambda: random_best(q)}[m]()
                dt = 1000 * (time.perf_counter() - t)
            gap = (v - ref) / max(1e-9, abs(ref)) if abs(ref) > 1e-9 else (v - ref)
            rows[m]["opt"] += v <= ref + 1e-6; rows[m]["gaps"].append(max(0.0, gap)); rows[m]["ms"].append(dt)
    res = {"problems": n, "variables": {"median": pct(sizes, .5), "max": max(sizes)}}
    for m, r in rows.items():
        res[m] = {"optimal": r["opt"], "optimal_share": r["opt"] / n, "mean_rel_gap": float(np.mean(r["gaps"])),
                  "ms_median": pct(r["ms"], .5), "ms_p95": pct(r["ms"], .95)}
    return res


def large_incident():
    net = QS.cluster(); sc = QS.incident(net); q = V7.build_v7(net, sc)
    out = {"machines": len(net.machines), "hacked": len(sc.hacked), "variables": q.n}
    t = time.perf_counter(); ref, _ = QS.exact_milp(q); out["exact_milp"] = {"value": ref, "ms": 1000 * (time.perf_counter() - t)}
    for m, f in (("greedy", lambda: greedy(q)), ("annealing", lambda: annealing(q, steps=60000)),
                 ("random_1000", lambda: random_best(q))):
        t = time.perf_counter(); v = f()
        out[m] = {"value": v, "rel_gap": (v - ref) / abs(ref) if ref else v - ref, "ms": 1000 * (time.perf_counter() - t)}
    return out


# ------------------------------------------------------------------ C. MITRE ATT&CK ------------------------------
ICS_ROLES = ("scada", "hmi", "plc", "sis")
TACTIC = {"T1190": "Initial Access", "T1566": "Initial Access", "T1021": "Lateral Movement",
          "T1071": "Command and Control", "T1003": "Credential Access", "T1078": "Defense Evasion / Persistence",
          "T1005": "Collection", "T1041": "Exfiltration", "T1486": "Impact",
          "ICS:T0886": "Lateral Movement (ICS)", "ICS:T0843": "Lateral Movement (ICS)", "ICS:T0822": "Initial Access (ICS)"}


def ics_tags(sc):
    tags = {}
    if not sc.description.startswith("attack chain"):
        return tags
    for path in sc.description.split(": ", 1)[1].split(" | "):
        hops = path.split(" -> ")
        for a, b in zip(hops, hops[1:]):
            if b.startswith(ICS_ROLES):
                tags.setdefault(b, set()).add("ICS:T0886")
            if b.startswith("plc"):
                tags[b].add("ICS:T0843")
            if a == "vpn" and b.startswith(ICS_ROLES + ("pc_eng",)):
                tags.setdefault(a, set()).add("ICS:T0822")
    return tags


def mitre(pairs_by_net):
    out = {}
    for name, (net, scs) in pairs_by_net.items():
        tech, scen_cov = {}, 0
        for sc in scs:
            tags = {m: set(v) for m, v in RV.mitre_tags(net, sc).items()}
            for m, t in (ics_tags(sc).items() if net.name.startswith("factory") else ()):   # OT zone exists only in the factory
                tags.setdefault(m, set()).update(t)
            seen = set().union(*tags.values()) if tags else set()
            scen_cov += bool(seen)
            for t in seen:
                tech[t] = tech.get(t, 0) + 1
        tactics = {}
        for t, c in tech.items():
            tactics[TACTIC.get(t, "?")] = tactics.get(TACTIC.get(t, "?"), 0) + c
        out[name] = {"scenarios": len(scs), "scenarios_tagged": scen_cov,
                     "techniques": dict(sorted(tech.items(), key=lambda kv: -kv[1])), "tactics": tactics}
    return out


def main():
    t0 = time.perf_counter()
    res = {"meta": meta("phase15_v10", ("sectors_v10.py", "phase15_v10.py", "hassan.py", "qubo_v7.py", "hassan_v9.py"))}
    res["meta"]["preregistration"] = "docs/qacrs/PREREGISTRATION_v10.md"
    print("== A. cross-sector generalisation", flush=True)
    res["A_sectors"] = sector_test()

    sector_pairs = {}
    for name, f in SEC.SECTORS.items():
        net = f(); sector_pairs[name] = (net, dedup(chain_scenarios(net, SEC.N_CHAIN, SEC.CHAIN_SEEDS[name]))[0])
    sets, _ = V9.fresh_sets_v9()
    h60 = V9.hospital60_v9()
    chains7009 = sets["chains_7009"]
    print("== B. solver comparison", flush=True)
    problems = [(net, sc) for net, scs in sector_pairs.values() for sc in scs] + list(chains7009) + [(h60[0], s) for s in h60[1]]
    res["B_solvers"] = solver_compare(problems)
    print("   ", json.dumps(res["B_solvers"])[:900], flush=True)
    res["B_large_incident"] = large_incident()
    print("   ", json.dumps(res["B_large_incident"]), flush=True)
    res["B_ibm_quoted"] = {"note": "quoted from results/v3/ibm (E7-E9), not re-run",
                           "E7_ibm_kingston_optimal_share": 0.119, "E8_ibm_fez_optimal_share": 0.827,
                           "E9_components_optimal": "11/11"}

    print("== C. MITRE ATT&CK coverage", flush=True)
    by_net = dict(sector_pairs)
    by_net["hospital60_7102"] = (h60[0], list(h60[1]))
    for net_name in sorted({n.name for n, _ in chains7009}):
        by_net[f"{net_name}_7009"] = (next(n for n, _ in chains7009 if n.name == net_name),
                                      [s for n, s in chains7009 if n.name == net_name])
    res["C_mitre"] = mitre(by_net)
    print("   ", json.dumps(res["C_mitre"])[:900], flush=True)

    res["meta"]["seconds"] = round(time.perf_counter() - t0, 1)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v10.json").write_text(json.dumps(res, indent=1, default=str))
    print(f"saved results/v10/v10.json in {res['meta']['seconds']} s")


if __name__ == "__main__":
    main()
