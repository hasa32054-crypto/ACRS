"""Phase 14 (v9): root-cause fixes on FRESH data. Rules: docs/qacrs/PREREGISTRATION_v9.md (+ amendment 1).

    cd backend && python -m qacrs.phase14_v9        -> results/v9/v9.json
(the kernel parts — 26-v9, S6-v9, SHIELD in iptables — are in sandbox_v9.py, needs root)
"""
from __future__ import annotations

import copy
import json
import random
import time
from pathlib import Path

import numpy as np

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.meta import meta
from qacrs.network import build as build_net
from qacrs.phase8_ood import chain_scenarios
from qacrs.phase10_adversarial import manipulated_sets

OUT = Path(__file__).parent / "results" / "v9"


def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def portfolio(net, sc):
    iso, seg, _ = H.solve(net, sc)
    return iso, seg


# ------------------------------------------------------------------ v7 claims on fresh data ----------------------
def fresh_claims(sets, h60):
    out = {}
    for name, pairs in list(sets.items()) + [("hospital60_7102", [(h60[0], s) for s in h60[1]])]:
        n = len(pairs); st = {}; down = full_down = unsafe = silent = cont = cont_full = 0
        for net, sc in pairs:
            iso, seg = portfolio(net, sc)
            d = V7.decide_v7(net, sc, iso, seg); st[d.status] = st.get(d.status, 0) + 1
            unsafe += d.status == S.REJECTED; silent += d.status == S.NOT_CONTAINED
            cont += d.status in (S.CONTAINED, S.PENDING)
            fi, fs_ = V7.m_full_isolation_safe(net, sc)
            cont_full += V7.decide_v7(net, sc, fi, fs_).status in (S.CONTAINED, S.PENDING)
            down += len(V7.services_down_v7(net, iso, seg, set(sc.hacked)))
            full_down += len(V7.services_down_v7(net, fi, set(), set(sc.hacked)))
        ratio = cont / cont_full if cont_full else None
        out[name] = {"n": n, "status": st, "containment_ratio_vs_full_isolation": ratio, "services_down": down,
                     "full_isolation_services_down": full_down, "unsafe": unsafe, "silent": silent,
                     "silent_wilson95": stats.wilson(silent, n),
                     "target_met": (ratio or 0) >= 0.9 and down == 0 and silent == 0 and unsafe == 0}
    return out


# ------------------------------------------------------------------ S5-v9 ----------------------------------------
def certificates(pairs, n_tamper=1000):
    rng = random.Random(V9.TAMPER_SEED)
    base, acc, times = [], 0, []
    for net, sc in pairs:
        iso, seg = portfolio(net, sc)
        c = V9.certificate_v9(net, sc, iso, seg)
        t = time.perf_counter(); ok = V9.verify_certificate_v9(net, sc, c); times.append(1000 * (time.perf_counter() - t))
        acc += ok; base.append((net, sc, iso, seg, c))
    kinds = ("naive_add_isolation", "status_flip", "claims_edit", "smart_add_isolation", "smart_remove_action")
    rej = {k: [0, 0] for k in kinds}
    i = 0
    while sum(v[1] for v in rej.values()) < n_tamper:
        net, sc, iso, seg, c = base[rng.randrange(len(base))]
        kind = kinds[i % 5]; i += 1
        machines = {m.name: m for m in net.machines}
        t = copy.deepcopy(c)
        if kind == "naive_add_isolation":
            extra = [m for m in machines if m not in iso]
            t["isolate"] = sorted(set(iso) | {rng.choice(extra)})
        elif kind == "status_flip":
            t["status"] = S.CONTAINED if c["status"] != S.CONTAINED else "ESCALATED"
        elif kind == "claims_edit":
            t["claims"]["services_down"] = t["claims"]["services_down"] + ["fake_service"]
        elif kind == "smart_add_isolation":
            cand = [h for h in sc.hacked if h not in iso and machines[h].isolatable and not machines[h].critical]
            if not cand:
                continue
            t = V9.certificate_v9(net, sc, set(iso) | {rng.choice(cand)}, seg)      # fully self-consistent forgery
        else:
            acts = [("i", m) for m in iso] + [("s", m) for m in seg]
            if not acts:
                continue
            k, m = rng.choice(acts)
            t = V9.certificate_v9(net, sc, set(iso) - {m} if k == "i" else iso, set(seg) - {m} if k == "s" else seg)
        rej[kind][1] += 1
        rej[kind][0] += not V9.verify_certificate_v9(net, sc, t)
    total_rej = sum(v[0] for v in rej.values())
    return {"genuine": len(base), "genuine_accepted": acc,
            "checker_ms": {"median": pct(times, .5), "p95": pct(times, .95)},
            "tampered": n_tamper, "rejected": total_rej,
            "by_kind": {k: {"rejected": v[0], "n": v[1]} for k, v in rej.items()},
            "target_met": acc == len(base) and total_rej == n_tamper and pct(times, .5) < 5}


# ------------------------------------------------------------------ S10-v9 ---------------------------------------
def guard(chains):
    rng = random.Random(V9.MANIP_SEED)
    det = {"naive": [0, 0], "path_aware": [0, 0]}
    nets = (build_net(1), build_net(2))
    for net in nets:
        for sc, kind in manipulated_sets(net, 500, V9.MANIP_SEED + len(net.machines)):
            lat = V9.ndr_lateral_flows(net, [], rng)                           # model A: forged alerts, no real hops
            det[kind][1] += 1; det[kind][0] += bool(V9.guard_v2(net, sc, lat))
    ff = sum(bool(V9.guard_v2(net, sc, V9.ndr_lateral_flows(net, V9.hops_of(sc), rng))) for net, sc in chains)
    overall = sum(v[0] for v in det.values()) / sum(v[1] for v in det.values())
    # model B: forger also controls the NDR feed -> forged flows on every forged hop; protection = harm bound
    worst_b = 0
    for net in nets:
        eng = H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9))
        for sc, kind in manipulated_sets(net, 500, V9.MANIP_SEED + 7 + len(net.machines)):
            d = eng.decide(sc)
            worst_b = max(worst_b, len(V7.services_down_v7(net, set(d.isolate), set(d.segment), set(sc.hacked))))
    return {"model_A": {"detection": {k: {"detected": v[0], "n": v[1], "rate": v[0] / v[1]} for k, v in det.items()},
                        "detection_overall": overall, "false_flags_chains_7009": ff, "chains": len(chains),
                        "false_flag_rate": ff / len(chains)},
            "model_B_worst_services_down": worst_b,
            "assumptions": {"p_spurious_lateral_flow_per_link": V9.P_SPURIOUS, "p_ndr_miss_per_hop": V9.P_MISS},
            "target_met": overall >= 0.8 and ff / len(chains) <= 0.10 and worst_b == 0}


# ------------------------------------------------------------------ R-v9 -----------------------------------------
def ransomware():
    out = {}
    for net in (build_net(1), RV.hospital60()):
        rng = random.Random(V9.RW_SEED)
        names = [m.name for m in net.machines]
        models = {"entry": [{V9.chain_paths(sc)[0][0]} for sc in chain_scenarios(net, 100, V9.RW_SEED)],
                  "anywhere": [{rng.choice(names)} for _ in range(100)]}
        for mname, inits in models.items():
            pol = {"hassan_v9": (portfolio, True), "hassan_v7": (portfolio, False),
                   "full_isolation_safe": (V7.m_full_isolation_safe, False), "no_action": (None, False)}
            res = {k: [V9.spread_v9(net, i, p, shield=sh) for i in inits] for k, (p, sh) in pol.items()}
            enc = {k: [x["encrypted"] for x in v] for k, v in res.items()}
            svc = {k: [len(x["services_unavailable"]) for x in v] for k, v in res.items()}
            at_floor = sum(x["encrypted"] == x["floor"] for x in res["hassan_v9"])
            w = stats.wilcoxon_less(enc["hassan_v9"], enc["full_isolation_safe"]) \
                if any(a != b for a, b in zip(enc["hassan_v9"], enc["full_isolation_safe"])) else None
            out[f"{net.name}/{mname}"] = {
                "mean_encrypted": {k: float(np.mean(v)) for k, v in enc.items()},
                "mean_services_unavailable": {k: float(np.mean(v)) for k, v in svc.items()},
                "hassan_v9_at_floor": at_floor, "runs": len(inits),
                "original_R_v9_less_than_full_isolation": w,
                "R_v9a_floor_100pct": at_floor == len(inits),
                "R_v9b_services_le_full": np.mean(svc["hassan_v9"]) <= np.mean(svc["full_isolation_safe"]),
                "R_v9c_le_v7": np.mean(enc["hassan_v9"]) <= np.mean(enc["hassan_v7"]) and np.mean(svc["hassan_v9"]) <= np.mean(svc["hassan_v7"])}
    out["model"] = "1 hop per tick; decision at tick 2; floor = machines infected before the decision; SHIELD assumption: spread uses admin protocols"
    return out


# ------------------------------------------------------------------ G-v9 -----------------------------------------
def regret(sets):
    out = {}
    for name, pairs in sets.items():
        r = [x for x in (V9.regret_resolve(net, sc) for net, sc in pairs) if x]
        out[name] = {"escalations": len(r), "resolved_automatically": sum(x["resolved"] for x in r),
                     "silent_introduced": sum(x["resolved"] and x["status_alt"] == S.NOT_CONTAINED for x in r)}
    out["target_met"] = all(v["silent_introduced"] == 0 for v in out.values() if isinstance(v, dict))
    return out


def main():
    t = time.perf_counter()
    sets, dropped = V9.fresh_sets_v9()
    h60 = V9.hospital60_v9()
    res = {"meta": meta("phase14_v9", ("hassan_v9.py", "phase14_v9.py", "hassan.py", "qubo_v7.py")),
           "fresh_sizes": {k: len(v) for k, v in sets.items()} | {"hospital60_7102": len(h60[1])}, "dropped_duplicates": dropped}
    for name, fn in (("fresh_claims", lambda: fresh_claims(sets, h60)),
                     ("S5_v9_certificates", lambda: certificates(sets["chains_7009"] + sets["random_9004"])),
                     ("S10_v9_guard", lambda: guard(sets["chains_7009"])),
                     ("R_v9_ransomware", ransomware), ("G_v9_regret", lambda: regret(sets))):
        t0 = time.perf_counter(); res[name] = fn()
        print(f"== {name} ({time.perf_counter() - t0:.1f}s): {json.dumps(res[name], default=str)[:1500]}", flush=True)
    res["meta"]["seconds"] = round(time.perf_counter() - t, 1)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v9.json").write_text(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()
