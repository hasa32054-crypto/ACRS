"""Phase 10 (v8 B): can an attacker turn HASSAN against the hospital?

    cd backend && python -m qacrs.phase10_adversarial      -> results/v8/adversarial.json

Rules: docs/qacrs/PREREGISTRATION_v8.md, section B. Forged-alert generators (fixed here, before results):
  * exhaustive: every set of 1-3 machines at risk 10 (the strongest forged signal), per network;
  * random: 10,000 per network, 1-5 machines, risks uniform 1-10, seed 8008;
  * manipulation (S10): 1,000 sets, seed 8009. Half "naive" (1-3 service replicas / critical servers at risk 9-10);
    half "path-aware" (a target plus a plausible chain of predecessors back to an exposed entry point, chain risks 3-8).
"Automatic damage" = what happens with no human: isolations applied + segments applied (critical isolation always waits).
"""
from __future__ import annotations

import itertools
import json
import random
import statistics
import time
from pathlib import Path

from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.meta import meta
from qacrs.network import Scenario, build as build_net, random_scenarios, scenarios
from qacrs.phase6_heldout import heldout_pairs
from qacrs.phase7_v5 import fresh_pairs
from qacrs.phase8_ood import ood_pairs
from qacrs.phase9_v7 import fresh_sets

OUT = Path(__file__).parent / "results" / "v8"
NETS = (build_net(1), build_net(2))


def fresh_engine(net):
    return H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9))      # single incident: rate limit not the subject here


def damage_hassan(net, sc, eng=None):
    d = (eng or fresh_engine(net)).decide(sc)
    iso, seg = set(d.isolate), set(d.segment)
    crit = {m.name for m in net.machines if m.critical}
    return {"services_down": len(V7.services_down_v7(net, iso, seg, set(sc.hacked))), "isolated": len(iso),
            "critical_isolated_auto": len(iso & crit), "isolated_not_reported": len(iso - set(sc.hacked)),
            "cert_ok": H.verify_certificate(net, sc, d.certificate)}


def damage_full_safe(net, sc):
    machines = {m.name: m for m in net.machines}
    iso = {h for h in sc.hacked if machines[h].isolatable and not machines[h].critical}   # automatic part only
    return {"services_down": len(V7.services_down_v7(net, iso, set(), set(sc.hacked))), "isolated": len(iso)}


def harm_bound():
    out = {}
    for net in NETS:
        names = [m.name for m in net.machines]
        eng = fresh_engine(net)
        worst_h, worst_f, n = {"services_down": 0}, {"services_down": 0}, 0
        viol = {"critical_isolated_auto": 0, "isolated_not_reported": 0, "cert_fail": 0}
        for k in (1, 2, 3):
            for combo in itertools.combinations(names, k):
                sc = Scenario("forged", net.name, {m: 10 for m in combo}, "forged")
                h, f = damage_hassan(net, sc, eng), damage_full_safe(net, sc); n += 1
                viol["critical_isolated_auto"] += h["critical_isolated_auto"] > 0
                viol["isolated_not_reported"] += h["isolated_not_reported"] > 0
                viol["cert_fail"] += not h["cert_ok"]
                if h["services_down"] > worst_h["services_down"]:
                    worst_h = h | {"set": combo}
                if f["services_down"] > worst_f["services_down"]:
                    worst_f = f | {"set": combo}
        out[net.name] = {"forged_sets": n, "hassan_worst": worst_h, "full_isolation_safe_worst": worst_f,
                         "violations": viol}
    out["H9_supported"] = all(out[n.name]["hassan_worst"]["services_down"] < out[n.name]["full_isolation_safe_worst"]["services_down"]
                              for n in NETS)
    return out


def random_forgeries(net, n, seed):
    rng = random.Random(seed); names = [m.name for m in net.machines]
    return [Scenario(f"rf{i}", net.name, {m: rng.randint(1, 10) for m in rng.sample(names, rng.randint(1, 5))}, "forged")
            for i in range(n)]


def certificate_validity():
    out = {}
    for net in NETS:
        worst, viol = 0, {"critical_isolated_auto": 0, "isolated_not_reported": 0, "cert_fail": 0}
        eng = fresh_engine(net)
        for sc in random_forgeries(net, 10_000, 8008):
            h = damage_hassan(net, sc, eng)
            worst = max(worst, h["services_down"])
            viol["critical_isolated_auto"] += h["critical_isolated_auto"] > 0
            viol["isolated_not_reported"] += h["isolated_not_reported"] > 0
            viol["cert_fail"] += not h["cert_ok"]
        out[net.name] = {"sets": 10_000, "violations": viol, "worst_services_down": worst}
    return out


def flood():
    net = NETS[0]
    clock = [0.0]
    eng = H.Engine(net, limiter=H.RateLimiter(clock=lambda: clock[0]))
    rng = random.Random(8010)
    lat, iso_total, unreported = [], 0, 0
    pool = random_forgeries(net, 1000, 8011)
    for i, sc in enumerate(pool):
        clock[0] = 60.0 * i / 1000                         # 1,000 alerts inside one simulated minute
        d = eng.decide(sc)
        lat.append(d.ms); iso_total += len(d.isolate); unreported += len(set(d.isolate) - set(sc.hacked))
    lat.sort()
    return {"alerts": 1000, "window_s": 60, "auto_isolations_total": iso_total, "rate_limit": H.RATE_LIMIT,
            "isolated_not_reported": unreported, "latency_ms": {"median": lat[500], "p99": lat[989], "max": lat[-1]},
            "p99_target_met": lat[989] < 10, "rate_limit_respected": iso_total <= H.RATE_LIMIT}


def inflation():
    sets = {"development": [(n, s) for n in NETS for s in scenarios(n)], "heldout_9001": heldout_pairs()[0],
            "heldout_9002": fresh_pairs()[0], "ood_7007": ood_pairs()[0]}
    fs, _ = fresh_sets(); sets |= fs
    out = {}
    for name, pairs in sets.items():
        crit_auto, down, n = 0, 0, 0
        engines = {net.name: fresh_engine(net) for net in NETS}
        for net, sc in pairs:
            inflated = Scenario(sc.id, sc.network, {m: 10 for m in sc.hacked}, sc.description)
            h = damage_hassan(net, inflated, engines[net.name]); n += 1
            crit_auto += h["critical_isolated_auto"]; down += h["services_down"]
        out[name] = {"scenarios": n, "critical_isolated_automatically": crit_auto, "services_down": down}
    return out


def failsafe():
    net = NETS[0]
    def boom(*_): raise RuntimeError("injected")
    def slow(*_): time.sleep(0.15); return set(), set(), "slow"
    def bad(*_): return {"ghost"}, set(), "bad"
    res = {"exception": 0, "timeout": 0, "malformed": 0}
    crashes, silent, n = 0, 0, 0
    pool = random_scenarios(net, 1000, 8012)
    engines = {k: H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9), solver=f)
               for k, f in (("exception", boom), ("timeout", slow), ("malformed", bad))}
    for i, sc in enumerate(pool):
        kind = ("exception", "timeout", "malformed")[i % 3]
        eng = engines[kind]
        try:
            d = eng.decide(sc); n += 1
        except Exception:
            crashes += 1; continue
        if d.fallback and not d.isolate and not d.segment and d.status == "ESCALATED":
            res[kind] += 1
        silent += d.status == S.NOT_CONTAINED
    return {"injected": 1000, "fell_back_correctly": res, "crashes": crashes, "silent": silent,
            "target_met": sum(res.values()) == 1000 and crashes == 0 and silent == 0}


def manipulated_sets(net, n, seed):
    rng = random.Random(seed)
    preds = {}
    for a, b in net.links:
        preds.setdefault(b, []).append(a)
    targets = sorted({r for s in net.services for r in s.replicas} | {m.name for m in net.machines if m.critical})
    entries = H.entry_points(net)
    out = []
    for i in range(n):
        hacked = {t: rng.randint(9, 10) for t in rng.sample(targets, rng.randint(1, 3))}
        kind = "naive"
        if i % 2:                                         # path-aware forger builds a plausible chain to each target
            kind = "path_aware"
            for t in list(hacked):
                cur = t
                while cur not in entries and preds.get(cur):
                    cur = rng.choice(preds[cur])
                    hacked.setdefault(cur, rng.randint(3, 8))
        out.append((Scenario(f"mf{i}", net.name, hacked, kind), kind))
    return out


def guard():
    det = {"naive": [0, 0], "path_aware": [0, 0]}
    for net in NETS:
        for sc, kind in manipulated_sets(net, 500, 8009 + len(net.machines)):
            det[kind][1] += 1; det[kind][0] += bool(H.consistency_flags(net, sc))
    total = sum(v[0] for v in det.values()) / sum(v[1] for v in det.values())
    ff = {}
    fs, _ = fresh_sets()
    for name, pairs in (("ood_7007", ood_pairs()[0]), ("chains_7008", fs["chains_7008"]),
                        ("heldout_9001_random", heldout_pairs()[0])):
        flagged = sum(bool(H.consistency_flags(n, s)) for n, s in pairs)
        ff[name] = {"scenarios": len(pairs), "flagged": flagged, "rate": flagged / len(pairs)}
    chain_rate = (ff["ood_7007"]["flagged"] + ff["chains_7008"]["flagged"]) / (ff["ood_7007"]["scenarios"] + ff["chains_7008"]["scenarios"])
    return {"detection": {k: {"detected": v[0], "n": v[1], "rate": v[0] / v[1]} for k, v in det.items()},
            "detection_overall": total, "false_flags": ff, "false_flag_rate_chains": chain_rate,
            "target_detection_met": total >= 0.8, "target_false_flag_met": chain_rate <= 0.10,
            "caveat": "chains are generated with the same 'reachable from a hacked predecessor or entry' idea the guard "
                      "uses, so their false-flag rate is optimistic; the random sets show the opposite extreme"}


def main():
    t = time.perf_counter()
    res = {"meta": meta("phase10_adversarial", ("hassan.py", "phase10_adversarial.py", "qubo_v7.py"))}
    for name, fn in (("harm_bound_exhaustive", harm_bound), ("certificate_validity_random", certificate_validity),
                     ("flood", flood), ("inflation", inflation), ("failsafe", failsafe), ("consistency_guard", guard)):
        t0 = time.perf_counter(); res[name] = fn()
        print(f"== {name} ({time.perf_counter() - t0:.1f}s)\n{json.dumps(res[name], indent=1, default=str)[:1500]}", flush=True)
    res["meta"]["seconds"] = round(time.perf_counter() - t, 1)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "adversarial.json").write_text(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()
