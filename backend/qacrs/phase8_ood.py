"""Phase 8 (v6): E11 out-of-distribution attack chains + E12 decision latency.

    cd backend && python -m qacrs.phase8_ood      -> results/v6/ood.json, results/v6/latency.json

Rules: docs/qacrs/PREREGISTRATION_v6.md. The model is frozen (LOCK_v5.json is checked first).
"""
from __future__ import annotations

import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

from qacrs import escalation_v5 as E5
from qacrs.independent_test_v5 import check_lock5
from qacrs.meta import meta
from qacrs.network import Network, Scenario, build as build_net, random_scenarios, scenarios
from qacrs.phase3_compare import q_acrs
from qacrs.phase6_heldout import heldout_pairs, tests
from qacrs.phase7_v5 import block, evaluate, fresh_pairs
from qacrs.policy_executor import MockFirewallAdapter, PolicyAuditLog, PolicyExecutor

OUT = Path(__file__).parent / "results" / "v6"
SEED, N_PER_NET = 7007, 200
P_TWO_CHAINS, P_CONTINUE, MAX_CHAIN = 0.3, 0.6, 4


def entry_points(net: Network) -> list[str]:
    return [m.name for m in net.machines if m.name.startswith(("web", "pc_"))]


def chain_scenarios(net: Network, n: int, seed: int) -> list[Scenario]:
    rng = random.Random(seed)
    out_links: dict[str, list[str]] = {}
    for a, b in net.links:
        out_links.setdefault(a, []).append(b)
    crown = {m.name for m in net.machines if m.critical}
    entries = entry_points(net)
    res = []
    for k in range(n):
        hacked: dict[str, int] = {}
        chains = 2 if rng.random() < P_TWO_CHAINS else 1
        paths = []
        for _ in range(chains):
            cur = rng.choice(entries); path = [cur]
            while len(path) < MAX_CHAIN and rng.random() < P_CONTINUE and out_links.get(cur):
                cur = rng.choice(out_links[cur]); path.append(cur)
            paths.append(path)
            for m in path:
                r = rng.randint(6, 9) if m in crown else rng.randint(3, 9)
                hacked[m] = max(hacked.get(m, 0), r)
        res.append(Scenario(f"{net.name}_ood{k + 1:03d}", net.name, hacked,
                            "attack chain(s): " + " | ".join(" -> ".join(p) for p in paths)))
    return res


def ood_pairs():
    prior = {}
    for net, s in heldout_pairs()[0] + fresh_pairs()[0]:
        prior.setdefault(net.name, set()).add(tuple(sorted(s.hacked.items())))
    pairs, dropped = [], []
    for net in (build_net(1), build_net(2)):
        seen = {tuple(sorted(s.hacked.items())) for s in scenarios(net)} | prior.get(net.name, set())
        for s in chain_scenarios(net, N_PER_NET, SEED):
            key = tuple(sorted(s.hacked.items()))
            if key in seen:
                dropped.append(s.id); continue
            seen.add(key); pairs.append((net, s))
    return pairs, dropped


def latency_ms(net, sc, reps=3) -> float:
    times = []
    for _ in range(reps):
        t = time.perf_counter()
        iso, _, _ = q_acrs(net, sc)                                           # build reduced QUBO + exact solve
        E5.decide(net, sc, iso)                                               # safety layer + v5 gate
        PolicyExecutor(net, MockFirewallAdapter(), PolicyAuditLog()).execute(sc, iso)   # plan (dry run)
        times.append(1000 * (time.perf_counter() - t))
    return statistics.median(times)


def pct(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def main():
    drift = check_lock5()
    if drift:
        sys.exit("REFUSED: v5-locked code changed:\n  " + "\n  ".join(drift))
    pairs, dropped = ood_pairs()
    rows = evaluate(pairs)
    for r, (_, s) in zip(rows, pairs):
        r["description"] = s.description
    res = {"meta": meta("phase8_ood", ("phase8_ood.py",), seed=SEED, per_network=N_PER_NET, p_two_chains=P_TWO_CHAINS,
                        p_continue=P_CONTINUE, max_chain=MAX_CHAIN, dropped_duplicates=dropped),
           "ood": block(rows) | {"n": len(rows)},
           "chain_stats": {"mean_hacked": statistics.mean(len(r["hacked"]) for r in rows),
                           "two_chain_share": sum(" | " in r["description"] for r in rows) / len(rows),
                           "reaches_critical": sum(any(h in ("dc", "db") or h.startswith("db_") for h in r["hacked"]) for r in rows) / len(rows)},
           "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ood.json").write_text(json.dumps(res, indent=1))
    o = res["ood"]; g = o["gate_comparison_q_acrs"]; t = o["tests"]
    print(f"OOD n={o['n']} (dropped {len(dropped)})  silent v3 {g['v3']['silent']} -> v5 {g['v5']['silent']} "
          f"(upper {g['v5']['silent_wilson95'][1]:.3f})  H2-v5-OOD {o['H2_v5_supported']}  escalation v5 {g['v5']['escalation_rate']:.3f}")
    print("H1:", t["H1_v3"], "\nH3:", t["H3_services_down_wilcoxon_one_sided"], "\nH4:", t["H4_containment_mcnemar"])
    print("chains:", res["chain_stats"])
    for r in rows:
        if r["q_acrs"]["status"] == "NOT_CONTAINED":
            print("SILENT", r["scenario"], r["hacked"], r["q_acrs"]["reasons"])

    sets = {"development": [(n, s) for n in (build_net(1), build_net(2)) for s in scenarios(n)],
            "heldout_9001": heldout_pairs()[0], "heldout_9002": fresh_pairs()[0], "ood_7007": pairs,
            "scaling_52_machines": [(build_net(5), s) for s in random_scenarios(build_net(5), 15, 2027)]}
    lat = {}
    for name, ps in sets.items():
        ms = [latency_ms(n, s) for n, s in ps]
        lat[name] = {"n": len(ms), "median_ms": statistics.median(ms), "p95_ms": pct(ms, 0.95), "max_ms": max(ms)}
        print(f"latency {name:20} n={len(ms):>3}  median {lat[name]['median_ms']:.2f} ms  p95 {lat[name]['p95_ms']:.2f}  max {lat[name]['max_ms']:.2f}")
    allp95 = max(v["p95_ms"] for v in lat.values()); allmax = max(v["max_ms"] for v in lat.values())
    (OUT / "latency.json").write_text(json.dumps({
        "meta": meta("phase8_latency", ("phase8_ood.py",), reps=3, machine=platform.processor() or platform.machine(),
                     cpu_count=__import__("os").cpu_count()),
        "sets": lat, "target": {"p95_below_ms": 1000, "max_below_ms": 7000},
        "target_met": allp95 < 1000 and allmax < 7000}, indent=1))
    print("latency target met:", allp95 < 1000 and allmax < 7000)


if __name__ == "__main__":
    main()
