"""v11 E1: a white-box attacker against five fusion defenders. Rules: docs/qacrs/PREREGISTRATION_v11.md.

    cd backend && python -m qacrs.phase16_v11            # -> results/v11/attack.json  (~2 h on 2 cores)
    cd backend && python -m qacrs.phase16_v11 --resume   # continue an interrupted run from results/v11/partial/

Every scenario is written to results/v11/partial/<id>.json as soon as it is done, so a crash loses nothing.
The v9 engine (hassan.py, hassan_v9.py, qubo_v7.py ...) is imported unchanged.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import random
import sys
import time
from pathlib import Path

from qacrs import hassan_v9 as V9
from qacrs import sensors_v11 as SV
from qacrs.meta import meta
from qacrs.network import build as build_net
from qacrs.phase8_ood import chain_scenarios

OUT = Path(__file__).parent / "results" / "v11"
PART = OUT / "partial"
N_PER_NET = 120
CHAIN_SEED = {1: 7501, 2: 7502}
NOISE_SEED, NDR_SEED, FP_SEED = 7511, 7521, 7531
BEAM_WIDTH, BEAM_GAMMA = 20, 3
GOALS = ("A1", "A2", "A3")
LOCKED = ("hassan.py", "hassan_v9.py", "qubo_v7.py", "qubo_builder.py", "escalation.py", "safety_checks.py", "network.py")


def dataset():
    """Fresh chains (seeds 7501/7502), exact duplicates dropped, plus per-scenario honest readings and NDR flows.
    The random streams are created once per network and consumed in scenario order (fixed, reproducible)."""
    items, dropped = [], {}
    for d in (1, 2):
        net = build_net(d)
        rn, rf, rd = random.Random(NOISE_SEED + d), random.Random(FP_SEED + d), random.Random(NDR_SEED + d)
        seen, drop = set(), 0
        for sc in chain_scenarios(net, N_PER_NET, CHAIN_SEED[d]):
            key = tuple(sorted(sc.hacked.items()))
            if key in seen:
                drop += 1; continue
            seen.add(key)
            sc.id = sc.id + "_v11"
            honest = SV.honest_readings(net, sc, rn, rf)
            lateral = V9.ndr_lateral_flows(net, V9.hops_of(sc), rd)
            items.append((d, sc, honest, sorted(lateral)))
        dropped[net.name] = drop
    return items, dropped


def run_one(item) -> dict:
    d, sc, honest, lateral = item
    net = build_net(d)
    lateral = set(map(tuple, lateral))
    values2 = SV.VALUES_FULL if d == 1 else SV.VALUES_SMALL
    rec = {"id": sc.id, "network": net.name, "truth": sc.hacked, "description": sc.description,
           "honest": {m: list(v) for m, v in honest.items() if any(v)}, "defenders": {}}
    t0 = time.perf_counter()
    for name, (rule, ndr) in SV.DEFENDERS.items():
        dfd = SV.Defender(net, rule, ndr)
        g1 = SV.exhaustive(dfd, sc, honest, lateral, 1, values=SV.VALUES_FULL, goals=GOALS)
        g2 = SV.exhaustive(dfd, sc, honest, lateral, 2, values=values2, goals=GOALS)
        g3 = {g: SV.beam(dfd, sc, honest, lateral, g, BEAM_GAMMA, BEAM_WIDTH) for g in GOALS}
        rec["defenders"][name] = {"base": g1["base"],
                                  "gamma1": g1["goals"], "gamma2": g2["goals"], "gamma3_beam": g3,
                                  "tried": {"gamma1": g1["n_tried"], "gamma2": g2["n_tried"]},
                                  "gamma2_values": "0-10" if d == 1 else "{0,1,6,7,10}"}
    rec["seconds"] = round(time.perf_counter() - t0, 2)
    return rec


def radius(dres: dict, goal: str):
    if dres["gamma1"][goal]["success"]:
        return 1
    if dres["gamma2"][goal]["success"]:
        return 2
    return ">=3"


def summarise(recs: list[dict]) -> dict:
    from qacrs.stats import mcnemar_exact, wilson
    n = len(recs)
    out = {"n_scenarios": n, "per_defender": {}}
    for name in SV.DEFENDERS:
        row = {}
        for gk in ("gamma1", "gamma2", "gamma3_beam"):
            for g in GOALS:
                k = sum(r["defenders"][name][gk][g]["success"] for r in recs)
                row[f"{g}_{gk}"] = {"k": k, "rate": round(k / n, 4), "wilson95": [round(x, 4) for x in wilson(k, n)]}
        row["services_extra_max_gamma_le2"] = max(
            max((r["defenders"][name][gk]["A1"]["outcome"] or {}).get("services_down", 0)
                - r["defenders"][name]["base"]["services_down"] for gk in ("gamma1", "gamma2")) for r in recs)
        row["radius_A2"] = {v: sum(radius(r["defenders"][name], "A2") == v for r in recs) for v in (1, 2, ">=3")}
        row["radius_A1"] = {v: sum(radius(r["defenders"][name], "A1") == v for r in recs) for v in (1, 2, ">=3")}
        row["honest"] = {"silent": sum(r["defenders"][name]["base"]["status"] == "CONTAINED"
                                       and r["defenders"][name]["base"]["truth_status"] == "NOT_CONTAINED" for r in recs),
                         "services_down": sum(r["defenders"][name]["base"]["services_down"] for r in recs),
                         "escalated": sum(r["defenders"][name]["base"]["status"] == "ESCALATED" for r in recs)}
        out["per_defender"][name] = row
    a = [r["defenders"]["D0"]["gamma1"]["A2"]["success"] for r in recs]
    b = [r["defenders"]["D3"]["gamma1"]["A2"]["success"] for r in recs]
    d0_only, d3_only = sum(x and not y for x, y in zip(a, b)), sum(y and not x for x, y in zip(a, b))
    p = mcnemar_exact(d0_only, d3_only)
    d3_rate = sum(b) / n
    h1 = d0_only > d3_only and p < 0.05 and d3_rate <= 0.05
    h2 = all(max((r["defenders"]["D4"][gk]["A1"]["outcome"] or {}).get("services_down", 0)
                 - r["defenders"]["D4"]["base"]["services_down"] for gk in ("gamma1", "gamma2")) <= 0 for r in recs)
    h3_share = sum(radius(r["defenders"]["D4"], "A2") != 1 for r in recs) / n
    out["hypotheses"] = {
        "H1": {"target": "A2 at gamma 1: D3 < D0 (exact McNemar p<0.05) and D3 <= 5%", "d0_only": d0_only,
               "d3_only": d3_only, "p": p, "d3_rate": round(d3_rate, 4), "met": h1},
        "H2": {"target": "A1 at gamma<=2: D4 causes 0 extra services down in every scenario", "met": h2},
        "H3": {"target": "certified A2 radius under D4 >= 2 in >= 80% of scenarios", "share": round(h3_share, 4),
               "met": h3_share >= 0.80}}
    out["d4_successes"] = [{"id": r["id"], "goal": g, "gamma": gk, "attack": r["defenders"]["D4"][gk][g]["attack"],
                            "outcome": r["defenders"]["D4"][gk][g]["outcome"]}
                           for r in recs for gk in ("gamma1", "gamma2", "gamma3_beam") for g in ("A1", "A2")
                           if r["defenders"]["D4"][gk][g]["success"]]
    return out


def main(resume: bool = False, workers: int = 2):
    PART.mkdir(parents=True, exist_ok=True)
    items, dropped = dataset()
    todo = [it for it in items if not (resume and (PART / f"{it[1].id}.json").exists())]
    print(f"v11 E1: {len(items)} scenarios ({dropped} duplicates dropped), {len(todo)} to run, {workers} workers")
    t = time.time()
    with mp.Pool(workers) as pool:
        for i, rec in enumerate(pool.imap_unordered(run_one, todo), 1):
            (PART / f"{rec['id']}.json").write_text(json.dumps(rec))
            if i % 10 == 0:
                print(f"  {i}/{len(todo)}  {time.time() - t:.0f} s")
    recs = sorted((json.loads((PART / f"{it[1].id}.json").read_text()) for it in items), key=lambda r: r["id"])
    res = {"meta": meta("v11_attack", extra_files=LOCKED + ("sensors_v11.py", "phase16_v11.py"),
                        preregistration="docs/qacrs/PREREGISTRATION_v11.md", n_per_net=N_PER_NET,
                        chain_seeds=CHAIN_SEED, noise_seed=NOISE_SEED, fp_seed=FP_SEED, ndr_seed=NDR_SEED,
                        beam_width=BEAM_WIDTH, beam_gamma=BEAM_GAMMA, duplicates_dropped=dropped),
           "summary": summarise(recs), "scenarios": recs}
    (OUT / "attack.json").write_text(json.dumps(res, indent=1))
    h = res["summary"]["hypotheses"]
    print("H1", h["H1"]["met"], "H2", h["H2"]["met"], "H3", h["H3"]["met"], f"total {time.time() - t:.0f} s")
    return res


if __name__ == "__main__":
    main(resume="--resume" in sys.argv)
