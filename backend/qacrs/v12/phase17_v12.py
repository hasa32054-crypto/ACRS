"""Phase 17 (v12): the main experiment. Rules: docs/qacrs/PREREGISTRATION_v12.md (D5, D6, D7, T1-T7, T11).

    cd backend && python -m qacrs.v12.phase17_v12       -> qacrs/results/v12/v12.json

Sets: real 16 moments (v11 conversions), open corpus (qacrs/v12/corpus/*.json, if present), realistic generator
(D4, 894 moments), v9 fresh sets (regression). Five policies on every scenario. Primary metric: services down AFTER
approvals. Plus monotonicity (D6), scale (D7), sensitivity x0.5/x1.5 on the real set (T11), guard (T4).
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
import time
from pathlib import Path

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import stats
from qacrs import phase16_v11 as P16
from qacrs.phase10_adversarial import manipulated_sets
from qacrs.network import build as build_net
from qacrs.v12 import guard_v12 as G
from qacrs.v12 import qubo_v12 as Q
from qacrs.v12 import realism_v12 as R
from qacrs.v12 import risk_map as RM

HERE = Path(__file__).parent
OUT = HERE.parent / "results" / "v12"
CORPUS = HERE / "corpus"
PREREG = HERE.parent.parent.parent / "docs" / "qacrs" / "PREREGISTRATION_v12.md"
POL = list(Q.POLICIES)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ------------------------------------------------------------------ sets -----------------------------------------
def real_set():
    out = []
    for p in sorted(P16.INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is not None:
            out.append((p.stem, net, scs))
    return out


def corpus_set():
    out, dropped = [], []
    if not CORPUS.exists():
        return out, dropped
    for p in sorted(CORPUS.glob("*.json")):
        if p.name == "MANIFEST.json":
            continue
        try:
            d, net, scs = P16.load(p)
        except Exception as e:  # noqa: BLE001 - a broken conversion is reported, not hidden
            dropped.append({"file": p.name, "reason": f"invalid: {e}"}); continue
        if net is None:
            dropped.append({"file": p.name, "reason": d.get("drop_reason", "")})
        else:
            out.append((p.stem, net, scs))
    return out, dropped


def v9_regression_set():
    fs, _ = V9.fresh_sets_v9()
    return [(name, [(net, sc) for net, sc in pairs]) for name, pairs in fs.items()]


# ------------------------------------------------------------------ evaluation -----------------------------------
def compare(net, sc) -> dict:
    return {p: Q.evaluate_policy(net, sc, p) for p in POL}


def summarise(rows: list[dict], label: str) -> dict:
    n = len(rows)
    out = {"label": label, "n": n, "policies": {}}
    for p in POL:
        ev = [r["policies"][p] for r in rows]
        auto = sum(e["auto_contained"] for e in ev)
        pool = [r for r in rows if len(r["policies"]["full_isolation"]["services_down_after_approval"]) >= 1]
        fewer = sum(len(r["policies"][p]["services_down_after_approval"])
                    < len(r["policies"]["full_isolation"]["services_down_after_approval"]) for r in pool)
        out["policies"][p] = {
            "unsafe": sum(e["unsafe"] for e in ev), "silent": sum(e["silent"] for e in ev),
            "auto_contained": auto, "auto_ratio": auto / n if n else None, "auto_wilson95": stats.wilson(auto, n) if n else None,
            "services_down_auto": sum(len(e["services_down_auto"]) for e in ev),
            "services_down_after_approval": sum(len(e["services_down_after_approval"]) for e in ev),
            "healthy_isolated": sum(len(e["healthy_isolated"]) for e in ev),
            "escalations": sum(e["escalations"] for e in ev),
            "fewer_than_full_isolation": {"k": fewer, "pool": len(pool),
                                          "wilson95": stats.wilson(fewer, len(pool)) if pool else None},
            "decision_ms_median": sorted(e["decision_ms"] for e in ev)[n // 2] if n else None,
            "decision_ms_max": max((e["decision_ms"] for e in ev), default=None),
        }
    return out


def run_set(items) -> list[dict]:
    rows = []
    for net, sc in items:
        rows.append({"scenario": sc.id, "n_machines": len(net.machines), "hacked": sc.hacked, "policies": compare(net, sc),
                     "guard_v12": G.flags_v12(net, sc), "guard_v9": H.consistency_flags(net, sc)})
    return rows


# ------------------------------------------------------------------ D6 monotonicity --------------------------------
def monotonicity(groups) -> dict:
    """groups: list of (net, [sc_m1, sc_m2, ...]) ordered in time."""
    checked = ok = 0; misses = []
    for net, scs in groups:
        prev = None
        for sc in scs:
            d = Q.decide_v12(net, sc)
            cur = (set(d.isolate), set(d.segment) | set(d.isolate))
            if prev is not None:
                checked += 1
                still = set(sc.hacked)
                released = {h for h in prev[0] if h in still and h not in cur[0]}
                if released:
                    misses.append({"scenario": sc.id, "released": sorted(released)})
                else:
                    ok += 1
            prev = cur
    return {"checked": checked, "ok": ok, "misses": misses, "met": checked > 0 and ok == checked}


# ------------------------------------------------------------------ D7 scale ---------------------------------------
def scale(sizes=(100, 300, 1000), n=50, seed=12013) -> dict:
    rng = random.Random(seed)
    out = {}
    for size in sizes:
        times, unsafe, auto = [], 0, 0
        for i in range(n):
            sector = rng.choice(list(R.SECTORS))
            spec = R.SECTORS[sector]
            n_pcs = size - 2 - len(spec["servers"]) - len(spec["devices"]) - 2
            net = R.build_network(rng, sector, n_pcs, rng.choice([0.0, 0.1, 0.3]), rng.random() < 0.5, f"s{size}_{i}")
            sc = R.moments(rng, net, R.chain(rng, net), f"s{size}_{i}")[-1]
            e = Q.evaluate_policy(net, sc, "v12")
            times.append(e["decision_ms"]); unsafe += e["unsafe"]; auto += e["auto_contained"]
        times.sort()
        out[str(size)] = {"n": n, "median_ms": times[n // 2], "p95_ms": times[int(0.95 * (n - 1))], "max_ms": times[-1],
                          "unsafe": unsafe, "auto_contained": auto}
    return out


# ------------------------------------------------------------------ T11 sensitivity --------------------------------
def sensitivity(real) -> dict:
    out = {"x0.5": [0, 0], "x1.5": [0, 0]}
    for _, net, scs in real:
        for sc in scs:
            base = Q.decide_v12(net, sc)
            for f, key in ((0.5, "x0.5"), (1.5, "x1.5")):
                n2 = copy.deepcopy(net)
                for s in n2.services:
                    s.value = s.value * f
                for m in n2.machines:
                    m.disruption = m.disruption * f
                d = Q.decide_v12(n2, sc)
                out[key][1] += 1
                out[key][0] += (set(d.isolate), set(d.segment)) == (set(base.isolate), set(base.segment))
    return {k: {"same_decision": v[0], "n": v[1]} for k, v in out.items()}


# ------------------------------------------------------------------ T4 guard ---------------------------------------
def guard(real) -> dict:
    real_burst_v9 = real_burst_v12 = 0
    for _, net, scs in real:
        for sc in scs:
            real_burst_v9 += any("burst" in f for f in H.consistency_flags(net, sc))
            real_burst_v12 += any("burst" in f for f in G.flags_v12(net, sc))
    inj = {"naive": [0, 0, 0], "path_aware": [0, 0, 0]}      # v12 flagged, v9 flagged, n
    for net in (build_net(1), build_net(2)):
        for sc, kind in manipulated_sets(net, 500, 8009 + len(net.machines)):
            inj[kind][2] += 1
            inj[kind][0] += bool(G.flags_v12(net, sc)); inj[kind][1] += bool(H.consistency_flags(net, sc))
    naive_rel = inj["naive"][0] / inj["naive"][1] if inj["naive"][1] else None
    return {"real_detonations_flagged": {"v9": real_burst_v9, "v12": real_burst_v12},
            "injections": {k: {"v12": v[0], "v9": v[1], "n": v[2]} for k, v in inj.items()},
            "naive_detection_relative_to_v9": naive_rel,
            "met": real_burst_v12 == 0 and (naive_rel or 0) >= 0.9}


# ------------------------------------------------------------------ main ------------------------------------------
def main() -> None:
    t0 = time.time()
    real = real_set()
    corpus, corpus_dropped = corpus_set()
    nets, scen = R.generate()
    byname = {n.name: n for n in nets}
    sets = {}
    sets["real16"] = run_set([(net, sc) for _, net, scs in real for sc in scs])
    sets["corpus"] = run_set([(net, sc) for _, net, scs in corpus for sc in scs])
    sets["realistic_v12"] = run_set([(byname[name], sc) for name, scs in scen for sc in scs])
    for name, pairs in v9_regression_set():
        sets[f"v9_{name}"] = run_set(pairs)

    summaries = {k: summarise(v, k) for k, v in sets.items()}

    def t(k):
        return summaries[k]["policies"]

    r16, co = t("real16"), t("corpus")
    targets = {
        "T1": {"met": all(t(k)["v12"]["unsafe"] == 0 and t(k)["v12"]["silent"] == 0 for k in summaries),
               "detail": {k: [t(k)["v12"]["unsafe"], t(k)["v12"]["silent"]] for k in summaries}},
        "T2": {"real16": r16["v12"]["auto_ratio"], "corpus": co["v12"]["auto_ratio"],
               "met": (r16["v12"]["auto_ratio"] or 0) >= 0.8 and (co["v12"]["auto_ratio"] is None or co["v12"]["auto_ratio"] >= 0.8)},
        "T3": {"real16": {"v12": r16["v12"]["services_down_after_approval"], "rule_segment": r16["rule_segment"]["services_down_after_approval"],
                          "fewer_than_full": r16["v12"]["fewer_than_full_isolation"]},
               "corpus": {"v12": co["v12"]["services_down_after_approval"], "rule_segment": co["rule_segment"]["services_down_after_approval"],
                          "fewer_than_full": co["v12"]["fewer_than_full_isolation"]}},
        "T4": guard(real),
        "T5": {k: {"v12_auto": t(k)["v12"]["auto_contained"], "v9_auto": t(k)["v9"]["auto_contained"],
                   "v12_down": t(k)["v12"]["services_down_after_approval"], "v9_down": t(k)["v9"]["services_down_after_approval"]}
               for k in summaries if k.startswith("v9_")},
        "T6": monotonicity([(net, scs) for _, net, scs in real if len(scs) >= 2]
                           + [(byname[name], scs) for name, scs in scen if len(scs) >= 2]),
        "T7": scale(),
        "T11": sensitivity(real),
    }
    t3 = targets["T3"]
    pool = t3["real16"]["fewer_than_full"]
    t3["met_real16"] = t3["real16"]["v12"] <= t3["real16"]["rule_segment"] and pool["pool"] > 0 and pool["k"] / pool["pool"] >= 0.7
    t5 = targets["T5"]
    t5["met"] = all(v["v12_auto"] >= v["v9_auto"] and v["v12_down"] <= v["v9_down"] for v in t5.values() if isinstance(v, dict))
    targets["T7"]["met"] = targets["T7"]["1000"]["median_ms"] <= 2000 and targets["T7"]["1000"]["unsafe"] == 0

    res = {"meta": {"experiment": "v12", "prereg_sha256": sha(PREREG) if PREREG.exists() else None,
                    "script_sha256": sha(Path(__file__)), "risk_table_hash": RM.table_hash(),
                    "realistic_corpus_hash": R.corpus_hash(nets, scen), "corpus_files": len(corpus) + len(corpus_dropped),
                    "corpus_converted": len(corpus), "corpus_dropped": corpus_dropped,
                    "converter": "Claude (Anthropic) for the open corpus — not an independent human",
                    "wording": "all containment figures are 'given an alert'", "seconds": round(time.time() - t0, 1)},
            "targets": targets, "summaries": summaries,
            "rows": {k: v for k, v in sets.items() if k in ("real16", "corpus")}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "v12.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"targets": {k: (v.get("met", v.get("met_real16")) if isinstance(v, dict) else v) for k, v in targets.items()}},
                     indent=1))
    for k, s in summaries.items():
        print(k, s["n"], {p: (s["policies"][p]["auto_contained"], s["policies"][p]["services_down_after_approval"],
                              s["policies"][p]["unsafe"]) for p in POL})
    print(f"saved {OUT / 'v12.json'} in {res['meta']['seconds']} s")


if __name__ == "__main__":
    main()
