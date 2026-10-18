"""Phase 19 (v13): immunity refinement D13-v13. Rules: PREREGISTRATION_v13.md (T9-v13, T9b-v13).

    cd backend && python -m qacrs.v12.phase19_v13    -> qacrs/results/v13/immunity_v13.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from qacrs import phase16_v11 as P16
from qacrs.v12 import immunity as IM
from qacrs.v12 import phase18_survive_immune as P18
from qacrs.v12 import qubo_v12 as Q

OUT = Path(__file__).parent.parent / "results" / "v13"
CORPUS = Path(__file__).parent / "corpus"


def corpus_same_attack(v13: bool) -> dict:
    """T9b: after immunisation, replaying the SAME attack must never take more services down than before."""
    rows, worse = [], []
    for p in sorted(CORPUS.glob("*.json")):
        if p.name == "MANIFEST.json":
            continue
        d, net, scs = P16.load(p)
        if net is None:
            continue
        path = P18.path_of(d)
        if len(path) < 2:
            continue
        tech = [t for hop in d.get("attack_path", []) for t in hop[2].split() if t.startswith("T1")]
        last = scs[-1]
        before = Q.evaluate_policy(net, last, "v12")
        im = IM.Immunity(v13=v13); im.learn(net, path, tech, p.stem)
        after = Q.evaluate_policy(net, last, "v12", im)
        b, a = len(before["services_down_after_approval"]), len(after["services_down_after_approval"])
        row = {"case": p.stem, "down_before": b, "down_after": a, "first_hop_isolated": path[0] in after["isolate"],
               "unsafe_after": after["unsafe"], "silent_after": after["silent"]}
        rows.append(row)
        if a > b: worse.append(row)
    return {"n": len(rows), "worse": len(worse), "worse_cases": worse, "better": sum(r["down_after"] < r["down_before"] for r in rows),
            "first_hop_isolated": sum(r["first_hop_isolated"] for r in rows),
            "unsafe": sum(r["unsafe_after"] for r in rows), "silent": sum(r["silent_after"] for r in rows),
            "met": not worse, "rows": rows}


def main() -> None:
    t0 = time.time()
    real = []
    for p in sorted(P16.INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is not None:
            real.append((p.stem, net, scs, d))
    t9 = P18.immunity(real, v13=True)
    rows = [r for r in t9["rows"] if "skipped" not in r]
    # T9-v13 as pre-registered: same attack <= before in 8/8; similar <= before in >= 6/8; dissimilar identical wherever one exists
    t9["summary_v13"] = {
        "same_le_before": sum(r["same_down_before_after"][1] <= r["same_down_before_after"][0] for r in rows),
        "same_first_hop_isolated": sum(r["same_first_hop_isolated_at_m1"] for r in rows),
        "similar_le_before": sum(r["similar_down_before_after"][1] <= r["similar_down_before_after"][0] for r in rows),
        "dissimilar_identical": t9["summary"]["dissimilar_identical"], "dissimilar_n": t9["summary"]["dissimilar_n"], "n": len(rows)}
    sv = t9["summary_v13"]
    sv["met"] = sv["same_le_before"] == sv["n"] and sv["similar_le_before"] >= 6 and sv["dissimilar_identical"] == sv["dissimilar_n"]
    res = {"T9_v13_real": t9, "T9_v12_real_for_contrast": P18.immunity(real, v13=False),
           "T9b_v13_corpus": corpus_same_attack(True), "T9b_v12_corpus_for_contrast": corpus_same_attack(False),
           "meta": {"experiment": "v13-immunity", "seconds": round(time.time() - t0, 1)}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "immunity_v13.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print("T9-v13 real:", res["T9_v13_real"]["summary_v13"])
    print("T9-v12 real:", res["T9_v12_real_for_contrast"]["summary"])
    for k in ("T9b_v13_corpus", "T9b_v12_corpus_for_contrast"):
        c = res[k]; print(k, {x: c[x] for x in ("n", "worse", "better", "first_hop_isolated", "unsafe", "silent", "met")})
        for w in c["worse_cases"][:10]: print("   worse:", w)


if __name__ == "__main__":
    main()
