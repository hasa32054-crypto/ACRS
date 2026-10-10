"""Phase 3b (v2): apply the PRE-REGISTERED containment criteria to the four methods on the same 40 scenarios.

    cd backend && python -m qacrs.phase3b_containment

Criteria, methods, metrics and hypothesis H1: docs/qacrs/PREREGISTRATION.md (written before this file).
Nothing in the QUBO or the scenarios is changed; the v1 Phase-3 decisions are re-used as they are.
Writes:  qacrs/results/v2/containment.json      (metadata + summary + every scenario)
         qacrs/results/v2/containment_per_scenario.csv
"""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import time
from pathlib import Path

import numpy as np

from qacrs import safety_checks as sc_mod
from qacrs.network import build as build_net, scenarios
from qacrs.phase3_compare import full_isolation, per_machine, q_acrs, score
from qacrs.qubo_builder import SPREAD

OUT = Path(__file__).parent / "results" / "v2"
PRIMARY = sc_mod.HIGH_RISK
SECONDARY = (6, 8)
H1_RATIO = 0.80
SEED, N_RANDOM = 2027, 15


def full_isolation_safe(net, sc):
    iso = {m.name for m in net.machines if m.isolatable}
    return {h for h in sc.hacked if h in iso}


METHODS = {
    "full_isolation": lambda net, sc: full_isolation(net, sc),
    "full_isolation_safe": full_isolation_safe,
    "per_machine": per_machine,
    "q_acrs": lambda net, sc: q_acrs(net, sc)[0],
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def metadata() -> dict:
    here = Path(__file__).parent
    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=here,
                                         stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        commit = "unknown"
    return {"experiment": "phase3b_containment", "version": "v2",
            "preregistration": "docs/qacrs/PREREGISTRATION.md",
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "git_commit": commit,
            "code_sha256_prefix": {f: _sha(here / f) for f in
                                   ("network.py", "qubo_builder.py", "safety_checks.py", "phase3_compare.py",
                                    "phase3b_containment.py")},
            "python": platform.python_version(), "numpy": np.__version__,
            "scenario_seed": SEED, "n_random_per_network": N_RANDOM, "weights": {"SPREAD": SPREAD,
            "note": "disruption, service values and risks exactly as in network.py (unchanged since v1)"},
            "solver_for_q_acrs": "exact brute force over all 2^n reduced decisions",
            "primary_threshold": PRIMARY, "secondary_thresholds": list(SECONDARY)}


def evaluate() -> dict:
    rows = []
    for net in (build_net(1), build_net(2)):
        for s in scenarios(net, N_RANDOM, SEED):
            row = {"scenario": s.id, "network": net.name, "hacked": s.hacked, "description": s.description}
            for name, fn in METHODS.items():
                iso = set(fn(net, s))
                base = score(net, s, iso)
                v = sc_mod.check(net, s, iso)
                row[name] = {"isolated": sorted(iso), "verdict": v.as_dict(),
                             "services_down": base["services_down"],
                             "healthy_isolated": sorted(iso - set(s.hacked)),
                             "risk_left": base["risk_left"], "cost": base["cost"],
                             "secondary": {str(t): sc_mod.check(net, s, iso, t).status for t in SECONDARY}}
            rows.append(row)
    return {"rows": rows}


def summarise(rows: list[dict]) -> dict:
    out = {}
    for name in METHODS:
        r = [row[name] for row in rows]
        st = [x["verdict"]["status"] for x in r]
        out[name] = {
            "scenarios": len(r),
            "status_counts": {s: st.count(s) for s in sc_mod.STATUSES},
            "contained": sum(s in (sc_mod.CONTAINED, sc_mod.PENDING) for s in st),
            "services_down": sum(len(x["services_down"]) for x in r),
            "healthy_isolated": sum(len(x["healthy_isolated"]) for x in r),
            "risk_left": sum(x["risk_left"] for x in r),
            "total_cost": round(sum(x["cost"] for x in r), 1),
            "needs_two_person": sum(bool(x["verdict"]["needs_two_person"]) for x in r),
            "owner_review": sum(bool(x["verdict"]["owner_review"]) for x in r),
            "contained_at_secondary": {str(t): sum(x["secondary"][str(t)] in (sc_mod.CONTAINED, sc_mod.PENDING)
                                                   for x in r) for t in SECONDARY},
        }
    return out


def test_h1(summary: dict) -> dict:
    q, b = summary["q_acrs"], summary["full_isolation_safe"]
    need = H1_RATIO * b["contained"]
    parts = {"containment_ratio": round(q["contained"] / b["contained"], 3) if b["contained"] else None,
             "containment_ok": q["contained"] >= need,
             "fewer_services_down": q["services_down"] < b["services_down"],
             "fewer_healthy_isolated": q["healthy_isolated"] < b["healthy_isolated"]}
    parts["H1_supported"] = all(parts[k] for k in ("containment_ok", "fewer_services_down",
                                                   "fewer_healthy_isolated"))
    parts["rule"] = (f"q_acrs contained >= {H1_RATIO:.0%} of full_isolation_safe contained, AND fewer services "
                     "down, AND fewer healthy machines isolated")
    return parts


def write_csv(rows: list[dict], path: Path) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "network", "hacked", "method", "isolated", "status", "reasons",
                    "needs_two_person", "owner_review", "services_down", "healthy_isolated", "risk_left", "cost",
                    "status_t6", "status_t8"])
        for row in rows:
            for name in METHODS:
                x = row[name]; v = x["verdict"]
                w.writerow([row["scenario"], row["network"], json.dumps(row["hacked"]), name,
                            " ".join(x["isolated"]), v["status"], " | ".join(v["reasons"]),
                            " ".join(v["needs_two_person"]), " ".join(v["owner_review"]),
                            " ".join(x["services_down"]), " ".join(x["healthy_isolated"]), x["risk_left"], x["cost"],
                            x["secondary"]["6"], x["secondary"]["8"]])


def main() -> None:
    t0 = time.perf_counter()
    res = evaluate()
    summary = summarise(res["rows"])
    h1 = test_h1(summary)
    meta = metadata() | {"seconds": round(time.perf_counter() - t0, 2), "status": "complete", "warnings": []}

    print(f"{'method':22}{'contained':>10}{'pending':>9}{'not cont.':>10}{'rejected':>9}"
          f"{'svc down':>9}{'healthy iso':>12}{'risk left':>10}")
    for k, s in summary.items():
        c = s["status_counts"]
        print(f"{k:22}{s['contained']:>7}/{s['scenarios']}{c[sc_mod.PENDING]:>9}{c[sc_mod.NOT_CONTAINED]:>10}"
              f"{c[sc_mod.REJECTED]:>9}{s['services_down']:>9}{s['healthy_isolated']:>12}{s['risk_left']:>10}")
    print(f"\nSecondary thresholds (contained): " + "; ".join(
        f"{k}: " + ", ".join(f"t={t} {n}" for t, n in s["contained_at_secondary"].items()) for k, s in summary.items()))
    print(f"\nH1 ({h1['rule']}): {'SUPPORTED' if h1['H1_supported'] else 'NOT SUPPORTED'}  {h1}")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "containment.json").write_text(json.dumps({"meta": meta, "summary": summary, "h1": h1,
                                                      "rows": res["rows"]}, indent=1))
    write_csv(res["rows"], OUT / "containment_per_scenario.csv")
    print("Saved: qacrs/results/v2/containment.json and containment_per_scenario.csv")


if __name__ == "__main__":
    main()
