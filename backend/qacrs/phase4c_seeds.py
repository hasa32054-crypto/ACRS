"""Phase 4c (v3, E4): QAOA and CVaR over several optimiser seeds, with a REAL 100-sample budget.

    cd backend && python -m qacrs.phase4c_seeds 0 1 2 3 4      # one JSON per seed in results/v3/qaoa_seeds/
    cd backend && python -m qacrs.phase4c_seeds --aggregate    # -> results/v3/qaoa_seeds_summary.json

Rules: docs/qacrs/PREREGISTRATION_v3.md (E4). Uses the unchanged v1 code paths (`run_qaoa`, `tune`).
For each scenario and seed:
  qaoa_mean  depth p=1..3 (warm start), mean-cost objective          -> exact p_best + 100 drawn samples
  qaoa_cvar  same, CVaR alpha=0.10 objective, hard scenarios only (>= 7 qubits)
  random100  100 uniform random decisions
  sa100      simulated annealing with 100 cost evaluations (1 restart)
Success with a budget = the best of the 100 samples is an optimal decision. Never-isolate devices are fixed to 0
before the solver, so every sample passes the safety rule S1 (this is checked, not assumed).
The classical cost of tuning the QAOA angles is NOT counted inside the 100-sample budget.
"""
from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import scipy

from qacrs import safety_checks as S
from qacrs.network import build as build_net, scenarios
from qacrs.phase3_compare import annealing
from qacrs.phase4_qaoa_sim import DEPTHS, RESTARTS, fix_zero, grade, run_qaoa
from qacrs.phase4b_cvar import ALPHA, MIN_QUBITS, tune
from qacrs.qubo_builder import build, decision_from_bits

OUT = Path(__file__).parent / "results" / "v3"
SHOTS = 100


def sample(probs, vals, rng, shots=SHOTS):
    idx = rng.choice(len(probs), size=shots, p=probs / probs.sum())
    best = vals[idx].min()
    return {"best_of_samples": float(best), "hit": bool(np.isclose(best, vals.min())),
            "optimal_samples": int(np.isclose(vals[idx], vals.min()).sum())}, idx


def bits(k, n):
    return [(k >> i) & 1 for i in range(n)]


def run_seed(seed: int) -> dict:
    rows = []
    t_all = time.perf_counter()
    for net in (build_net(1), build_net(2)):
        never = {m.name for m in net.machines if not m.isolatable}
        for j, sc in enumerate(scenarios(net)):
            q = fix_zero(build(net, sc), never)
            row = {"scenario": sc.id, "qubits": q.n}
            if q.n == 0:
                row["note"] = "no decision variable left"; rows.append(row); continue
            rng = np.random.default_rng([seed, j, len(net.machines)])
            vals = q.all_values()
            row["opt"] = float(vals.min()); row["random_p_best"] = float(np.isclose(vals, vals.min()).mean())
            warm = None
            for p in DEPTHS:
                t = time.perf_counter()
                warm, probs, vals = run_qaoa(q, p, warm, seed=seed)
                g = grade(probs, vals)
                row[f"mean_p{p}"] = {"p_best": g["p_best"], "ratio": g["ratio"], "seconds": round(time.perf_counter() - t, 2)}
            s, idx = sample(probs, vals, rng)
            unsafe = sum(S.check(net, sc, decision_from_bits(q, bits(int(k), q.n))).status == S.REJECTED for k in set(idx.tolist()))
            row["qaoa_mean_100"] = s | {"unsafe_samples": unsafe}
            if q.n >= MIN_QUBITS:
                warm = None
                for p in DEPTHS:
                    warm, probs_c, _ = tune(q, p, "cvar", warm, seed=seed)
                    g = grade(probs_c, vals)
                    row[f"cvar_p{p}"] = {"p_best": g["p_best"], "ratio": g["ratio"]}
                row["qaoa_cvar_100"] = sample(probs_c, vals, rng)[0]
            ridx = rng.integers(0, len(vals), SHOTS)
            row["random_100"] = {"hit": bool(np.isclose(vals[ridx].min(), vals.min()))}
            row["sa_100"] = {"hit": bool(np.isclose(annealing(q, steps=SHOTS, restarts=1, seed=1000 * seed + j), vals.min()))}
            rows.append(row)
            print(f"seed {seed} {sc.id:11} {q.n:>2}q  p3 p_best {row['mean_p3']['p_best']:.1%}  "
                  f"100-shot hit qaoa={row['qaoa_mean_100']['hit']} cvar={row.get('qaoa_cvar_100', {}).get('hit', '-')} "
                  f"rand={row['random_100']['hit']} sa100={row['sa_100']['hit']}", flush=True)
    return {"meta": {"experiment": "phase4c_seeds", "version": "v3", "seed": seed, "shots": SHOTS,
                     "depths": list(DEPTHS), "restarts": RESTARTS, "cvar_alpha": ALPHA, "hard_min_qubits": MIN_QUBITS,
                     "python": platform.python_version(), "numpy": np.__version__, "scipy": scipy.__version__,
                     "seconds": round(time.perf_counter() - t_all, 1), "status": "complete",
                     "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            "rows": rows}


def aggregate() -> dict:
    files = sorted((OUT / "qaoa_seeds").glob("seed*.json"))
    runs = [json.loads(f.read_text()) for f in files]
    per_seed = []
    for r in runs:
        rows = [x for x in r["rows"] if x.get("qubits", 0) > 0]
        hard = [x for x in rows if x["qubits"] >= MIN_QUBITS]
        per_seed.append({
            "seed": r["meta"]["seed"], "scenarios": len(rows), "hard": len(hard),
            "mean_p_best_p3": float(np.mean([x["mean_p3"]["p_best"] for x in rows])),
            "random_p_best": float(np.mean([x["random_p_best"] for x in rows])),
            "hits_100": {"qaoa_mean": sum(x["qaoa_mean_100"]["hit"] for x in rows),
                         "random": sum(x["random_100"]["hit"] for x in rows),
                         "sa_100": sum(x["sa_100"]["hit"] for x in rows)},
            "hard_hits_100": {"qaoa_mean": sum(x["qaoa_mean_100"]["hit"] for x in hard),
                              "qaoa_cvar": sum(x["qaoa_cvar_100"]["hit"] for x in hard),
                              "random": sum(x["random_100"]["hit"] for x in hard),
                              "sa_100": sum(x["sa_100"]["hit"] for x in hard)},
            "hard_p_best_p3": {"mean": float(np.mean([x["mean_p3"]["p_best"] for x in hard])),
                               "cvar": float(np.mean([x["cvar_p3"]["p_best"] for x in hard]))},
            "unsafe_samples": sum(x["qaoa_mean_100"]["unsafe_samples"] for x in rows)})

    def stat(get):
        v = [get(s) for s in per_seed]
        return {"median": float(np.median(v)), "min": min(v), "max": max(v)}

    by_q = {}
    for r in runs:
        for x in r["rows"]:
            if x.get("qubits", 0) > 0:
                by_q.setdefault(x["qubits"], []).append(x)
    qubit_table = {str(n): {"runs": len(xs), "scenarios": len(xs) // max(len(runs), 1),
                            "mean_p_best_p3": float(np.mean([x["mean_p3"]["p_best"] for x in xs])),
                            "random_p_best": float(np.mean([x["random_p_best"] for x in xs])),
                            "qaoa_hit_rate_100": float(np.mean([x["qaoa_mean_100"]["hit"] for x in xs])),
                            "sa100_hit_rate": float(np.mean([x["sa_100"]["hit"] for x in xs])),
                            "random_hit_rate_100": float(np.mean([x["random_100"]["hit"] for x in xs]))}
                   for n, xs in sorted(by_q.items())}
    return {"seeds": [s["seed"] for s in per_seed], "per_seed": per_seed,
            "summary": {"mean_p_best_p3": stat(lambda s: s["mean_p_best_p3"]),
                        "hits_100_qaoa_mean": stat(lambda s: s["hits_100"]["qaoa_mean"]),
                        "hits_100_random": stat(lambda s: s["hits_100"]["random"]),
                        "hits_100_sa_100": stat(lambda s: s["hits_100"]["sa_100"]),
                        "hard_hits_100_qaoa_mean": stat(lambda s: s["hard_hits_100"]["qaoa_mean"]),
                        "hard_hits_100_qaoa_cvar": stat(lambda s: s["hard_hits_100"]["qaoa_cvar"]),
                        "hard_hits_100_random": stat(lambda s: s["hard_hits_100"]["random"]),
                        "hard_hits_100_sa_100": stat(lambda s: s["hard_hits_100"]["sa_100"]),
                        "unsafe_samples_total": sum(s["unsafe_samples"] for s in per_seed)},
            "by_qubits": qubit_table,
            "note": "Noiseless simulation. 100 real samples per method. QAOA angle-tuning cost is outside the budget."}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    (OUT / "qaoa_seeds").mkdir(parents=True, exist_ok=True)
    if argv and argv[0] == "--aggregate":
        res = aggregate()
        (OUT / "qaoa_seeds_summary.json").write_text(json.dumps(res, indent=1))
        print(json.dumps(res["summary"], indent=1)); return
    for s in [int(a) for a in argv] or [0]:
        res = run_seed(s)
        (OUT / "qaoa_seeds" / f"seed{s}.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
