"""Phase 5 / E3: scaling study, 1-5 departments (12-52 machines), 15 random scenarios each (seed 2027).

    cd backend && python -m qacrs.phase5_scaling      -> results/v3/scaling.json + scaling.csv

Rules: docs/qacrs/PREREGISTRATION_v3.md (E3). Exact brute force only when qubits <= 20.
QAOA size is the LOGICAL circuit per layer (before routing on real hardware): n RX gates and one ZZ term per
quadratic QUBO term; two-qubit gates = 2 * |quad| * p (CNOT-RZ-CNOT). Hardware depth after routing is not estimated.
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

import numpy as np

from qacrs.meta import meta
from qacrs.network import build as build_net, check, random_scenarios
from qacrs.phase3_compare import annealing
from qacrs.phase4_qaoa_sim import fix_zero
from qacrs.qubo_builder import build

OUT = Path(__file__).parent / "results" / "v3"
DEPTS, N_SC, SEED, EXACT_MAX, P = (1, 2, 3, 4, 5), 15, 2027, 20, 3


def main():
    rows = []
    for d in DEPTS:
        net = build_net(d); check(net)
        never = {m.name for m in net.machines if not m.isolatable}
        for sc in random_scenarios(net, N_SC, SEED):
            t = time.perf_counter()
            full = build(net, sc)
            q = fix_zero(full, never)
            t_build = time.perf_counter() - t
            row = {"departments": d, "machines": len(net.machines), "scenario": sc.id, "hacked": len(sc.hacked),
                   "variables_after_reduction": full.n, "never_isolate_removed": full.n - q.n, "qubits": q.n,
                   "linear_terms": len(q.lin), "quadratic_terms": len(q.quad), "build_ms": round(1000 * t_build, 3),
                   "qaoa_layer_rx": q.n, "qaoa_layer_zz": len(q.quad), "qaoa_two_qubit_gates_p3": 2 * len(q.quad) * P}
            if q.n == 0:
                row.update(exact_ms=0.0, sa_ms=0.0, sa_matches_exact=True); rows.append(row); continue
            t = time.perf_counter(); sa = annealing(q); row["sa_ms"] = round(1000 * (time.perf_counter() - t), 1)
            if q.n <= EXACT_MAX:
                t = time.perf_counter(); ex = float(q.all_values().min())
                row["exact_ms"] = round(1000 * (time.perf_counter() - t), 1)
                row["sa_matches_exact"] = bool(abs(sa - ex) < 1e-9)
            else:
                row["exact_ms"] = None; row["sa_matches_exact"] = None
            rows.append(row)
        r = [x for x in rows if x["departments"] == d]
        print(f"{d} dept  {len(net.machines):>3} machines  qubits mean {np.mean([x['qubits'] for x in r]):.1f} "
              f"max {max(x['qubits'] for x in r)}  SA=exact {sum(bool(x['sa_matches_exact']) for x in r)}/{len(r)}", flush=True)
    by = {}
    for d in DEPTS:
        r = [x for x in rows if x["departments"] == d]
        ex = [x["exact_ms"] for x in r if x["exact_ms"] is not None]
        by[str(d)] = {"machines": r[0]["machines"], "scenarios": len(r),
                      "qubits_mean": float(np.mean([x["qubits"] for x in r])), "qubits_max": max(x["qubits"] for x in r),
                      "quadratic_terms_mean": float(np.mean([x["quadratic_terms"] for x in r])),
                      "two_qubit_gates_p3_mean": float(np.mean([x["qaoa_two_qubit_gates_p3"] for x in r])),
                      "exact_ms_median": float(np.median(ex)) if ex else None,
                      "sa_ms_median": float(np.median([x["sa_ms"] for x in r])),
                      "sa_matches_exact": sum(bool(x["sa_matches_exact"]) for x in r),
                      "exact_available": len(ex)}
    res = {"meta": meta("phase5_scaling", ("phase5_scaling.py",), departments=DEPTS, scenarios_per_network=N_SC,
                        seed=SEED, exact_max_qubits=EXACT_MAX, qaoa_p=P), "by_departments": by, "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "scaling.json").write_text(json.dumps(res, indent=1))
    with (OUT / "scaling.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(json.dumps(by, indent=1))


if __name__ == "__main__":
    main()
