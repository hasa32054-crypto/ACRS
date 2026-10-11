"""E9: the whole 4-hospital incident decision on ONE IBM quantum job. Rules: docs/qacrs/PREREGISTRATION_E9.md.
Run on YOUR machine (saved IBM account; no key in the repo). The design (angles) is fixed in e9_design.json.

    cd backend
    python -m qacrs.lesson6_ibm_scale --check              # rebuild + hash-check the problem, self-check circuits. NO job.
    python -m qacrs.lesson6_ibm_scale --dry-run            # transpile the packed circuit: qubits, depth, 2-qubit gates. NO job.
    python -m qacrs.lesson6_ibm_scale --run                # ONE job, only after you type 'yes'
    python -m qacrs.lesson6_ibm_scale --run --backend ibm_kingston --tag rep   # optional replication on a 2nd QPU
    python -m qacrs.lesson6_ibm_scale --job <JOB_ID> [--tag rep]               # fetch a finished job (no QPU time)
"""
from __future__ import annotations

import argparse
import json
import time

import numpy as np

from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import quantum_scale as QS
from qacrs import safety_checks as S
from qacrs.ising import to_ising
from qacrs.phase4_qaoa_sim import qaoa_state

SHOTS = 10_000


def save(name, data):
    QS.OUT.mkdir(parents=True, exist_ok=True)
    p = QS.OUT / name
    p.write_text(json.dumps(data | {"saved_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1))
    print(f"Saved: {p}")


def load_problem():
    d = json.loads((QS.OUT / "e9_design.json").read_text())
    net = QS.cluster(); sc = QS.incident(net)
    qt, q = QS.tight_qubo(net, sc)
    if QS.qubo_hash(qt) != d["qubo_hash"]:
        raise SystemExit("STOP: the rebuilt problem differs from the committed design. Send this output.")
    comps = QS.components(qt)
    for (idx, cq), row in zip(comps, d["components"]):
        if QS.qubo_hash(cq) != row["hash"]:
            raise SystemExit("STOP: component mismatch with the design. Send this output.")
    return d, net, sc, qt, q, comps


def add_qaoa(qc, cq, theta, p, offset):
    s = QS.scale_of(cq)
    _, h, J = to_ising(0.0, {i: a / s for i, a in cq.lin.items()}, {k: b / s for k, b in cq.quad.items()}, cq.n)
    qs = [offset + i for i in range(cq.n)]
    qc.h(qs)
    for g, b in zip(theta[:p], theta[p:]):
        for i in range(cq.n):
            if h[i]:
                qc.rz(2 * g * h[i], qs[i])
        for (i, j), w in J.items():
            qc.rzz(2 * g * w, qs[i], qs[j])
        qc.rx(2 * b, qs)


def build_circuit(d, comps):
    from qiskit import QuantumCircuit
    layout, off = [], 0
    for (idx, cq), row in zip(comps, d["components"]):
        if row["mode"] == "qpu":
            layout.append((off, idx, cq, row)); off += cq.n
    qc = QuantumCircuit(off)
    for o, idx, cq, row in layout:
        add_qaoa(qc, cq, row["theta"], row["p"], o)
    return qc, layout


def self_check(layout):
    from qiskit import QuantumCircuit
    from qiskit.quantum_info import Statevector
    worst = 0.0
    for _, idx, cq, row in layout:
        qc = QuantumCircuit(cq.n); add_qaoa(qc, cq, row["theta"], row["p"], 0)
        _, cost = QS.norm_cost(cq)
        ideal = qaoa_state(cost, cq.n, row["theta"][:row["p"]], row["theta"][row["p"]:])
        worst = max(worst, float(np.abs(Statevector(qc).probabilities() - ideal).max()))
    return worst


def analyse(d, net, sc, qt, q, comps, layout, counts, backend, job_id):
    from scipy.stats import binomtest
    shots = sum(counts.values())
    per, x = [], [0] * qt.n
    for (idx, cq), row in zip(comps, d["components"]):
        if row["mode"] == "classical_singleton":
            x[idx[0]] = row["x"][0]
    all_opt_shots = 0
    comp_hits = {id(cq): 0 for _, _, cq, _ in layout}
    best = {id(cq): (np.inf, None) for _, _, cq, _ in layout}
    for bitstr, c in counts.items():
        bits = bitstr.replace(" ", "")[::-1]
        all_ok = True
        for o, idx, cq, row in layout:
            xs = [int(b) for b in bits[o:o + cq.n]]
            v = cq.value(xs)
            if abs(v - row["opt_value"]) < 1e-6:
                comp_hits[id(cq)] += c
            else:
                all_ok = False
            if v < best[id(cq)][0]:
                best[id(cq)] = (v, xs)
        all_opt_shots += c * all_ok
    pvals = []
    for o, idx, cq, row in layout:
        k = comp_hits[id(cq)]; rand = row["n_optima"] / 2 ** cq.n
        pv = float(binomtest(k, shots, rand, alternative="greater").pvalue)
        bv, bx = best[id(cq)]
        qpu_found = abs(bv - row["opt_value"]) < 1e-6
        if not qpu_found:                                          # classical fallback, counted as a QPU miss
            bv, bx = QS.exact_milp(cq)
        for loc, g in enumerate(idx):
            x[g] = bx[loc]
        per.append({"n": cq.n, "p": row["p"], "real_p_opt": k / shots, "ideal_p_opt": row["ideal_p_opt"],
                    "random_p_opt": rand, "real_over_random": (k / shots) / rand, "p_value_vs_random": pv,
                    "qpu_best_is_optimal": qpu_found, "vars": [qt.names[g] for g in idx]})
        pvals.append(pv)
    order = np.argsort(pvals); m = len(pvals); holm = [False] * m; running = True
    for r, i in enumerate(order):
        running = running and pvals[i] <= 0.05 / (m - r); holm[i] = running
    for i, row in enumerate(per):
        row["holm_significant"] = bool(holm[i])
    on = {qt.names[i] for i, v in enumerate(x) if v}
    iso = {n for n in on if not n.endswith(V7.SEG)}
    seg = {n[:-len(V7.SEG)] for n in on if n.endswith(V7.SEG)}
    milp_opt = QS.exact_milp(q)[0]
    value = V7.build_v7(net, sc).value([1 if (n in iso or (n.endswith(V7.SEG) and n[:-len(V7.SEG)] in seg)) else 0
                                         for n in V7.build_v7(net, sc).names])
    verdict = V7.decide_v7(net, sc, iso, seg)
    cert = V9.certificate_v9(net, sc, iso, seg)
    qpu_vars = sum(r["n"] for r in per)
    found = sum(r["n"] for r in per if r["qpu_best_is_optimal"])
    return {"backend": backend, "job_id": job_id, "shots": shots, "components": per,
            "summary": {"qpu_components": len(per), "qpu_components_optimal": sum(r["qpu_best_is_optimal"] for r in per),
                        "qpu_qubits": qpu_vars, "qpu_qubits_in_optimal_components": found,
                        "classical_singletons": sum(1 for r in d["components"] if r["mode"] == "classical_singleton"),
                        "H_E9a_all_components_beat_random_holm": all(r["holm_significant"] for r in per),
                        "H_E9b_share_optimal": sum(r["qpu_best_is_optimal"] for r in per) / len(per),
                        "H_E9b_supported": sum(r["qpu_best_is_optimal"] for r in per) / len(per) >= 0.75,
                        "single_shot_all_components_optimal": all_opt_shots / shots,
                        "assembled_value": float(value), "milp_optimum": float(milp_opt),
                        "assembled_equals_optimum": abs(value - milp_opt) < 1e-6,
                        "safety_gate_status": verdict.status, "unsafe": verdict.status == S.REJECTED,
                        "certificate_verified": V9.verify_certificate_v9(net, sc, cert),
                        "isolate": sorted(iso), "segment": sorted(seg)},
            "counts": counts}


def main(argv=None):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true"); g.add_argument("--dry-run", action="store_true")
    g.add_argument("--run", action="store_true"); g.add_argument("--job")
    ap.add_argument("--backend"); ap.add_argument("--tag", default="")
    a = ap.parse_args(argv)
    tag = f"_{a.tag}" if a.tag else ""

    d, net, sc, qt, q, comps = load_problem()
    print(f"{d['network']}: {d['machines']} machines, {d['hacked']} compromised; decision variables {d['vars_tight']} "
          f"(tight QUBO == original by MILP: {d['tight_equivalent']})")
    qc, layout = build_circuit(d, comps)
    print(f"  packed circuit: {qc.num_qubits} qubits in {len(layout)} independent sub-problems; "
          f"{d['vars_tight'] - qc.num_qubits} single-variable choices decided classically")
    diff = self_check(layout)
    print(f"  Qiskit vs numpy simulator, every sub-problem: max probability difference {diff:.1e}")
    if diff > 1e-9:
        raise SystemExit("STOP: circuit does not match the simulator. Do not use QPU time; send this output.")

    from qiskit_ibm_runtime import QiskitRuntimeService
    service = QiskitRuntimeService()
    if a.job:
        job = service.job(a.job)
        counts = job.result()[0].data.meas.get_counts()
        res = analyse(d, net, sc, qt, q, comps, layout, counts, job.backend().name, a.job)
        return finish(res, tag)

    backend = service.backend(a.backend) if a.backend else service.least_busy(operational=True, simulator=False)
    info = {"experiment": "E9", "backend": backend.name, "backend_qubits": backend.num_qubits, "packed_qubits": qc.num_qubits,
            "selfcheck_max_diff": diff}
    if a.check:
        print(f"  account OK, QPU: {backend.name} ({backend.num_qubits} qubits). No job sent.")
        return save(f"e9_check{tag}.json", info | {"status": "check_ok"})
    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    qc.measure_all()
    isa = generate_preset_pass_manager(backend=backend, optimization_level=3).run(qc)
    ops = dict(isa.count_ops())
    info |= {"isa_depth": isa.depth(), "two_qubit_gates": sum(v for k, v in ops.items() if k in ("cz", "ecr", "cx"))}
    print(f"  on {backend.name}: depth {info['isa_depth']}, two-qubit gates {info['two_qubit_gates']}")
    if a.dry_run:
        return save(f"e9_dryrun{tag}.json", info | {"status": "dry_run_no_job"})
    if input(f"Send ONE job ({SHOTS} shots, {qc.num_qubits} qubits) to {backend.name}? type 'yes': ").strip() != "yes":
        return print("Not sent.")
    from qiskit_ibm_runtime import SamplerV2 as Sampler
    sampler = Sampler(mode=backend)
    applied = {}
    for obj, key, val in (("dynamical_decoupling", "enable", True), ("dynamical_decoupling", "sequence_type", "XpXm"),
                          ("twirling", "enable_gates", True), ("twirling", "enable_measure", True),
                          ("twirling", "num_randomizations", "auto")):
        try:
            setattr(getattr(sampler.options, obj), key, val); applied[f"{obj}.{key}"] = val
        except Exception as e:
            applied[f"{obj}.{key}"] = f"not applied: {type(e).__name__}"
    job = sampler.run([isa], shots=SHOTS)
    save(f"e9_pending{tag}.json", info | {"job_id": job.job_id(), "error_suppression": applied, "status": "submitted"})
    print(f"Sent. Job id {job.job_id()}. If you stop waiting, later run: --job {job.job_id()}" + (f" --tag {a.tag}" if a.tag else ""))
    counts = job.result()[0].data.meas.get_counts()
    finish(info | {"error_suppression": applied} | analyse(d, net, sc, qt, q, comps, layout, counts, backend.name, job.job_id()), tag)


def finish(res, tag):
    s = res["summary"]
    print(f"\nE9 on {res['backend']} (job {res['job_id']}), {res['shots']} shots")
    for r in res["components"]:
        print(f"  {r['n']:>2} qubits p={r['p']}: real {r['real_p_opt']:.2%} | ideal {r['ideal_p_opt']:.2%} | "
              f"random {r['random_p_opt']:.3%} | x{r['real_over_random']:.0f} | QPU best optimal: {r['qpu_best_is_optimal']}")
    print(f"  components solved optimally by the QPU: {s['qpu_components_optimal']}/{s['qpu_components']} "
          f"({s['qpu_qubits_in_optimal_components']}/{s['qpu_qubits']} qubits)")
    print(f"  assembled decision = exact optimum: {s['assembled_equals_optimum']}; safety gate: {s['safety_gate_status']}; "
          f"certificate verified: {s['certificate_verified']}")
    save(f"e9_run{tag}.json", res | {"status": "complete"})


if __name__ == "__main__":
    main()
