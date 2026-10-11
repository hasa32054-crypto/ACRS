"""E8: second IBM hardware run — corrected angle range, p = 2 and p = 3 in ONE job, error suppression.
Rules: docs/qacrs/PREREGISTRATION_E8.md. Run on YOUR machine (saved IBM account; no key in the repo):

    cd backend
    python -m qacrs.lesson5_ibm_tuned --check        # tune, self-check vs simulator, account. NO job.
    python -m qacrs.lesson5_ibm_tuned --dry-run      # transpile both circuits: depth, two-qubit gates. NO job.
    python -m qacrs.lesson5_ibm_tuned --run          # ONE job (two circuits), only after you type 'yes'
    python -m qacrs.lesson5_ibm_tuned --job <JOB_ID> # fetch a finished job (no new QPU time)

Results: qacrs/results/v3/ibm/e8_{check,dryrun,pending,run}.json (raw counts included).
"""
from __future__ import annotations

import argparse
import json

import numpy as np
from scipy.optimize import minimize

from qacrs.lesson4_ibm_scaled import PRIMARY, problem, report, save
from qacrs.ising import to_ising
from qacrs.phase4_qaoa_sim import qaoa_state

DEPTHS, PRIMARY_P = (2, 3), 2
GAMMA_MAX, RESTARTS, SEED, SHOTS = 40.0, 30, 0, 4000


def scale_of(q):
    return sum(abs(a) for a in q.lin.values()) + sum(abs(b) for b in q.quad.values()) or 1.0


def tune(q, p):
    vals = q.all_values()
    cost = (vals - q.const) / scale_of(q)
    rng = np.random.default_rng(SEED)
    f = lambda t: float(qaoa_state(cost, q.n, t[:p], t[p:]) @ cost)
    best = None
    for _ in range(RESTARTS):
        s = np.concatenate([rng.uniform(0, GAMMA_MAX, p), rng.uniform(0, np.pi, p)])
        r = minimize(f, s, method="COBYLA", options={"maxiter": 600})
        if best is None or r.fun < best.fun:
            best = r
    return best.x, qaoa_state(cost, q.n, best.x[:p], best.x[p:]), vals


def circuit(q, theta, p):
    from qiskit import QuantumCircuit
    s = scale_of(q)
    _, h, J = to_ising(0.0, {i: a / s for i, a in q.lin.items()}, {k: b / s for k, b in q.quad.items()}, q.n)
    qc = QuantumCircuit(q.n)
    qc.h(range(q.n))
    for g, b in zip(theta[:p], theta[p:]):
        for i in range(q.n):
            if h[i]:
                qc.rz(2 * g * h[i], i)
        for (i, j), w in J.items():
            qc.rzz(2 * g * w, i, j)
        qc.rx(2 * b, range(q.n))
    return qc


def make_sampler(backend):
    from qiskit_ibm_runtime import SamplerV2 as Sampler
    sampler = Sampler(mode=backend)
    applied = {}
    for path, val in (("dynamical_decoupling.enable", True), ("dynamical_decoupling.sequence_type", "XpXm"),
                      ("twirling.enable_gates", True), ("twirling.enable_measure", True),
                      ("twirling.num_randomizations", "auto")):
        obj, *rest = path.split(".")
        try:
            setattr(getattr(sampler.options, obj), rest[0], val); applied[path] = val
        except Exception as e:                                    # report, never hide
            applied[path] = f"not applied: {type(e).__name__}"
    return sampler, applied


def main(argv=None):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true"); g.add_argument("--dry-run", action="store_true")
    g.add_argument("--run", action="store_true"); g.add_argument("--job")
    ap.add_argument("--backend", help="QPU name (default: least busy)")
    a = ap.parse_args(argv)

    net, sc, q = problem(PRIMARY)
    print(f"Scenario {sc.id}: hacked {sc.hacked}; {q.n} qubits = {q.names}")
    import qiskit
    from qiskit.quantum_info import Statevector
    tuned, circs, diffs = {}, {}, {}
    for p in DEPTHS:
        print(f"Tuning p={p} on the noiseless simulator (gamma in [0, {GAMMA_MAX}], {RESTARTS} restarts) ...")
        theta, ideal, vals = tune(q, p)
        opt = np.isclose(vals, vals.min())
        qc = circuit(q, theta, p)
        diffs[p] = float(np.abs(Statevector(qc).probabilities() - ideal).max())
        print(f"  p={p}: ideal p_best {ideal[opt].sum():.1%} (random {opt.mean():.1%}); Qiskit vs simulator diff {diffs[p]:.1e}")
        if diffs[p] > 1e-9:
            raise SystemExit("STOP: Qiskit circuit does not match the simulator. Do not use QPU time; send this output.")
        tuned[p] = (theta, ideal, vals); circs[p] = qc

    from qiskit_ibm_runtime import QiskitRuntimeService
    import qiskit_ibm_runtime
    service = QiskitRuntimeService()

    def finish(job, backend_name, info):
        res = job.result()
        out = {}
        for k, p in enumerate(DEPTHS):
            counts = res[k].data.meas.get_counts()
            theta, ideal, vals = tuned[p]
            out[f"p{p}"] = report(net, sc, q, vals, ideal, counts, backend_name, job.job_id()) | {
                "p": p, "theta": list(map(float, theta))}
        e7 = 477 / 4000; r = out[f"p{PRIMARY_P}"]
        k3 = round(r["p_best_real"] * r["shots"]); n3 = r["shots"]
        from scipy.stats import binomtest, norm
        pp = (k3 + 477) / (n3 + 4000); se = (pp * (1 - pp) * (1 / n3 + 1 / 4000)) ** 0.5
        z = (k3 / n3 - e7) / se if se else 0.0
        tests = {"H_E8a_vs_E7": {"z": z, "p_one_sided": float(1 - norm.cdf(z)), "supported": bool(1 - norm.cdf(z) < 0.05)},
                 "H_E8b_vs_random": {"p_one_sided": float(binomtest(k3, n3, r["p_best_random"], alternative="greater").pvalue)}}
        tests["H_E8b_vs_random"]["supported"] = tests["H_E8b_vs_random"]["p_one_sided"] < 0.05
        print(f"\nE8 primary p={PRIMARY_P}: real {r['p_best_real']:.1%} vs E7 11.9% (p={tests['H_E8a_vs_E7']['p_one_sided']:.2g}); "
              f"p=2 real {out['p2']['p_best_real']:.1%}")
        save("e8_run.json", info | {"results": out, "tests": tests, "status": "complete"})

    if a.job:
        job = service.job(a.job)
        return finish(job, job.backend().name, {"job_id": a.job})

    backend = service.backend(a.backend) if a.backend else service.least_busy(operational=True, simulator=False)
    info = {"experiment": "E8", "scenario": sc.id, "qubits": q.n, "depths": list(DEPTHS), "primary_p": PRIMARY_P,
            "gamma_max": GAMMA_MAX, "restarts": RESTARTS, "qiskit": qiskit.__version__,
            "qiskit_ibm_runtime": qiskit_ibm_runtime.__version__, "backend": backend.name,
            "selfcheck_max_diff": diffs, "ideal_p_best": {p: float(tuned[p][1][np.isclose(tuned[p][2], tuned[p][2].min())].sum()) for p in DEPTHS}}
    if a.check:
        print(f"  account OK, QPU: {backend.name} ({backend.num_qubits} qubits). No job sent.")
        return save("e8_check.json", info | {"status": "check_ok"})

    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    pm = generate_preset_pass_manager(backend=backend, optimization_level=3)
    isas, shape = [], {}
    for p in DEPTHS:
        qc = circs[p].copy(); qc.measure_all()
        isa = pm.run(qc); isas.append(isa)
        ops = dict(isa.count_ops())
        shape[p] = {"depth": isa.depth(), "two_qubit_gates": sum(v for k, v in ops.items() if k in ("cz", "ecr", "cx"))}
        print(f"  p={p} on {backend.name}: depth {shape[p]['depth']}, two-qubit gates {shape[p]['two_qubit_gates']}")
    info["transpiled"] = shape
    if a.dry_run:
        return save("e8_dryrun.json", info | {"status": "dry_run_no_job"})

    if input(f"Send ONE job ({len(DEPTHS)} circuits x {SHOTS} shots) to the REAL quantum computer {backend.name}? type 'yes': ").strip() != "yes":
        return print("Not sent.")
    sampler, applied = make_sampler(backend)
    print(f"  error suppression: {applied}")
    job = sampler.run(isas, shots=SHOTS)
    info |= {"job_id": job.job_id(), "error_suppression": applied}
    save("e8_pending.json", info | {"status": "submitted"})
    print(f"Sent. Job id {job.job_id()}. If you stop waiting, later run: --job {job.job_id()}")
    finish(job, backend.name, info)


if __name__ == "__main__":
    main()
