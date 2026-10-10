"""E7 (v3): run a REAL hospital decision (pre-registered: net12_h04, 5 qubits) on IBM quantum hardware.

Run on YOUR machine (needs qiskit + qiskit-ibm-runtime and a saved IBM account; no key is ever stored here):

    cd backend
    python -m qacrs.lesson4_ibm_scaled --check          # 1. libraries, account, backends, circuit self-test. NO job.
    python -m qacrs.lesson4_ibm_scaled --dry-run        # 2. transpile for the least busy QPU: depth, 2-qubit gates. NO job.
    python -m qacrs.lesson4_ibm_scaled --run            # 3. ONE job, only after you type 'yes'
    python -m qacrs.lesson4_ibm_scaled --job <JOB_ID>   #    fetch a job that finished later (no new QPU time)
    add  --scenario net12_h01  to use the pre-registered 4-qubit fallback.

Angles are tuned on the noiseless numpy simulator used in Phase 4 (same maths); --check proves that the Qiskit
circuit built here gives the same probabilities before any QPU time is used.
Metric definitions are the same as Lesson 3: p_best = chance ONE measurement is an optimal decision.
Results: qacrs/results/v3/ibm/<scenario>_{check,dryrun,run}.json (raw counts included).
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

from qacrs import escalation as E
from qacrs.ising import to_ising
from qacrs.network import build as build_net, scenarios
from qacrs.phase4_qaoa_sim import fix_zero, qaoa_state, run_qaoa
from qacrs.qubo_builder import build, decision_from_bits

OUT = Path(__file__).parent / "results" / "v3" / "ibm"
P, SHOTS, SEED = 2, 4000, 0
PRIMARY, FALLBACK = "net12_h04", "net12_h01"


def problem(sid: str):
    for net in (build_net(1), build_net(2)):
        for sc in scenarios(net):
            if sc.id == sid:
                never = {m.name for m in net.machines if not m.isolatable}
                return net, sc, fix_zero(build(net, sc), never)
    raise SystemExit(f"unknown scenario {sid}")


def tuned(q):
    warm = None
    for p in range(1, P + 1):                       # same warm-start chain as Phase 4
        warm, probs, vals = run_qaoa(q, p, warm, seed=SEED)
    scale = sum(abs(a) for a in q.lin.values()) + sum(abs(b) for b in q.quad.values()) or 1.0
    return warm, probs, vals, scale


def qiskit_circuit(q, theta, scale):
    from qiskit import QuantumCircuit
    _, h, J = to_ising(0.0, {i: a / scale for i, a in q.lin.items()}, {k: b / scale for k, b in q.quad.items()}, q.n)
    gam, bet = theta[:P], theta[P:]
    qc = QuantumCircuit(q.n)
    qc.h(range(q.n))
    for g, b in zip(gam, bet):
        for i in range(q.n):
            if h[i]:
                qc.rz(2 * g * h[i], i)
        for (i, j), w in J.items():
            qc.rzz(2 * g * w, i, j)
        qc.rx(2 * b, range(q.n))
    return qc


def bits_to_x(bitstring: str):
    return [int(c) for c in bitstring.replace(" ", "")[::-1]]   # IBM prints qubit 0 on the right


def save(name: str, data: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    p.write_text(json.dumps(data | {"saved_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=1))
    print(f"Saved: {p}")
    return p


def report(net, sc, q, vals, ideal, counts, backend, job_id):
    opt = vals.min(); optimal = np.isclose(vals, opt)
    shots = sum(counts.values())
    real = np.zeros(len(vals))
    for b, c in counts.items():
        x = bits_to_x(b); real[sum(v << i for i, v in enumerate(x))] += c / shots
    pool = []                                          # counts lose shot order: draw 100 of the real shots (seeded)
    for b, c in counts.items():
        pool += [b] * c
    rng = np.random.default_rng(SEED)
    pick = rng.choice(len(pool), size=min(100, len(pool)), replace=False)
    best100 = min(vals[sum(v << i for i, v in enumerate(bits_to_x(pool[k])))] for k in pick)
    top = int(np.argmax(real)); top_x = [(top >> i) & 1 for i in range(q.n)]
    decision = decide_names(q, top_x)
    verdict = E.decide(net, sc, decision)
    res = {"scenario": sc.id, "hacked": sc.hacked, "qubits": q.n, "variables": q.names, "p": P, "shots": shots,
           "backend": backend, "job_id": job_id, "best_cost": float(opt),
           "p_best_real": float(real[optimal].sum()), "p_best_ideal": float(ideal[optimal].sum()),
           "p_best_random": float(optimal.mean()),
           "expected_cost_real": float(real @ vals), "expected_cost_ideal": float(ideal @ vals),
           "worst_cost": float(vals.max()), "best_of_100_real_shots_is_optimal": bool(np.isclose(best100, opt)),
           "most_frequent_real_decision": {"isolate": sorted(decision), "cost": float(vals[top]),
                                           "is_optimal": bool(optimal[top]), "safety_gate": verdict.as_dict()},
           "counts": counts}
    print(f"\n{sc.id} on {backend} (job {job_id}), {shots} shots, {q.n} qubits, p={P}")
    print(f"  chance one shot is optimal: real {res['p_best_real']:.1%} | ideal {res['p_best_ideal']:.1%} | "
          f"random {res['p_best_random']:.1%}")
    print(f"  expected cost: real {res['expected_cost_real']:.2f} | ideal {res['expected_cost_ideal']:.2f} | best {opt:.2f}")
    print(f"  most frequent real decision: isolate {sorted(decision) or 'nothing'} -> safety gate: {verdict.status}")
    return res


def decide_names(q, x):
    return decision_from_bits(q, x)


def main(argv=None):
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true"); g.add_argument("--dry-run", action="store_true")
    g.add_argument("--run", action="store_true"); g.add_argument("--job")
    ap.add_argument("--scenario", default=PRIMARY, choices=[PRIMARY, FALLBACK])
    ap.add_argument("--backend", help="QPU name (default: least busy)")
    a = ap.parse_args(argv)

    net, sc, q = problem(a.scenario)
    print(f"Scenario {sc.id}: hacked {sc.hacked}; {q.n} qubits = {q.names}")
    print("Tuning angles on the noiseless simulator ...")
    theta, ideal, vals, scale = tuned(q)
    print(f"  ideal p_best = {ideal[np.isclose(vals, vals.min())].sum():.1%}  (random {np.isclose(vals, vals.min()).mean():.1%})")

    import qiskit
    from qiskit.quantum_info import Statevector
    qc = qiskit_circuit(q, theta, scale)
    sv = Statevector(qc).probabilities()
    diff = float(np.abs(sv - ideal).max())
    print(f"  Qiskit circuit vs numpy simulator: max probability difference {diff:.2e}")
    if diff > 1e-6:
        raise SystemExit("STOP: the Qiskit circuit does not match the simulator. Do not use QPU time; report this.")

    from qiskit_ibm_runtime import QiskitRuntimeService
    service = QiskitRuntimeService()                       # uses the account saved on YOUR machine
    if a.job:
        job = service.job(a.job)
        counts = job.result()[0].data.meas.get_counts()
        res = report(net, sc, q, vals, ideal, counts, job.backend().name, a.job)
        return save(f"{sc.id}_run.json", res | {"theta": list(map(float, theta)), "status": "complete"})

    backend = service.backend(a.backend) if a.backend else service.least_busy(operational=True, simulator=False)
    import qiskit_ibm_runtime
    info = {"scenario": sc.id, "qubits": q.n, "p": P, "qiskit": qiskit.__version__,
            "qiskit_ibm_runtime": qiskit_ibm_runtime.__version__, "backend": backend.name,
            "backend_qubits": backend.num_qubits, "selfcheck_max_diff": diff,
            "ideal_p_best": float(ideal[np.isclose(vals, vals.min())].sum())}
    if a.check:
        print(f"  account OK, least busy QPU: {backend.name} ({backend.num_qubits} qubits). No job sent.")
        return save(f"{sc.id}_check.json", info | {"status": "check_ok"})

    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    qc.measure_all()
    isa = generate_preset_pass_manager(backend=backend, optimization_level=3).run(qc)
    ops = dict(isa.count_ops())
    two_q = sum(v for k, v in ops.items() if k in ("cz", "ecr", "cx"))
    info |= {"isa_depth": isa.depth(), "two_qubit_gates": two_q, "ops": {k: int(v) for k, v in ops.items()}}
    print(f"  on {backend.name}: depth {isa.depth()}, two-qubit gates {two_q}")
    if a.dry_run:
        return save(f"{sc.id}_dryrun.json", info | {"status": "dry_run_no_job"})

    if input(f"Send ONE job to the REAL quantum computer {backend.name} ({SHOTS} shots)? type 'yes': ").strip() != "yes":
        return print("Not sent.")
    from qiskit_ibm_runtime import SamplerV2 as Sampler
    job = Sampler(mode=backend).run([isa], shots=SHOTS)
    save(f"{sc.id}_pending.json", info | {"job_id": job.job_id(), "status": "submitted"})
    print(f"Sent. Job id {job.job_id()}. If you stop waiting, later run: --job {job.job_id()}")
    counts = job.result()[0].data.meas.get_counts()
    res = report(net, sc, q, vals, ideal, counts, backend.name, job.job_id())
    save(f"{sc.id}_run.json", info | res | {"theta": list(map(float, theta)), "status": "complete"})


if __name__ == "__main__":
    main()
