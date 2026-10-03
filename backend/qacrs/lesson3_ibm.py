"""Lesson 3: run the Lesson-2 QAOA decision on a REAL IBM quantum computer.

    source ~/qenv/bin/activate
    cd ~/ACRS/backend && python -m qacrs.lesson3_ibm              # tune, then send one job (asks first)
    cd ~/ACRS/backend && python -m qacrs.lesson3_ibm --job <ID>   # fetch a job that finished later

What happens:
  1. Tune the QAOA angles on the noiseless simulator (same as Lesson 2).
  2. Send the tuned circuit to the least busy real IBM QPU, measured SHOTS times.
  3. Compare: real hardware vs ideal simulator vs random guessing.
  4. Safety layer: the most frequent real answer is checked classically before it would be executed.
Uses a few seconds of the 10 free minutes. Results are saved in qacrs/results/lesson3_ibm.json.
"""
import argparse
import json
import time
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from qacrs.ising import brute_force, qubo_value, to_ising
from qacrs.lesson2_qaoa import CONST, LIN, N, QUAD, circuit, probs

OUT = Path(__file__).parent / "results" / "lesson3_ibm.json"
P, SHOTS = 2, 4000
NAMES = ["A (web twin 1)", "B (web twin 2)", "C (office PC)"]


def tune(p=P, restarts=8, seed=7):
    _, h, J = to_ising(CONST, LIN, QUAD, N)
    rng = np.random.default_rng(seed)
    def expected_cost(theta):
        pr = probs(circuit(theta[:p], theta[p:], h, J))
        return sum(pv * qubo_value(CONST, LIN, QUAD, x) for x, pv in pr.items())
    run = min((minimize(expected_cost, rng.uniform(0, np.pi, 2 * p), method="COBYLA") for _ in range(restarts)),
              key=lambda r: r.fun)
    return run.x, h, J


def to_x(bits: str):
    return tuple(int(c) for c in bits[::-1])          # IBM prints qubit 0 on the right


def report(counts: dict, ideal: dict, backend: str, job_id: str):
    best_val, best_xs = brute_force(CONST, LIN, QUAD, N)
    shots = sum(counts.values())
    real = {to_x(b): c / shots for b, c in counts.items()}
    hit_real = sum(p for x, p in real.items() if x in best_xs)
    hit_ideal = sum(p for x, p in ideal.items() if x in best_xs)
    exp_real = sum(p * qubo_value(CONST, LIN, QUAD, x) for x, p in real.items())
    top = max(real, key=real.get)
    safe = qubo_value(CONST, LIN, QUAD, top) == best_val     # classical check before execution

    print(f"\nQPU: {backend}   job: {job_id}   shots: {shots}")
    print(f"Best decision (brute force): {best_xs}  cost {best_val}\n")
    print(f"{'decision (A,B,C)':18}{'cost':>6}{'real QPU':>11}{'ideal sim':>11}")
    for x in sorted(set(real) | set(ideal), key=lambda x: -real.get(x, 0)):
        mark = "  <- best" if x in best_xs else ""
        print(f"{str(x):18}{qubo_value(CONST, LIN, QUAD, x):>6}{real.get(x, 0):>11.1%}{ideal.get(x, 0):>11.1%}{mark}")
    print(f"\nChance one measurement is a best decision:")
    print(f"  real quantum computer : {hit_real:.1%}")
    print(f"  ideal simulator       : {hit_ideal:.1%}")
    print(f"  random guessing       : {len(best_xs) / 2 ** N:.1%}")
    print(f"Expected cost on real QPU: {exp_real:.2f}   (best {best_val})")
    print(f"\nMost frequent real answer: {top} -> " +
          ", ".join(f"{n}: {'isolate' if v else 'restrict only'}" for n, v in zip(NAMES, top)))
    print(f"Safety check (classical): {'PASS - would be executed' if safe else 'FAIL - rejected, fall back to classical'}")

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({
        "backend": backend, "job_id": job_id, "shots": shots, "p": P,
        "best_decisions": [list(x) for x in best_xs], "best_cost": best_val,
        "hit_real": round(hit_real, 4), "hit_ideal": round(hit_ideal, 4), "hit_random": len(best_xs) / 2 ** N,
        "expected_cost_real": round(exp_real, 3), "top_real": list(top), "safety_check_pass": safe,
        "counts": counts, "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=1))
    print(f"Saved: {OUT.relative_to(Path.cwd()) if OUT.is_relative_to(Path.cwd()) else OUT}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", help="fetch the result of an earlier job id")
    args = ap.parse_args()

    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    service = QiskitRuntimeService()

    print("Tuning QAOA angles on the simulator ...")
    theta, h, J = tune()
    qc = circuit(theta[:P], theta[P:], h, J)
    ideal = probs(qc)

    if args.job:
        job = service.job(args.job)
        print(f"Job status: {job.status()}")
        counts = job.result()[0].data.meas.get_counts()
        return report(counts, ideal, job.backend().name, args.job)

    backend = service.least_busy(operational=True, simulator=False)
    qc.measure_all()
    isa = generate_preset_pass_manager(backend=backend, optimization_level=3).run(qc)
    print(f"Least busy QPU: {backend.name}  ({backend.num_qubits} qubits)")
    print(f"Circuit on the chip: {isa.depth()} layers, {isa.count_ops().get('cz', 0)} two-qubit gates")
    if input(f"Send to the REAL quantum computer ({SHOTS} shots, a few seconds of your 10 min)? [y/N] ").lower() != "y":
        return print("Not sent.")
    job = Sampler(mode=backend).run([isa], shots=SHOTS)
    print(f"Sent. Job id: {job.job_id()}")
    print("Waiting in the queue ... (you can Ctrl+C and later run:  python -m qacrs.lesson3_ibm --job " + job.job_id() + ")")
    counts = job.result()[0].data.meas.get_counts()
    report(counts, ideal, backend.name, job.job_id())


if __name__ == "__main__":
    main()
