"""Lesson 2: solve the Lesson-1 decision with QAOA on a quantum simulator (Qiskit).   Run on your laptop:

    source ~/qenv/bin/activate
    cd ~/ACRS/backend && python -m qacrs.lesson2_qaoa

Builds the QAOA circuit by hand (so you can see every gate), tunes its angles on a noiseless simulator, then
reports how often a measurement gives the best decision found by brute force in Lesson 1.
"""
import numpy as np
from scipy.optimize import minimize
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from qacrs.ising import brute_force, qubo_value, to_ising
from qacrs.lesson1_qubo import DISRUPTION, LEFTOVER_RISK, SITE_DOWN

N = 3
CONST = sum(LEFTOVER_RISK)
LIN = {i: DISRUPTION[i] - LEFTOVER_RISK[i] for i in range(N)}
QUAD = {(0, 1): SITE_DOWN}


def circuit(gammas, betas, h, J):
    qc = QuantumCircuit(N)
    qc.h(range(N))                                   # start in every decision at once
    for g, b in zip(gammas, betas):
        for i in range(N):
            if h[i]: qc.rz(2 * g * h[i], i)          # cost of each single decision
        for (i, j), w in J.items():
            qc.rzz(2 * g * w, i, j)                  # cost of the pair (the twins)
        qc.rx(2 * b, range(N))                       # mixer: lets the state explore
    return qc


def probs(qc):
    d = Statevector(qc).probabilities_dict()
    return {tuple(int(c) for c in k[::-1]): p for k, p in d.items()}   # qubit 0 first


def main(p=2, restarts=8, seed=7):
    c, h, J = to_ising(CONST, LIN, QUAD, N)
    best_val, best_xs = brute_force(CONST, LIN, QUAD, N)
    rng = np.random.default_rng(seed)

    def expected_cost(theta):
        pr = probs(circuit(theta[:p], theta[p:], h, J))
        return sum(pv * qubo_value(CONST, LIN, QUAD, x) for x, pv in pr.items())

    run = min((minimize(expected_cost, rng.uniform(0, np.pi, 2 * p), method="COBYLA") for _ in range(restarts)),
              key=lambda r: r.fun)
    pr = probs(circuit(run.x[:p], run.x[p:], h, J))
    hit = sum(pv for x, pv in pr.items() if x in best_xs)
    top = max(pr, key=pr.get)
    print(f"QAOA depth p={p}")
    print(f"Best decision (brute force): {best_xs}  cost {best_val}")
    print(f"Most likely QAOA answer:     {top}  cost {qubo_value(CONST, LIN, QUAD, top)}")
    print(f"Chance one measurement is a best decision: {hit:.1%}   (random guessing: {len(best_xs)/2**N:.1%})")
    print(f"Expected cost under QAOA: {run.fun:.2f}   (best {best_val}, worst {max(qubo_value(CONST, LIN, QUAD, x) for x in pr)})")


if __name__ == "__main__":
    main()
