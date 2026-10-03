"""QUBO <-> Ising conversion (pure Python, shared by every Q-ACRS script).

QUBO:  f(x) = const + sum_i a_i x_i + sum_{i<j} b_ij x_i x_j        x_i in {0,1}
Ising: E(z) = c     + sum_i h_i z_i + sum_{i<j} J_ij z_i z_j        z_i in {+1,-1},  x_i = (1 - z_i) / 2
A measured qubit 0 means z=+1 means x=0, so the measured bit string IS the decision vector x.
"""
from itertools import product


def qubo_value(const, lin, quad, x):
    return const + sum(a * x[i] for i, a in lin.items()) + sum(b * x[i] * x[j] for (i, j), b in quad.items())


def to_ising(const, lin, quad, n):
    h = [0.0] * n; J = {}; c = float(const)
    for i, a in lin.items():                      # a x = a/2 - (a/2) z
        c += a / 2; h[i] -= a / 2
    for (i, j), b in quad.items():                # b x_i x_j = b/4 (1 - z_i - z_j + z_i z_j)
        c += b / 4; h[i] -= b / 4; h[j] -= b / 4; J[(i, j)] = J.get((i, j), 0.0) + b / 4
    return c, h, J


def brute_force(const, lin, quad, n):
    best = None
    for x in product([0, 1], repeat=n):
        v = qubo_value(const, lin, quad, x)
        if best is None or v < best[0] - 1e-12:
            best = (v, [x])
        elif abs(v - best[0]) <= 1e-12:
            best[1].append(x)
    return best   # (best value, list of optimal x)
