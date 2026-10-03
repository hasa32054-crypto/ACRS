"""Phase 3: turn ANY network + attack scenario into a QUBO, and verify a decision before it is executed.

Decision x_i = 1 isolate machine i, x_i = 0 restrict only (cut the attacker's channel, keep it working).

Cost (lower is better) = sum of these terms, each written as const / linear / quadratic in x:
  1. leftover risk   r_i * (1 - x_i)                 hacked machine left running (restricted) keeps some risk
  2. spread risk     SPREAD * r_i * (1 - x_i)(1 - x_j)  hacked i can still reach critical j, neither isolated
  3. disruption      d_i * x_i                        isolating a machine costs its users a tool
  4. service down    V * x_a * x_b                    both twins of a service isolated  -> service down
                     V * x_a                          the only replica, or a machine the service depends on
  5. hard rule       BIG * x_i                        machines that must NEVER be isolated (MRI, lab)
Term 4 counts a service twice if both its twins AND its database are isolated (an over-estimate of the
damage, never an under-estimate), which keeps the model quadratic.

Variables: by default only the machines that matter (hacked machines + machines they link to + twins/
dependencies of affected services). Everything else is fixed at x = 0. This "problem reduction" is what keeps
the number of qubits small; `full=True` uses every machine (for the scale study).
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from qacrs.network import Network, Scenario

SPREAD = 0.5


@dataclass
class Qubo:
    names: list[str]                       # variable i <-> machine names[i]
    const: float
    lin: dict[int, float]
    quad: dict[tuple[int, int], float]

    @property
    def n(self) -> int:
        return len(self.names)

    def value(self, x) -> float:
        return self.const + sum(a * x[i] for i, a in self.lin.items()) + sum(b * x[i] * x[j] for (i, j), b in self.quad.items())

    def all_values(self) -> np.ndarray:
        """Cost of every one of the 2^n decisions at once (vectorised brute force). Row k = bits of k."""
        k = np.arange(2 ** self.n, dtype=np.int64)
        X = ((k[:, None] >> np.arange(self.n)) & 1).astype(np.float64)
        v = np.full(len(k), self.const)
        for i, a in self.lin.items():
            v += a * X[:, i]
        for (i, j), b in self.quad.items():
            v += b * X[:, i] * X[:, j]
        return v


def variables(net: Network, sc: Scenario, full: bool = False) -> list[str]:
    if full:
        return [m.name for m in net.machines]
    keep = set(sc.hacked)
    for a, b in net.links:
        if a in sc.hacked: keep.add(b)
    for s in net.services:
        if keep & set(s.replicas + s.depends_on):
            keep |= set(s.replicas)
    return [m.name for m in net.machines if m.name in keep]         # stable order


def build(net: Network, sc: Scenario, full: bool = False, hard: bool = True) -> Qubo:
    """hard=False drops the BIG penalty (used only to SCORE decisions; unsafe ones are counted separately)."""
    names = variables(net, sc, full)
    v = {n: i for i, n in enumerate(names)}
    const, lin, quad = 0.0, {}, {}

    def L(i, a): lin[i] = lin.get(i, 0.0) + a
    def Q(i, j, b):
        if i == j: return L(i, b)
        key = (min(i, j), max(i, j)); quad[key] = quad.get(key, 0.0) + b

    machines = {m.name: m for m in net.machines}
    big = 1 + sum(sc.hacked.values()) * (1 + SPREAD * len(net.links)) + sum(m.disruption for m in net.machines) \
        + sum(s.value * (1 + len(s.depends_on)) for s in net.services)

    for h, r in sc.hacked.items():                                  # 1. leftover risk r(1-x)
        const += r
        if h in v: L(v[h], -r)
    for a, b in net.links:                                          # 2. spread  S r (1-x_a)(1-x_b)
        if a in sc.hacked and machines[b].critical and b not in sc.hacked:
            w = SPREAD * sc.hacked[a]
            const += w
            if a in v: L(v[a], -w)
            if b in v: L(v[b], -w)
            if a in v and b in v: Q(v[a], v[b], w)
    for n, i in v.items():                                          # 3. disruption, 5. hard rule
        m = machines[n]
        L(i, m.disruption + (0 if m.isolatable or not hard else big))
    for s in net.services:                                          # 4. service down
        reps = [v[r] for r in s.replicas if r in v]
        if len(reps) == len(s.replicas) == 2: Q(reps[0], reps[1], s.value)
        elif len(reps) == len(s.replicas) == 1: L(reps[0], s.value)
        for d in s.depends_on:
            if d in v: L(v[d], s.value)
    return Qubo(names, const, lin, quad)


# ---------------------------------------------------------------- explain & verify --------------------------

def services_down(net: Network, isolated: set[str]) -> list[str]:
    return [s.name for s in net.services
            if all(r in isolated for r in s.replicas) or any(d in isolated for d in s.depends_on)]


def verify(net: Network, isolated: set[str]) -> dict:
    """Classical safety layer: runs on EVERY decision (quantum or not) before anything is executed."""
    machines = {m.name: m for m in net.machines}
    never = sorted(n for n in isolated if not machines[n].isolatable)
    approval = sorted(n for n in isolated if machines[n].critical)
    return {"ok": not never, "violations": never, "needs_two_person": approval}


def decision_from_bits(q: Qubo, x) -> set[str]:
    return {q.names[i] for i, b in enumerate(x) if b}
