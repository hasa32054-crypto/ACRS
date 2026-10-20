"""v14: several independent alert sources per machine, fusion rules, and a white-box attacker that searches for the
input that hurts most. Rules: docs/qacrs/PREREGISTRATION_v14.md. The v9 engine is imported and used unchanged.

    honest = honest_readings(net, truth, rng)         # {machine: (s1, s2, s3)}  0 = no alert
    reported = fuse(net, honest, "median")             # Scenario the engine sees
    outcome(net, truth, reported, defender, lateral)   # what the engine does, judged against the truth

Goals (judged against the TRUTH, compared with the honest readings):
  A1 weaponize : extra services down from automatic actions + extra healthy machines isolated automatically
  A2 hide      : engine says CONTAINED (nobody is asked) but the same automatic actions are NOT_CONTAINED on the truth
  A3 flood     : extra human escalations (descriptive)
"""
from __future__ import annotations

import itertools
import random
from dataclasses import dataclass

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario

N_SOURCES = 3
P_FALSE_POSITIVE = 0.02
NOISE = (-1, 0, 1)
VALUES_FULL = tuple(range(0, 11))
VALUES_SMALL = (0, 1, 6, 7, 10)
FUSIONS = ("single", "max", "mean", "median")
DEFENDERS = {"D0": ("single", False), "D1": ("max", False), "D2": ("mean", False),
             "D3": ("median", False), "D4": ("median", True)}


# ------------------------------------------------------------------ honest readings -------------------------------
def honest_readings(net: Network, truth: Scenario, rng_noise: random.Random, rng_fp: random.Random) -> dict:
    out = {}
    for m in net.machines:
        if m.name in truth.hacked:
            r = truth.hacked[m.name]
            out[m.name] = tuple(min(S.RISK_MAX, max(S.RISK_MIN, r + rng_noise.choice(NOISE))) for _ in range(N_SOURCES))
        else:
            out[m.name] = tuple(rng_fp.randint(1, 5) if rng_fp.random() < P_FALSE_POSITIVE else 0
                                for _ in range(N_SOURCES))
    return out


# ------------------------------------------------------------------ fusion -----------------------------------------
def fuse_one(vals, rule: str) -> int:
    if rule == "single":
        return vals[0]
    if rule == "max":
        return max(vals)
    if rule == "mean":
        return int(sum(vals) / len(vals) + 0.5)               # round half up (all values are >= 0)
    if rule == "median":
        return sorted(vals)[len(vals) // 2]
    raise ValueError(rule)


def fuse(net: Network, readings: dict, rule: str, sid: str = "v14") -> Scenario:
    hacked = {}
    for m in net.machines:
        f = fuse_one(readings[m.name], rule)
        if f >= 1:
            hacked[m.name] = int(f)
    return Scenario(sid, net.name, hacked, "v14 fused alerts")


def relevant_sources(rule: str) -> tuple[int, ...]:
    return (0,) if rule == "single" else tuple(range(N_SOURCES))


# ------------------------------------------------------------------ engine outcome ---------------------------------
@dataclass
class Outcome:
    status: str                  # engine status on the reported scenario ("NONE" if nothing was reported)
    isolate: frozenset
    segment: frozenset
    services_down: int           # caused by automatic actions (judged on the truth)
    healthy_isolated: int        # isolated automatically but not hacked in the truth
    escalations: int
    truth_status: str            # v7 check of the automatic actions against the truth

    @property
    def silent(self) -> bool:
        return self.status == S.CONTAINED and self.truth_status == S.NOT_CONTAINED


class Defender:
    """Fusion rule + the unchanged v9 engine. Decisions are cached per reported scenario (pure function)."""

    def __init__(self, net: Network, rule: str, use_ndr: bool):
        self.net, self.rule, self.use_ndr = net, rule, use_ndr
        self.engine = V9.EngineV9(net, limiter=H.RateLimiter(limit=10 ** 9))
        self._cache: dict = {}

    def decide(self, reported: Scenario, lateral: set | None):
        key = (tuple(sorted(reported.hacked.items())), frozenset(lateral) if (self.use_ndr and lateral) else None)
        if key not in self._cache:
            if not reported.hacked:
                self._cache[key] = ("NONE", frozenset(), frozenset(), 0)
            else:
                d = self.engine.decide(reported, lateral=lateral if self.use_ndr else None)
                self._cache[key] = (d.status, frozenset(d.isolate), frozenset(d.segment), len(d.escalations))
        return self._cache[key]

    def outcome(self, truth: Scenario, readings: dict, lateral: set | None) -> Outcome:
        rep = fuse(self.net, readings, self.rule, truth.id)
        status, iso, seg, n_esc = self.decide(rep, lateral)
        hacked_true = set(truth.hacked)
        down = len(V7.services_down_v7(self.net, iso, seg, hacked_true))
        tstat = V7.check_v7(self.net, truth, set(iso), set(seg)).status
        return Outcome(status, iso, seg, down, len(set(iso) - hacked_true), n_esc, tstat)


# ------------------------------------------------------------------ goals -----------------------------------------
def harm_a1(o: Outcome, base: Outcome) -> int:
    return max(0, o.services_down - base.services_down) + max(0, o.healthy_isolated - base.healthy_isolated)


def services_extra(o: Outcome, base: Outcome) -> int:
    return max(0, o.services_down - base.services_down)


def success(goal: str, o: Outcome, base: Outcome) -> bool:
    if goal == "A1":
        return harm_a1(o, base) > 0
    if goal == "A2":
        return o.silent and not base.silent
    if goal == "A3":
        return o.escalations > base.escalations
    raise ValueError(goal)


def score(goal: str, o: Outcome, base: Outcome) -> float:
    """How good an attack is for the attacker (used to rank partial attacks in the beam search)."""
    if goal == "A1":
        return 10 * services_extra(o, base) + harm_a1(o, base)
    if goal == "A2":
        return 100.0 * success("A2", o, base) + (o.status == S.CONTAINED) + (o.truth_status == S.NOT_CONTAINED)
    return float(o.escalations - base.escalations)


# ------------------------------------------------------------------ attacker --------------------------------------
def apply(readings: dict, changes) -> dict:
    out = dict(readings)
    for (m, s), v in changes:
        t = list(out[m]); t[s] = v; out[m] = tuple(t)
    return out


def sources(net: Network, rule: str) -> list[tuple[str, int]]:
    return [(m.name, s) for m in net.machines for s in relevant_sources(rule)]


def exhaustive(defender: Defender, truth, honest, lateral, gamma: int, values=VALUES_FULL, goals=("A1", "A2", "A3")):
    """Every set of exactly `gamma` sources and every value in `values` (only real changes), all goals in one pass.
    Exact for this source set and value set. Returns {goal: {success, n_success, attack, outcome}} and the base."""
    base = defender.outcome(truth, honest, lateral)
    best = {g: (None, float("-inf")) for g in goals}
    n_ok = {g: 0 for g in goals}
    n_tried = 0
    for combo in itertools.combinations(sources(defender.net, defender.rule), gamma):
        options = [[v for v in values if v != honest[m][s]] for (m, s) in combo]
        for vals in itertools.product(*options):
            ch = tuple(zip(combo, vals))
            o = defender.outcome(truth, apply(honest, ch), lateral)
            n_tried += 1
            for g in goals:
                sc = score(g, o, base)
                if success(g, o, base):
                    n_ok[g] += 1
                if sc > best[g][1]:
                    best[g] = ((ch, o), sc)
    res = {}
    for g in goals:
        b = best[g][0]
        ok = b is not None and success(g, b[1], base)
        res[g] = {"success": ok, "n_success": n_ok[g],
                  "attack": [[m, s, v] for (m, s), v in b[0]] if ok else None,
                  "outcome": _o(b[1]) if ok else None}
    return {"goals": res, "n_tried": n_tried, "base": _o(base)}


def beam(defender: Defender, truth, honest, lateral, goal: str, gamma: int, width: int = 20, values=VALUES_SMALL):
    """Greedy beam search over growing attacks (lower bound on attacker power, never used for a certificate)."""
    base = defender.outcome(truth, honest, lateral)
    srcs = sources(defender.net, defender.rule)
    frontier = [((), defender.outcome(truth, honest, lateral))]
    for _ in range(gamma):
        cand = {}
        for ch, _o0 in frontier:
            used = {c[0] for c in ch}
            cur = apply(honest, ch)
            for src in srcs:
                if src in used:
                    continue
                for v in values:
                    if v == cur[src[0]][src[1]]:
                        continue
                    nch = tuple(sorted(ch + ((src, v),)))
                    if nch not in cand:
                        cand[nch] = defender.outcome(truth, apply(honest, nch), lateral)
        if not cand:
            break
        frontier = sorted(cand.items(), key=lambda kv: -score(goal, kv[1], base))[:width]
    ch, o = frontier[0]
    ok = success(goal, o, base)
    return {"success": ok, "attack": [[m, s, v] for (m, s), v in ch] if ok else None,
            "outcome": _o(o) if ok else None}


def _o(o: Outcome) -> dict:
    return {"status": o.status, "isolate": sorted(o.isolate), "segment": sorted(o.segment),
            "services_down": o.services_down, "healthy_isolated": o.healthy_isolated,
            "escalations": o.escalations, "truth_status": o.truth_status}


# ------------------------------------------------------------------ property P6 (tested, and proved in formal_v14) --
def median_bounded(honest_pair, forged) -> bool:
    """With 3 sources and one forged, the median lies between the two honest readings."""
    a, b = sorted(honest_pair)
    return a <= fuse_one((a, b, forged), "median") <= b


__all__ = ["honest_readings", "fuse", "fuse_one", "Defender", "Outcome", "exhaustive", "beam", "success",
           "harm_a1", "median_bounded", "DEFENDERS", "VALUES_FULL", "VALUES_SMALL"]
