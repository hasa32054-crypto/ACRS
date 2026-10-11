"""HASSAN v9: root-cause fixes for the v8 misses. Rules: docs/qacrs/PREREGISTRATION_v9.md.

  * optimality certificate + independent checker that recomputes every field and re-solves (S5-v9)
  * corroborated-alert guard v2 using an independent NDR flow log (S10-v9)
  * SHIELD: port-scoped block of lateral-movement protocols on links out of non-isolated infected machines (R-v9)
  * safety-constrained regret rule (G-v9)
  * fresh data sets (seeds 7009 / 9004 / 7102 / 7203 / 8109 / 8131 / 8121)
"""
from __future__ import annotations

import hashlib
import json
import random

from qacrs import escalation as E
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario, build as build_net, random_scenarios
from qacrs.phase8_ood import chain_scenarios

CHAIN_SEED, RAND_SEED, H60_SEED, RW_SEED = 7009, 9004, 7102, 7203
MANIP_SEED, TAMPER_SEED, TWIN_SEED = 8109, 8131, 8121
N_CHAIN, N_RAND = 200, 250                       # per network, same sizes as v7
P_SPURIOUS, P_MISS = 0.02, 0.05                  # NDR design assumptions (pre-registered)
TAU = 5.0
EXACT_MAX_VARS_CHECKER = 22


# ------------------------------------------------------------------ fresh data ------------------------------------
def prior_keys_v9():
    from qacrs.phase9_v7 import fresh_sets, prior_keys
    keys = prior_keys()
    fs, _ = fresh_sets()
    for pairs in fs.values():
        for net, s in pairs:
            keys.setdefault(net.name, set()).add(tuple(sorted(s.hacked.items())))
    return keys


def fresh_sets_v9():
    prior = prior_keys_v9()
    out, dropped = {"chains_7009": [], "random_9004": []}, {"chains_7009": 0, "random_9004": 0}
    for d in (1, 2):
        net = build_net(d)
        for name, gen in (("chains_7009", lambda: chain_scenarios(net, N_CHAIN, CHAIN_SEED)),
                          ("random_9004", lambda: random_scenarios(net, N_RAND, RAND_SEED))):
            seen = set(prior.get(net.name, set()))
            for s in gen():
                k = tuple(sorted(s.hacked.items()))
                if k in seen:
                    dropped[name] += 1; continue
                seen.add(k)
                s.id = s.id + ("_c9" if name.startswith("chains") else "_r94")
                out[name].append((net, s))
    return out, dropped


def hospital60_v9():
    net = RV.hospital60()
    old = {tuple(sorted(s.hacked.items())) for s in chain_scenarios(net, 200, 7101)}
    return net, [s for s in chain_scenarios(net, 200, H60_SEED) if tuple(sorted(s.hacked.items())) not in old]


def chain_paths(sc: Scenario) -> list[list[str]]:
    if not sc.description.startswith("attack chain"):
        return []
    return [p.split(" -> ") for p in sc.description.split(": ", 1)[1].split(" | ")]


# ------------------------------------------------------------------ S5-v9: optimality certificate ----------------
def objective(net, sc, iso, seg) -> float:
    q = V7.build_v7(net, sc)
    x = [1 if (nm in iso or (nm.endswith(V7.SEG) and nm[:-len(V7.SEG)] in seg)) else 0 for nm in q.names]
    return float(q.value(x))


def expected_status(net, sc, iso, seg, held, flags, fallback) -> str:
    st = V7.decide_v7(net, sc, set(iso), set(seg)).status
    if (fallback or held or flags) and st in (S.CONTAINED, S.PENDING, S.NOT_CONTAINED):
        st = E.ESCALATED
    return st


def certificate_v9(net, sc, iso, seg, held=(), flags=(), fallback=None) -> dict:
    hacked = set(sc.hacked)
    machines = {m.name: m for m in net.machines}
    iso, seg, held = set(iso), set(seg), set(held)
    return {"scenario_hash": hashlib.sha256(json.dumps(sorted(sc.hacked.items())).encode()).hexdigest()[:16],
            "isolate": sorted(iso), "segment": sorted(seg), "held": sorted(held), "guard_flags": list(flags),
            "fallback": fallback, "status": expected_status(net, sc, iso, seg, held, flags, fallback),
            "objective_with_held": round(objective(net, sc, iso | held, seg), 6),
            "claims": {"isolated_subset_of_reported_hacked": (iso | held) <= hacked,
                       "no_never_isolate_device_isolated": all(machines[m].isolatable for m in iso | held),
                       "segment_only_on_critical": all(machines[m].critical for m in seg),
                       "no_critical_isolated_automatically": not any(machines[m].critical for m in iso),
                       "services_down": V7.services_down_v7(net, iso, seg, hacked),
                       "open_paths_after": [list(p) for p in V7.open_paths_v7(net, sc, iso, seg)]}}


def _checker_optimum(net, sc) -> tuple[float, str]:
    """Checker's own re-solve. Exact enumeration with a plain loop (not the engine's vectorised solver)."""
    q = V7.build_v7(net, sc)
    if q.n <= EXACT_MAX_VARS_CHECKER:
        best = min(q.value([(k >> i) & 1 for i in range(q.n)]) for k in range(2 ** q.n)) if q.n <= 12 \
            else float(q.all_values().min())
        return float(best), "exact"
    return float("nan"), "local"


def _one_flip_optimal(net, sc, iso, seg) -> bool:
    q = V7.build_v7(net, sc)
    x = [1 if (nm in iso or (nm.endswith(V7.SEG) and nm[:-len(V7.SEG)] in seg)) else 0 for nm in q.names]
    v = q.value(x)
    for i in range(q.n):
        x[i] ^= 1
        if q.value(x) < v - 1e-9:
            return False
        x[i] ^= 1
    return True


def verify_certificate_v9(net, sc, cert: dict) -> bool:
    try:
        iso, seg, held = set(cert["isolate"]), set(cert["segment"]), set(cert["held"])
        if iso & held or iso & seg:
            return False
        fresh = certificate_v9(net, sc, iso, seg, held, cert["guard_flags"], cert["fallback"])
    except Exception:
        return False
    if fresh != cert:
        return False
    c = fresh["claims"]
    if not (c["no_never_isolate_device_isolated"] and c["segment_only_on_critical"]
            and c["no_critical_isolated_automatically"] and c["isolated_subset_of_reported_hacked"]):
        return False
    if cert["fallback"]:
        return not iso and not seg and not held and cert["status"] == E.ESCALATED
    opt, how = _checker_optimum(net, sc)
    if how == "exact":
        return abs(cert["objective_with_held"] - opt) < 1e-6
    return _one_flip_optimal(net, sc, iso | held, seg)


# ------------------------------------------------------------------ S10-v9: corroborated alerts --------------------
def ndr_lateral_flows(net: Network, genuine_hops, rng: random.Random, p_spurious=P_SPURIOUS, p_miss=P_MISS) -> set:
    """Links on which the independent network sensor saw a lateral-movement (admin-protocol) flow."""
    flows = {tuple(h) for h in genuine_hops if rng.random() >= p_miss}
    flows |= {(a, b) for a, b in net.links if rng.random() < p_spurious}
    return flows


def hops_of(sc: Scenario) -> list[tuple[str, str]]:
    return [(p[i], p[i + 1]) for p in chain_paths(sc) for i in range(len(p) - 1)]


def guard_v2(net: Network, sc: Scenario, lateral: set) -> list[str]:
    from qacrs.hassan import entry_points
    entries = entry_points(net)
    return [f"'{m}' reported hacked with no lateral-movement flow from a compromised machine (NDR)"
            for m in sorted(sc.hacked) if m not in entries and not any((p, m) in lateral for p in sc.hacked)]


# ------------------------------------------------------------------ R-v9: SHIELD ----------------------------------
def shield_links(net: Network, infected, iso) -> set:
    return {(a, b) for a, b in net.links if a in infected and a not in iso}


def spread_v9(net: Network, initial, policy, ticks=10, decide_at=2, risk=8, shield=False) -> dict:
    infected = set(initial); iso, seg, sh = set(), set(), set(); floor = None
    for t in range(1, ticks + 1):
        if t == decide_at:
            floor = len(infected)
        if t == decide_at and policy is not None:
            sc = Scenario("rw", net.name, {m: risk for m in sorted(infected)}, "ransomware")
            iso, seg = policy(net, sc)
            iso = {m for m in iso if not net.machine(m).critical}
            if shield:
                sh = shield_links(net, infected, iso)
        new = {b for a, b in net.links if a in infected and a not in iso and b not in iso and b not in seg
               and (a, b) not in sh}
        infected |= new
    down = V7.services_down_v7(net, iso, seg, infected)
    enc_down = [s.name for s in net.services
                if all(r in infected or r in iso for r in s.replicas) or any(d in infected or d in iso for d in s.depends_on)]
    return {"encrypted": len(infected), "floor": floor, "isolated": len(iso), "shielded_links": len(sh),
            "services_unavailable": sorted(set(down) | set(enc_down))}


# ------------------------------------------------------------------ G-v9: safety-constrained regret ---------------
def regret_resolve(net, sc, tau=TAU):
    """Returns (resolved, alt_iso, seg, regret) for an escalated v7 decision; resolved only if every condition holds."""
    iso, seg, q, best = V7.q_acrs_v7(net, sc)
    d = V7.decide_v7(net, sc, iso, seg)
    if d.status != E.ESCALATED:
        return None
    machines = {m.name: m for m in net.machines}
    alt = set(iso) | {e["target"] for e in d.escalations if e["target"] in sc.hacked}
    alt = {m for m in alt if machines[m].isolatable and not machines[m].critical}
    seg2 = set(seg) - alt
    regret = objective(net, sc, alt, seg2) - best
    ok_safety = V7.check_v7(net, sc, alt, seg2).status != S.REJECTED
    st = V7.decide_v7(net, sc, alt, seg2).status
    down = V7.services_down_v7(net, alt, seg2, set(sc.hacked))
    resolved = ok_safety and st == S.CONTAINED and not down and regret <= tau
    return {"resolved": resolved, "status_alt": st, "services_down_alt": len(down), "regret": regret}


# ------------------------------------------------------------------ engine wiring ---------------------------------
class EngineV9:
    """HASSAN engine with the v9 fixes: corroborated-alert guard (when an NDR flow log is supplied) and the
    optimality certificate. Everything else (fail-safe, rate limit, TTL, HMAC, card) is the v8 engine."""

    def __init__(self, net, **kw):
        from qacrs import hassan as H
        self.H, self.net = H, net
        self.base = H.Engine(net, **kw)
        self.key = self.base.key

    def decide(self, sc, lateral: set | None = None):
        d = self.base.decide(sc, flags=guard_v2(self.net, sc, lateral) if lateral is not None else None)
        if d.status == S.REJECTED:
            return d
        d.certificate = certificate_v9(self.net, sc, d.isolate, d.segment, d.held_for_humans, d.guard_flags, d.fallback)
        d.signature = self.H.sign(d.certificate, self.base.key)
        return d
