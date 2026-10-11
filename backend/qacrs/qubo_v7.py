"""HASSAN v7: graded containment for critical servers (ISOLATE / SEGMENT / RESTRICT).

Rules: docs/qacrs/PREREGISTRATION_v7.md. Earlier modules are untouched (v1-v6 stay reproducible).

A decision is a pair (iso, seg): machines to ISOLATE and critical servers to SEGMENT. Every other hacked machine is
RESTRICTED (attacker channel cut).
  SEGMENT m  = drop m -> C2  +  drop every hacked, non-isolated machine -> m.  Healthy traffic to m keeps flowing.
This module holds: the v7 QUBO, the exact v7 scoring semantics, the v7 safety check + gate, and the four methods.
"""
from __future__ import annotations

from qacrs import escalation as E
from qacrs import qubo_builder as QB
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario
from qacrs.qubo_builder import Qubo, variables

RHO, D_SEG = 0.3, 1.0
SEG = "#seg"


# ------------------------------------------------------------------ exact semantics -------------------------------
def services_down_v7(net: Network, iso, seg, hacked) -> list[str]:
    iso, seg = set(iso), set(seg)
    down = []
    for s in net.services:
        if any(d in iso for d in s.depends_on):
            down.append(s.name); continue
        dep_seg = any(d in seg for d in s.depends_on)
        if all(r in iso or (dep_seg and r in hacked and r not in iso) for r in s.replicas):
            down.append(s.name)
    return down


def open_paths_v7(net: Network, sc: Scenario, iso, seg) -> list[tuple[str, str]]:
    iso, seg = set(iso), set(seg)
    crit = {m.name for m in net.machines if m.critical}
    return [(a, b) for a, b in net.links if a in sc.hacked and a not in iso and b in crit
            and b not in sc.hacked and b not in iso and b not in seg]


def check_v7(net: Network, sc: Scenario, iso, seg, threshold: int = S.HIGH_RISK) -> S.Verdict:
    errors = S.validate_scenario(net, sc)
    if errors:
        return S.Verdict(S.REJECTED, ["S3 invalid scenario: " + e for e in errors])
    iso, seg = set(iso), set(seg)
    machines = {m.name: m for m in net.machines}
    bad = [f"S2 unknown machine '{n}'" for n in sorted((iso | seg) - set(machines))]
    bad += [f"S1 '{n}' must never be isolated" for n in sorted(iso) if n in machines and not machines[n].isolatable]
    bad += [f"S4 '{n}' can only be segmented if it is a critical server" for n in sorted(seg)
            if n in machines and not machines[n].critical]
    bad += [f"S5 '{n}' cannot be both isolated and segmented" for n in sorted(iso & seg)]
    if bad:
        return S.Verdict(S.REJECTED, bad)
    reasons = [f"C1 open path {a} -> {b} (critical)" for a, b in open_paths_v7(net, sc, iso, seg)]
    owner = []
    for h, r in sorted(sc.hacked.items()):
        if r < threshold or h in iso or (h in seg and machines[h].critical):
            continue
        if machines[h].isolatable:
            reasons.append(f"C2 '{h}' has risk {r} >= {threshold} but is only restricted")
        else:
            owner.append(h)
    approval = sorted(n for n in iso if machines[n].critical)
    status = S.NOT_CONTAINED if reasons else (S.PENDING if approval else S.CONTAINED)
    return S.Verdict(status, reasons, approval, owner)


def decide_v7(net: Network, sc: Scenario, iso, seg, threshold: int = S.HIGH_RISK) -> E.Decision:
    """v7 gate: same G1/G2/G3 rules as v5, applied to failures that remain AFTER segmentation."""
    iso, seg = set(iso), set(seg)
    v = check_v7(net, sc, iso, seg, threshold)
    base = dict(isolate_now=sorted(iso), needs_two_person=v.needs_two_person, owner_review=v.owner_review)
    if v.status != S.NOT_CONTAINED:
        return E.Decision(v.status, reasons=v.reasons, **base)
    machines = {m.name: m for m in net.machines}
    hacked = set(sc.hacked)
    esc, uncovered = [], []

    def g3(h, why):
        before = set(services_down_v7(net, iso, seg, hacked))
        lost = sorted(set(services_down_v7(net, iso | {h}, seg - {h}, hacked)) - before)
        if machines[h].isolatable and not machines[h].critical and lost:
            esc.append({"rule": "G3", "target": h, "approvals": 2, "services_at_stake": lost,
                        "action": f"two-person decision: isolate '{h}' ({', '.join(lost)} go(es) down) or accept the documented risk ({why})"})
            return True
        return False

    for h, r in sorted(sc.hacked.items()):
        if r >= threshold and h not in iso and h not in seg and machines[h].isolatable:
            if machines[h].critical:
                esc.append({"rule": "G1", "target": h, "approvals": 2,
                            "action": f"isolate critical server '{h}' (risk {r}) after two-person approval"})
            elif not g3(h, f"risk {r} >= {threshold}"):
                uncovered.append(f"C2 '{h}' has risk {r} >= {threshold} but is only restricted")
    for a, b in open_paths_v7(net, sc, iso, seg):
        if not machines[a].isolatable:
            esc.append({"rule": "G2", "target": b, "approvals": 2,
                        "action": f"two-person decision on critical server '{b}' (never-isolatable source '{a}')"})
        elif not g3(a, f"open path {a} -> {b}"):
            uncovered.append(f"C1 open path {a} -> {b} (critical)")
    seen, unique = set(), []
    for e in esc:
        if (e["rule"], e["target"]) not in seen:
            seen.add((e["rule"], e["target"])); unique.append(e)
    return E.Decision(S.NOT_CONTAINED if uncovered else E.ESCALATED, escalations=unique, reasons=uncovered, **base)


# ------------------------------------------------------------------ QUBO -----------------------------------------
def build_v7(net: Network, sc: Scenario, rho: float = RHO, d_seg: float = D_SEG) -> Qubo:
    spread = QB.SPREAD
    machines = {m.name: m for m in net.machines}
    base = variables(net, sc)
    names = list(base) + [n + SEG for n in base if machines[n].critical]
    v = {n: i for i, n in enumerate(names)}
    X = lambda n: v.get(n)
    Sv = lambda n: v.get(n + SEG)
    const, lin, quad = 0.0, {}, {}

    def L(i, a):
        if i is not None:
            lin[i] = lin.get(i, 0.0) + a

    def Q(i, j, b):
        if i is None or j is None:
            return
        if i == j:
            return L(i, b)
        k = (min(i, j), max(i, j)); quad[k] = quad.get(k, 0.0) + b

    n_crit = sum(m.critical for m in net.machines)
    big = (1 + sum(sc.hacked.values()) * (1 + spread * len(net.links)) + sum(m.disruption for m in net.machines)
           + sum(s.value * (1 + len(s.depends_on)) for s in net.services) + n_crit * d_seg
           + 3 * sum(s.value * max(1, len(s.depends_on)) for s in net.services))

    for h, r in sc.hacked.items():                                   # 1. leftover risk
        const += r
        L(X(h), -r)
        if machines[h].critical:
            L(Sv(h), -(1 - rho) * r)
    for a, b in net.links:                                           # 2. spread w(1-xa)(1-xb-sb)
        if a in sc.hacked and machines[b].critical and b not in sc.hacked:
            w = spread * sc.hacked[a]
            const += w
            L(X(a), -w); L(X(b), -w); L(Sv(b), -w)
            Q(X(a), X(b), w); Q(X(a), Sv(b), w)
    for n in base:                                                   # 3. disruption, hard rules, one-hot
        m = machines[n]
        L(X(n), m.disruption + (0 if m.isolatable else big))
        if m.critical:
            L(Sv(n), d_seg)
            Q(X(n), Sv(n), big)
    for s in net.services:                                           # 4. service down
        reps = s.replicas
        if len(reps) == 2:
            Q(X(reps[0]), X(reps[1]), s.value)
        elif len(reps) == 1:
            L(X(reps[0]), s.value)
        for d in s.depends_on:
            L(X(d), s.value)
            sd = Sv(d)
            if sd is None:
                continue
            h = [1 if r in sc.hacked else 0 for r in reps]
            if len(reps) == 2:                                       # V(x1+h1 s)(x2+h2 s) - V x1 x2
                Q(X(reps[0]), sd, s.value * h[1])
                Q(X(reps[1]), sd, s.value * h[0])
                L(sd, s.value * h[0] * h[1])
            elif len(reps) == 1:
                L(sd, s.value * h[0])
    return Qubo(names, const, lin, quad)


def split(q: Qubo, k: int) -> tuple[set[str], set[str]]:
    on = [q.names[i] for i in range(q.n) if (k >> i) & 1]
    return {n for n in on if not n.endswith(SEG)}, {n[:-len(SEG)] for n in on if n.endswith(SEG)}


def q_acrs_v7(net, sc, rho=RHO, d_seg=D_SEG):
    q = build_v7(net, sc, rho, d_seg)
    vals = q.all_values()
    k = int(vals.argmin())
    iso, seg = split(q, k)
    return iso, seg, q, float(vals[k])


# ------------------------------------------------------------------ methods ---------------------------------------
def m_full_isolation_safe(net, sc):
    iso = {m.name for m in net.machines if m.isolatable}
    return {h for h in sc.hacked if h in iso}, set()


def m_rule_segment(net, sc):
    machines = {m.name: m for m in net.machines}
    iso = {h for h in sc.hacked if machines[h].isolatable and not machines[h].critical}
    seg = {h for h in sc.hacked if machines[h].critical}
    seg |= {b for a, b in net.links if a in sc.hacked and a not in iso and machines[b].critical and b not in sc.hacked}
    return iso, seg


def m_q_acrs_v5(net, sc):
    from qacrs.phase3_compare import q_acrs
    return set(q_acrs(net, sc)[0]), set()


def m_q_acrs_v7(net, sc):
    iso, seg, _, _ = q_acrs_v7(net, sc)
    return iso, seg


METHODS_V7 = {"full_isolation_safe": m_full_isolation_safe, "rule_segment": m_rule_segment,
              "q_acrs_v5": m_q_acrs_v5, "q_acrs_v7": m_q_acrs_v7}


def evaluate(net, sc, method: str) -> dict:
    """Score one method on one scenario with the v7 gate (v5 gate for q_acrs_v5) and both rule sets."""
    from qacrs import escalation_v5 as E5
    iso, seg = METHODS_V7[method](net, sc)
    d = E5.decide(net, sc, iso) if method == "q_acrs_v5" else decide_v7(net, sc, iso, seg)
    hacked = set(sc.hacked)
    return d.as_dict() | {
        "segment_now": sorted(seg),
        "services_down": services_down_v7(net, iso, seg, hacked),
        "healthy_isolated": sorted(iso - hacked),
        "risk_left": sum(r for h, r in sc.hacked.items() if h not in iso and h not in seg)
                     + sum(RHO * r for h, r in sc.hacked.items() if h in seg),
        "status_v2_rules": S.check(net, sc, iso).status,
    }
