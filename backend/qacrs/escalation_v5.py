"""v5 gate = v3 gate (G1, G2, unchanged in escalation.py) + G3 "twin dilemma".

Rules: docs/qacrs/PREREGISTRATION_v5.md.
G3: a containment failure on an isolatable, NON-critical machine h, where isolating h as well would take down at
least one more service -> ESCALATED with "two-person decision: isolate h (services X go down) or keep X up and
accept the documented risk". Still never adds an automatic isolation.
"""
from __future__ import annotations

from qacrs import escalation as E
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario
from qacrs.qubo_builder import services_down


def _twin_cost(net, isolated, h):
    before = set(services_down(net, isolated))
    return sorted(set(services_down(net, isolated | {h})) - before)


def decide(net: Network, sc: Scenario, isolated, threshold: int = S.HIGH_RISK) -> E.Decision:
    isolated = set(isolated)
    d = E.decide(net, sc, isolated, threshold)
    if d.status != S.NOT_CONTAINED:
        return d
    machines = {m.name: m for m in net.machines}
    esc, uncovered = [], []

    def g3(h, why):
        lost = _twin_cost(net, isolated, h)
        if machines[h].isolatable and not machines[h].critical and lost:
            esc.append({"rule": "G3", "target": h, "approvals": 2, "services_at_stake": lost,
                        "action": f"two-person decision: isolate '{h}' ({', '.join(lost)} go(es) down) or keep "
                                  f"{', '.join(lost)} up and accept the documented risk ({why})"})
            return True
        return False

    for h, r in sorted(sc.hacked.items()):                                       # C2
        if r >= threshold and h not in isolated and machines[h].isolatable:
            if machines[h].critical:
                esc.append({"rule": "G1", "target": h, "approvals": 2,
                            "action": f"isolate critical server '{h}' (risk {r}) after two-person approval"})
            elif not g3(h, f"risk {r} >= {threshold}"):
                uncovered.append(f"C2 '{h}' has risk {r} >= {threshold} but is only restricted")
    for a, b in S.open_paths(net, sc, isolated):                                 # C1
        if not machines[a].isolatable:
            esc.append({"rule": "G2", "target": b, "approvals": 2,
                        "action": f"two-person decision: isolate critical server '{b}' or accept the documented "
                                  f"risk from never-isolatable '{a}'; owner applies compensating controls on '{a}'"})
        elif not g3(a, f"open path {a} -> {b}"):
            uncovered.append(f"C1 open path {a} -> {b} (critical)")
    seen, unique = set(), []
    for e in esc:                                                                # one action per (rule, target)
        if (e["rule"], e["target"]) not in seen:
            seen.add((e["rule"], e["target"])); unique.append(e)
    return E.Decision(S.NOT_CONTAINED if uncovered else E.ESCALATED, isolate_now=d.isolate_now,
                      escalations=unique, reasons=uncovered, needs_two_person=d.needs_two_person,
                      owner_review=d.owner_review)
