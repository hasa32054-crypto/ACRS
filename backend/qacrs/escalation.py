"""v3 escalation gate (E1): turn silent containment failures into explicit, actionable human escalations.

Rules: docs/qacrs/PREREGISTRATION_v3.md (E1). Runs AFTER the solver and AFTER the v2 safety layer
(`safety_checks.check`, unchanged). It never adds or removes an automatic isolation; it only labels the outcome
and attaches the recommended human action.

  G1  hacked critical server with risk >= threshold left restricted  -> isolate it after two-person approval
  G2  C1 open path whose source is a hacked never-isolatable device  -> two-person decision on the critical server

Status ESCALATED only if EVERY containment failure is covered by G1/G2; otherwise it stays NOT_CONTAINED (silent).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from qacrs import safety_checks as S
from qacrs.network import Network, Scenario

ESCALATED = "ESCALATED"
STATUSES = (S.REJECTED, S.NOT_CONTAINED, ESCALATED, S.PENDING, S.CONTAINED)


@dataclass
class Decision:
    status: str
    isolate_now: list[str]                                   # automatic actions (unchanged from the solver)
    escalations: list[dict] = field(default_factory=list)    # human actions: {rule, action, target, approvals}
    reasons: list[str] = field(default_factory=list)          # uncovered failures (silent) or rejections
    needs_two_person: list[str] = field(default_factory=list)
    owner_review: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"status": self.status, "isolate_now": self.isolate_now, "escalations": self.escalations,
                "reasons": self.reasons, "needs_two_person": self.needs_two_person,
                "owner_review": self.owner_review}


def decide(net: Network, sc: Scenario, isolated, threshold: int = S.HIGH_RISK) -> Decision:
    isolated = set(isolated)
    v = S.check(net, sc, isolated, threshold)
    base = dict(isolate_now=sorted(isolated), needs_two_person=v.needs_two_person, owner_review=v.owner_review)
    if v.status != S.NOT_CONTAINED:
        return Decision(v.status, reasons=v.reasons, **base)

    machines = {m.name: m for m in net.machines}
    esc, uncovered = [], []
    for h, r in sorted(sc.hacked.items()):                                       # C2 failures
        if r >= threshold and h not in isolated and machines[h].isolatable:
            if machines[h].critical:
                esc.append({"rule": "G1", "target": h, "approvals": 2,
                            "action": f"isolate critical server '{h}' (risk {r}) after two-person approval"})
            else:
                uncovered.append(f"C2 '{h}' has risk {r} >= {threshold} but is only restricted")
    for a, b in S.open_paths(net, sc, isolated):                                 # C1 failures
        if not machines[a].isolatable:
            esc.append({"rule": "G2", "target": b, "approvals": 2,
                        "action": f"two-person decision: isolate critical server '{b}' or accept the documented "
                                  f"risk from never-isolatable '{a}'; owner applies compensating controls on '{a}'"})
        else:
            uncovered.append(f"C1 open path {a} -> {b} (critical)")
    status = S.NOT_CONTAINED if uncovered else ESCALATED
    return Decision(status, escalations=esc, reasons=uncovered, **base)
