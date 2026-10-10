"""Independent safety layer + pre-registered containment check (v2).

    Rules: docs/qacrs/PREREGISTRATION.md  (committed before this file and before any v2 result)

This module never looks at QUBO weights or solver output quality. It only receives a network, a scenario and
a SET of machines to isolate, so it judges a decision from a quantum solver, a classical solver or a simple
rule in exactly the same way. It is stricter than `qubo_builder.verify` (kept unchanged for v1
reproducibility), which only checks the never-isolate rule.

Statuses (exactly one per decision):
    REJECTED                    breaks a safety rule (S1-S3): must never be executed
    NOT_CONTAINED               safe, but containment rule C1 or C2 fails
    CONTAINED_PENDING_APPROVAL  safe and contained, but isolates a critical server -> two different people
    CONTAINED                   safe and contained, fully automatic
Extra flag: owner_review = hacked, never-isolatable machines with risk >= threshold (compensating controls).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from qacrs.network import Network, Scenario

HIGH_RISK = 7            # pre-registered primary threshold (CVSS v3 "High" starts at 7.0)
RISK_MIN, RISK_MAX = 1, 10

REJECTED = "REJECTED"
NOT_CONTAINED = "NOT_CONTAINED"
PENDING = "CONTAINED_PENDING_APPROVAL"
CONTAINED = "CONTAINED"
STATUSES = (REJECTED, NOT_CONTAINED, PENDING, CONTAINED)


@dataclass
class Verdict:
    status: str
    reasons: list[str] = field(default_factory=list)       # why it is not CONTAINED (empty if it is)
    needs_two_person: list[str] = field(default_factory=list)
    owner_review: list[str] = field(default_factory=list)

    @property
    def contained(self) -> bool:
        return self.status in (CONTAINED, PENDING)

    def as_dict(self) -> dict:
        return {"status": self.status, "reasons": self.reasons,
                "needs_two_person": self.needs_two_person, "owner_review": self.owner_review}


def validate_scenario(net: Network, sc: Scenario) -> list[str]:
    """S3: problems with the scenario itself (an empty list means it is valid)."""
    errors = []
    if sc is None or not isinstance(getattr(sc, "hacked", None), dict):
        return ["scenario has no 'hacked' mapping"]
    if sc.network != net.name:
        errors.append(f"scenario is for network '{sc.network}', not '{net.name}'")
    if not sc.hacked:
        errors.append("no hacked machine listed")
    idx = net.index()
    for m, r in sc.hacked.items():
        if m not in idx:
            errors.append(f"unknown machine '{m}'")
        if isinstance(r, bool) or not isinstance(r, int) or not RISK_MIN <= r <= RISK_MAX:
            errors.append(f"risk of '{m}' must be an integer {RISK_MIN}-{RISK_MAX}, got {r!r}")
    return errors


def open_paths(net: Network, sc: Scenario, isolated: set[str]) -> list[tuple[str, str]]:
    """C1: links from a restricted hacked machine to an untouched, non-hacked critical server."""
    crit = {m.name for m in net.machines if m.critical}
    return [(a, b) for a, b in net.links
            if a in sc.hacked and a not in isolated and b in crit and b not in sc.hacked and b not in isolated]


def check(net: Network, sc: Scenario, isolated, threshold: int = HIGH_RISK) -> Verdict:
    """Judge one decision. `isolated` = machines to isolate; every other hacked machine is restricted."""
    errors = validate_scenario(net, sc)
    if errors:
        return Verdict(REJECTED, ["S3 invalid scenario: " + e for e in errors])
    isolated = set(isolated)
    machines = {m.name: m for m in net.machines}

    unknown = sorted(n for n in isolated if n not in machines)                           # S2
    never = sorted(n for n in isolated if n in machines and not machines[n].isolatable)   # S1
    if unknown or never:
        return Verdict(REJECTED, [f"S2 unknown machine '{n}'" for n in unknown] +
                       [f"S1 '{n}' must never be isolated" for n in never])

    reasons = [f"C1 open path {a} -> {b} (critical)" for a, b in open_paths(net, sc, isolated)]
    owner = []
    for h, r in sorted(sc.hacked.items()):
        if r < threshold or h in isolated:
            continue
        if machines[h].isolatable:
            reasons.append(f"C2 '{h}' has risk {r} >= {threshold} but is only restricted")
        else:
            owner.append(h)
    approval = sorted(n for n in isolated if machines[n].critical)
    if reasons:
        status = NOT_CONTAINED
    else:
        status = PENDING if approval else CONTAINED
    return Verdict(status, reasons, approval, owner)
