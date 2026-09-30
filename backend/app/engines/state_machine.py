"""Incident State Machine. Every transition is validated here and recorded (event sourcing)."""
from __future__ import annotations

from .types import State as S

MAIN_PATH = [S.DETECT, S.UNDERSTAND, S.IDENTIFY_ENTRY, S.ATTRIBUTE_ASSET, S.RISK, S.DECIDE, S.CONTAIN,
             S.VERIFY, S.REMEDIATE, S.HARDEN, S.OBSERVE, S.RE_ENTRY, S.LEARN, S.CLOSE]

ACTIVE = {S.CONTAIN, S.VERIFY, S.REMEDIATE, S.HARDEN, S.OBSERVE, S.RE_ENTRY}
TERMINAL = {S.CLOSE, S.ROLLED_BACK}
AUTOMATED = set(MAIN_PATH) - {S.CLOSE}           # states the runner advances on its own

TRANSITIONS: dict[S, set[S]] = {
    S.DETECT: {S.UNDERSTAND},
    S.UNDERSTAND: {S.IDENTIFY_ENTRY},
    S.IDENTIFY_ENTRY: {S.ATTRIBUTE_ASSET},
    S.ATTRIBUTE_ASSET: {S.RISK},
    S.RISK: {S.DECIDE},
    S.DECIDE: {S.CONTAIN, S.MONITOR, S.PENDING_APPROVAL},
    S.CONTAIN: {S.VERIFY, S.ESCALATED},
    S.VERIFY: {S.REMEDIATE, S.CONTAIN, S.ESCALATED},
    S.REMEDIATE: {S.HARDEN, S.REMEDIATE, S.ESCALATED},
    S.HARDEN: {S.OBSERVE},
    S.OBSERVE: {S.RE_ENTRY, S.REMEDIATE, S.ESCALATED},
    S.RE_ENTRY: {S.LEARN, S.CONTAIN, S.ESCALATED},
    S.LEARN: {S.CLOSE},
    S.CLOSE: set(),
    S.MONITOR: {S.CONTAIN, S.CLOSE},
    S.PENDING_APPROVAL: {S.CONTAIN, S.CLOSE},
    S.ESCALATED: {S.VERIFY, S.REMEDIATE, S.CLOSE},
    S.ROLLED_BACK: set(),
}
# False-positive rollback is allowed from anything that is not finished.
for _s in list(TRANSITIONS):
    if _s not in TERMINAL:
        TRANSITIONS[_s].add(S.ROLLED_BACK)


class InvalidTransition(Exception):
    pass


def can(src: S | str, dst: S | str) -> bool:
    return S(dst) in TRANSITIONS[S(src)]


def check(src: S | str, dst: S | str) -> None:
    if not can(src, dst):
        raise InvalidTransition(f"{S(src).value} -> {S(dst).value} is not allowed")
