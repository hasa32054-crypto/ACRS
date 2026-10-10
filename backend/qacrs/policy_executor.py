"""E6: turn a Q-ACRS decision into firewall policy, SAFELY, against a MOCK firewall only.

    THIS MODULE NEVER TOUCHES A REAL NETWORK. MockFirewallAdapter keeps an in-memory rule table. The only other
    adapter allowed is qacrs.sandbox_lab.SandboxIptablesAdapter (v4, E10): real Linux iptables, but restricted to
    loopback addresses (127.0.0.0/8) inside its own chain, for validation in an isolated container. Anything else would need a new, reviewed adapter and an
    authorised, isolated test environment (see docs/qacrs/PREREGISTRATION_v3.md, E6).

Flow:  decision -> PolicyExecutor.execute()
         1. re-check the decision with the independent safety layer + escalation gate (never trust the solver)
         2. REJECTED -> nothing is applied, reason logged
         3. critical server to isolate -> needs two DIFFERENT approvers, otherwise it waits (BLOCKED_AWAITING_APPROVAL)
         4. apply each rule to the adapter with bounded retries; on failure, roll back what this policy applied
         5. same policy twice -> ALREADY_APPLIED (idempotent)
       every step is written to the append-only PolicyAuditLog
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from qacrs import escalation as E
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario

ISOLATE, RESTRICT = "ISOLATE", "RESTRICT"


class AdapterError(RuntimeError):
    pass


class MockFirewallAdapter:
    """In-memory stand-in for a firewall. `fail_next` = how many upcoming calls raise AdapterError (to test retries)."""

    is_real = False

    def __init__(self, fail_next: int = 0):
        self.rules: dict[str, str] = {}
        self.calls = 0
        self.fail_next = fail_next

    def apply(self, target: str, action: str) -> None:
        self.calls += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            raise AdapterError(f"mock failure applying {action} to {target}")
        self.rules[target] = action

    def remove(self, target: str) -> None:
        self.rules.pop(target, None)


@dataclass
class PolicyAuditLog:
    """Append-only log. Entries can be read but the list is never edited in place."""
    path: Path | None = None
    _entries: list[dict] = field(default_factory=list)

    def write(self, **entry) -> None:
        entry = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **entry}
        self._entries.append(entry)
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(entry) + "\n")

    @property
    def entries(self) -> tuple[dict, ...]:
        return tuple(self._entries)


@dataclass
class Result:
    status: str              # REJECTED | BLOCKED_AWAITING_APPROVAL | APPLIED | APPLIED_WITH_ESCALATION | FAILED_ROLLED_BACK | ALREADY_APPLIED | PLANNED_DRY_RUN | NOT_CONTAINED_ESCALATE
    policy_id: str
    rules: list[tuple[str, str]]
    detail: list[str] = field(default_factory=list)


class PolicyExecutor:
    def __init__(self, net: Network, adapter: MockFirewallAdapter, audit: PolicyAuditLog,
                 max_retries: int = 2, dry_run: bool = True):
        if getattr(adapter, "is_real", True) and not getattr(adapter, "sandbox_only", False):
            raise ValueError("only mock adapters, or sandbox adapters limited to loopback addresses, are allowed")
        self.net, self.adapter, self.audit = net, adapter, audit
        self.max_retries, self.dry_run = max_retries, dry_run
        self.applied: dict[str, list[tuple[str, str]]] = {}

    @staticmethod
    def policy_id(sc: Scenario, isolate) -> str:
        raw = json.dumps([sc.id, sorted(sc.hacked.items()), sorted(isolate)])
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    def plan(self, sc: Scenario, isolate) -> list[tuple[str, str]]:
        isolate = set(isolate)
        return [(m, ISOLATE) for m in sorted(isolate)] + [(h, RESTRICT) for h in sorted(sc.hacked) if h not in isolate]

    def execute(self, sc: Scenario, isolate, approvals: dict[str, list[str]] | None = None) -> Result:
        isolate = set(isolate)
        approvals = approvals or {}
        pid = self.policy_id(sc, isolate)
        rules = self.plan(sc, isolate) if not (set(sc.hacked) | isolate) - {m.name for m in self.net.machines} else []
        log = lambda status, **kw: self.audit.write(policy_id=pid, scenario=sc.id, status=status, **kw)

        if pid in self.applied:
            log("ALREADY_APPLIED"); return Result("ALREADY_APPLIED", pid, self.applied[pid])

        d = E.decide(self.net, sc, isolate)                                  # 1. independent re-check
        if d.status == S.REJECTED:                                           # 2.
            log("REJECTED", reasons=d.reasons); return Result("REJECTED", pid, [], d.reasons)

        missing = []                                                         # 3. two-person rule
        for m in d.needs_two_person:
            who = approvals.get(m, [])
            if len(set(who)) < 2:
                missing.append(f"'{m}' needs 2 different approvers, has {sorted(set(who))}")
        if missing:
            log("BLOCKED_AWAITING_APPROVAL", reasons=missing)
            return Result("BLOCKED_AWAITING_APPROVAL", pid, rules, missing)

        if self.dry_run:
            log("PLANNED_DRY_RUN", rules=rules); return Result("PLANNED_DRY_RUN", pid, rules)

        done = []                                                            # 4. apply with retries
        for target, action in rules:
            for attempt in range(1, self.max_retries + 2):
                try:
                    self.adapter.apply(target, action)
                    log("RULE_APPLIED", target=target, action=action, attempt=attempt)
                    done.append((target, action)); break
                except AdapterError as e:
                    log("RULE_FAILED", target=target, action=action, attempt=attempt, error=str(e))
            else:
                for t, _ in done:
                    self.adapter.remove(t)
                    log("RULE_ROLLED_BACK", target=t)
                return Result("FAILED_ROLLED_BACK", pid, [], [f"adapter failed on {target} after retries"])

        self.applied[pid] = done
        if d.status == E.ESCALATED:
            log("APPLIED_WITH_ESCALATION", escalations=d.escalations)
            return Result("APPLIED_WITH_ESCALATION", pid, done, [x["action"] for x in d.escalations])
        if d.status == S.NOT_CONTAINED:
            log("NOT_CONTAINED_ESCALATE", reasons=d.reasons)
            return Result("NOT_CONTAINED_ESCALATE", pid, done, d.reasons)
        log("APPLIED", rules=done)
        return Result("APPLIED", pid, done)

    def rollback(self, policy_id: str) -> bool:
        rules = self.applied.pop(policy_id, None)
        if rules is None:
            return False
        for t, _ in rules:
            self.adapter.remove(t)
        self.audit.write(policy_id=policy_id, status="ROLLED_BACK", rules=rules)
        return True
