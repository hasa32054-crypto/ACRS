"""Domain types for the ACRS engines.

Everything under app/engines is pure Python (stdlib only): no database, no web
framework. That keeps the security decision logic deterministic, explainable
and unit-testable in isolation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Level(str, Enum):
    """Containment levels, least to most disruptive."""
    MONITOR = "MONITOR"                        # no enforcement
    COMPENSATING = "COMPENSATING"              # non-isolatable assets: allowlist + C2 block only
    RESTRICT = "RESTRICT"                      # L1: block egress + new flows to Tier-0/1
    EMERGENCY_RESTRICT = "EMERGENCY_RESTRICT"  # Tier-0 emergency containment: restrictive actions only
    SURGICAL = "SURGICAL"                      # L2: quarantine label, EDR containment w/ jump host, DB protection
    FULL_ISOLATION = "FULL_ISOLATION"          # L3: full host isolation


LEVEL_RANK = {
    Level.MONITOR: 0, Level.COMPENSATING: 1, Level.RESTRICT: 1,
    Level.EMERGENCY_RESTRICT: 1, Level.SURGICAL: 2, Level.FULL_ISOLATION: 3,
}


class State(str, Enum):
    """Incident lifecycle. Main path first, then side states."""
    DETECT = "DETECT"
    UNDERSTAND = "UNDERSTAND"
    IDENTIFY_ENTRY = "IDENTIFY_ENTRY"
    ATTRIBUTE_ASSET = "ATTRIBUTE_ASSET"
    RISK = "RISK"
    DECIDE = "DECIDE"
    CONTAIN = "CONTAIN"
    VERIFY = "VERIFY"
    REMEDIATE = "REMEDIATE"
    HARDEN = "HARDEN"
    OBSERVE = "OBSERVE"
    RE_ENTRY = "RE_ENTRY"
    LEARN = "LEARN"
    CLOSE = "CLOSE"
    # side states
    MONITOR = "MONITOR"                  # low risk: watch, no containment
    PENDING_APPROVAL = "PENDING_APPROVAL"  # decision needs a human before any enforcement
    ESCALATED = "ESCALATED"              # ACRS could not finish on its own -> Emergency Queue
    ROLLED_BACK = "ROLLED_BACK"          # false positive, every action undone


@dataclass
class Asset:
    id: int
    hostname: str
    ip: str
    tier: int                         # 0, 1, 2
    role: str
    segment: str
    owner: str
    isolatable: bool = True
    criticality: str = "medium"       # critical | high | medium | low
    os: str = ""
    pool: str | None = None
    pool_size: int = 1
    environment: str = "on-prem"      # on-prem | aws | azure | gcp | k8s
    cloud_instance_id: str | None = None
    edr_device_id: str | None = None
    in_change_window: bool = False
    dependents: list[str] = field(default_factory=list)


@dataclass
class Event:
    """Common Event Schema, as seen by the engines."""
    ts: datetime
    source: str        # edr | ndr | firewall | identity | dns | cloud | ueba | threat_intel | app
    event_type: str    # net_conn | process | lsass_access | dns_query | file_activity | signin | cloud_api | ti_match | ueba_anomaly
    src_ip: str
    hostname: str | None = None
    user: str | None = None
    process_hash: str | None = None
    c2_domain: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass
class Detection:
    rule_id: str
    title: str
    mitre: list[str]
    source: str
    category: str      # edr_behavior | network | identity | threat_intel | ueba | cloud
    strength: float    # 0..1
    fast_path: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Attribution:
    asset: Asset | None
    ok: bool
    conflict: bool
    notes: list[str] = field(default_factory=list)


@dataclass
class Factor:
    """One row of the explainability matrix."""
    name: str
    weight: float
    value: float        # 0..1
    contribution: float  # weight * value * 100
    explanation: str


@dataclass
class RiskAssessment:
    risk: int                    # 0..100
    confidence: int              # 0..100 (%)
    risk_factors: list[Factor]
    confidence_factors: list[Factor]
    adjustments: dict[str, int]
    distinct_sources: int
    blast_radius: dict[str, Any]


@dataclass
class Decision:
    """level runs now if auto_execute, otherwise it waits for approval.
    escalation_level is an optional stronger level that always waits for approval.
    hold_after_verify pauses automation after containment until a human confirms."""
    level: Level
    auto_execute: bool
    deadline_s: float
    approvals_required: int
    reasons: list[str]
    escalation_level: Level | None = None
    hold_after_verify: str | None = None
    segment_restrict: bool = False
    degraded_mode: bool = False
    circuit_breaker: bool = False


@dataclass
class Command:
    name: str          # ISOLATE_ASSET, BLOCK_C2, ...
    layer: str         # network | endpoint | identity | application | cloud | dns | database
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    critical: bool = False


@dataclass
class CommandResult:
    command: Command
    ok: bool
    attempts: int
    duration_ms: int
    provider: str
    message: str
    undo: dict[str, Any] = field(default_factory=dict)
