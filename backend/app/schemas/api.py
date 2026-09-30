"""Pydantic v2 request/response schemas, including the Common Event Schema."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

Source = Literal["edr", "ndr", "firewall", "identity", "dns", "cloud", "ueba", "threat_intel", "app"]
EventType = Literal["net_conn", "process", "lsass_access", "dns_query", "file_activity", "signin", "cloud_api",
                    "ti_match", "ueba_anomaly"]
EngineerCommand = Literal["ISOLATE_ASSET", "BLOCK_C2", "PROTECT_DATABASE", "REVOKE_SESSION", "RUN_VERIFICATION"]
FailureMode = Literal["integration_down", "gate_fail", "ioc_return"]


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int


class EventIn(BaseModel):
    """Common Event Schema. Connectors normalise vendor logs into this shape."""
    model_config = ConfigDict(extra="forbid")
    event_id: str | None = Field(default=None, max_length=128)
    ts: datetime | None = None
    source: Source
    type: EventType
    severity: int = Field(default=5, ge=0, le=10)
    src_ip: IPvAnyAddress
    hostname: str | None = Field(default=None, max_length=255)
    asset_id: int | None = None
    user: str | None = Field(default=None, max_length=255)
    process_hash: str | None = Field(default=None, max_length=128)
    c2_domain: str | None = Field(default=None, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)


class IngestIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=1000)


class IngestOut(BaseModel):
    accepted: int
    incident_ids: list[str]


class RollbackIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class CommandIn(BaseModel):
    command: EngineerCommand


class SimRunIn(BaseModel):
    mode: Literal["success", "failure"] = "success"
    failure: FailureMode | None = None


class ChangeWindowIn(BaseModel):
    in_change_window: bool


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    state: str
    title: str
    src_ip: str
    hostname: str | None = None
    tier: int | None = None
    attack_type: str | None = None
    risk_score: int | None = None
    confidence: int | None = None
    level: str | None = None
    pending_level: str | None = None
    hold_reason: str | None = None
    escalation_reason: str | None = None
    detected_at: datetime
    deadline_at: datetime | None = None
    contained_at: datetime | None = None
    closed_at: datetime | None = None
    mttc_ms: int | None = None
    false_positive: bool = False
