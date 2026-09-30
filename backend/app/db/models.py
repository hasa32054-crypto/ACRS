"""SQLAlchemy 2.x models. They mirror alembic/versions/0001_initial.py exactly (the migration is authoritative)."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Float, ForeignKey, Integer, SmallInteger, Text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetRow(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(Text, unique=True)
    ip: Mapped[str] = mapped_column(INET, unique=True)
    tier: Mapped[int] = mapped_column(SmallInteger)
    role: Mapped[str] = mapped_column(Text)
    segment: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(Text)
    isolatable: Mapped[bool] = mapped_column(Boolean)
    criticality: Mapped[str] = mapped_column(Text)
    os: Mapped[str] = mapped_column(Text)
    pool: Mapped[str | None] = mapped_column(Text)
    pool_size: Mapped[int] = mapped_column(Integer)
    environment: Mapped[str] = mapped_column(Text)
    cloud_instance_id: Mapped[str | None] = mapped_column(Text)
    edr_device_id: Mapped[str | None] = mapped_column(Text)
    in_change_window: Mapped[bool] = mapped_column(Boolean)
    dependents: Mapped[list[str]] = mapped_column(ARRAY(Text))
    status: Mapped[str] = mapped_column(Text)
    network_stage: Mapped[int | None] = mapped_column(SmallInteger)
    current_risk: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    severity: Mapped[int | None] = mapped_column(SmallInteger)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    src_ip: Mapped[str] = mapped_column(INET)
    hostname: Mapped[str | None] = mapped_column(Text)
    user_name: Mapped[str | None] = mapped_column("user", Text)
    process_hash: Mapped[str | None] = mapped_column(Text)
    c2_domain: Mapped[str | None] = mapped_column(Text)
    raw_payload: Mapped[dict] = mapped_column(JSONB)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    state: Mapped[str] = mapped_column(Text)
    tier: Mapped[int | None] = mapped_column(SmallInteger)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    src_ip: Mapped[str] = mapped_column(INET)
    segment: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    attack_type: Mapped[str | None] = mapped_column(Text)
    entry_path: Mapped[str | None] = mapped_column(Text)
    attack_source: Mapped[dict | None] = mapped_column(JSONB)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    level: Mapped[str | None] = mapped_column(Text)
    pending_level: Mapped[str | None] = mapped_column(Text)
    approvals_required: Mapped[int] = mapped_column(SmallInteger)
    hold_reason: Mapped[str | None] = mapped_column(Text)
    escalation_reason: Mapped[str | None] = mapped_column(Text)
    escalated_from: Mapped[str | None] = mapped_column(Text)
    fast_path: Mapped[bool] = mapped_column(Boolean)
    auto_executed: Mapped[bool] = mapped_column(Boolean)
    false_positive: Mapped[bool] = mapped_column(Boolean)
    sla_breached: Mapped[bool] = mapped_column(Boolean)
    cycle: Mapped[int] = mapped_column(SmallInteger)
    remediation_attempts: Mapped[int] = mapped_column(SmallInteger)
    network_stage: Mapped[int | None] = mapped_column(SmallInteger)
    mttc_ms: Mapped[int | None] = mapped_column(Integer)
    correlation_keys: Mapped[list[str]] = mapped_column(ARRAY(Text))
    context: Mapped[dict] = mapped_column(JSONB)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observe_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentTransition(Base):
    __tablename__ = "incident_transitions"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    from_state: Mapped[str | None] = mapped_column(Text)
    to_state: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)
    correlation_weight: Mapped[float] = mapped_column(Float)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    cycle: Mapped[int] = mapped_column(SmallInteger)
    level: Mapped[str] = mapped_column(Text)
    action_type: Mapped[str] = mapped_column(Text)
    layer: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    params: Mapped[dict] = mapped_column(JSONB)
    provider: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(SmallInteger)
    manual: Mapped[bool] = mapped_column(Boolean)
    result: Mapped[dict] = mapped_column(JSONB)
    undo: Mapped[dict] = mapped_column(JSONB)
    duration_ms: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VerificationCheck(Base):
    __tablename__ = "verification_checks"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    cycle: Mapped[int] = mapped_column(SmallInteger)
    check_name: Mapped[str] = mapped_column(Text)
    passed: Mapped[bool] = mapped_column(Boolean)
    details: Mapped[dict] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    approver: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    kind: Mapped[str] = mapped_column(Text)
    uri: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    collector: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(Text)
    chain_hash: Mapped[str] = mapped_column(Text, unique=True)
    retention_days: Mapped[int] = mapped_column(Integer)
    retention_until: Mapped[date] = mapped_column(Date)
    legal_hold: Mapped[bool] = mapped_column(Boolean)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    incident_id: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    meta: Mapped[dict] = mapped_column("metadata", JSONB)


class RiskHistory(Base):
    __tablename__ = "risk_history"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    score: Mapped[int] = mapped_column(SmallInteger)


class ResponsePattern(Base):
    __tablename__ = "response_patterns"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    fingerprint: Mapped[dict] = mapped_column(JSONB)
    level: Mapped[str] = mapped_column(Text)
    commands: Mapped[list[str]] = mapped_column(ARRAY(Text))
    status: Mapped[str] = mapped_column(Text)
    hits: Mapped[int] = mapped_column(Integer)
    occurrences: Mapped[int] = mapped_column(Integer)
    source_incident: Mapped[str | None] = mapped_column(UUID(as_uuid=False))
    notes: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class HourlyReport(Base):
    __tablename__ = "hourly_reports"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    kpis: Mapped[dict] = mapped_column(JSONB)
    body: Mapped[dict] = mapped_column(JSONB)
