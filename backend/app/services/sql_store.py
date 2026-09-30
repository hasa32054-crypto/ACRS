"""PostgreSQL Store (SQLAlchemy 2.x async + asyncpg).

Same interface as InMemoryStore. Incident fields that are not first-class
columns live in the `context` JSONB column; transitions are compare-and-set on
`state`, so concurrent human actions and the runner can never both win.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any

from sqlalchemy import and_, cast, delete, func, literal, or_, select, text, update as _update
from sqlalchemy.dialects.postgresql import INET, JSONB, insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ..db.models import (Approval, AssetRow, AuditLog, EventRow, Evidence, HourlyReport, IncidentEvent, IncidentRow,
                         IncidentTransition, ResponseAction, ResponsePattern, RiskHistory, User, VerificationCheck)
from ..engines.state_machine import AUTOMATED, TERMINAL
from ..engines.types import Asset, CommandResult, Event, State

INCIDENT_COLUMNS = {c.name for c in IncidentRow.__table__.columns} - {"id", "context", "version", "updated_at"}
ASSET_KEYS = set(Asset.__dataclass_fields__.keys())
TERMINAL_VALUES = [s.value for s in TERMINAL]
AUTOMATED_VALUES = [s.value for s in AUTOMATED]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ip(v: Any) -> str | None:
    return None if v is None else str(v).split("/")[0]


def _inet(v: str) -> str:
    """Validate an IP and bind it as text: asyncpg's INET codec expects str, not ipaddress objects."""
    return str(ipaddress.ip_address(str(v).split("/")[0]))


def _json(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_json(v) for v in obj]
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    return obj


def update(model):
    """ORM-enabled UPDATE without session synchronisation (we never rely on identity-map state)."""
    return _update(model).execution_options(synchronize_session=False)


def _row(obj) -> dict:
    return {c.key: getattr(obj, c.key) for c in obj.__mapper__.column_attrs}


class SqlStore:
    def __init__(self, url: str, echo: bool = False):
        self.engine = create_async_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10, echo=echo)
        self.sm = async_sessionmaker(self.engine, expire_on_commit=False)

    async def close(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> bool:
        async with self.sm() as s:
            await s.execute(text("SELECT 1"))
        return True

    # ------------------------------------------------------------------ users
    async def get_user(self, username: str) -> dict | None:
        async with self.sm() as s:
            u = (await s.execute(select(User).where(User.username == username))).scalar_one_or_none()
            return _row(u) if u else None

    async def upsert_user(self, username: str, password_hash: str, role: str) -> None:
        async with self.sm() as s, s.begin():
            await s.execute(pg_insert(User).values(username=username, password_hash=password_hash, role=role,
                                                   created_at=_now()).on_conflict_do_nothing(index_elements=["username"]))

    # ------------------------------------------------------------------ assets
    @staticmethod
    def _asset_dict(a: AssetRow) -> dict:
        d = _row(a)
        d["ip"] = _ip(d["ip"])
        d["dependents"] = list(d["dependents"] or [])
        return d

    async def list_assets(self) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(AssetRow).order_by(AssetRow.tier, AssetRow.hostname))).scalars().all()
            return [self._asset_dict(a) for a in rows]

    async def get_asset(self, asset_id: int) -> dict | None:
        async with self.sm() as s:
            a = await s.get(AssetRow, asset_id)
            return self._asset_dict(a) if a else None

    async def assets_by_ip(self) -> dict[str, Asset]:
        return {a["ip"]: Asset(**{k: v for k, v in a.items() if k in ASSET_KEYS}) for a in await self.list_assets()}

    async def update_asset(self, asset_id: int, **fields) -> None:
        async with self.sm() as s, s.begin():
            await s.execute(update(AssetRow).where(AssetRow.id == asset_id).values(**fields))

    async def upsert_asset(self, row: dict) -> None:
        values = {k: v for k, v in row.items() if k != "id"}
        values["ip"] = _inet(values["ip"])
        async with self.sm() as s, s.begin():
            await s.execute(pg_insert(AssetRow).values(**values, status="healthy", current_risk=0,
                                                       created_at=_now(), updated_at=_now())
                            .on_conflict_do_nothing(index_elements=["hostname"]))

    async def record_risk(self, asset_id: int, score: int) -> None:
        async with self.sm() as s, s.begin():
            s.add(RiskHistory(asset_id=asset_id, score=score, ts=_now()))
            await s.execute(update(AssetRow).where(AssetRow.id == asset_id).values(current_risk=score))

    async def risk_history(self, asset_id: int, since: datetime) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(RiskHistory).where(RiskHistory.asset_id == asset_id, RiskHistory.ts >= since)
                                    .order_by(RiskHistory.ts))).scalars().all()
            return [{"ts": r.ts, "score": r.score} for r in rows]

    # ------------------------------------------------------------------ events
    async def insert_events(self, events: list[Event]) -> list[int]:
        if not events:
            return []
        by_ip = {a.ip: a.id for a in (await self.assets_by_ip()).values()}
        rows = [{"ts": e.ts, "source": e.source, "type": e.event_type, "severity": e.data.get("severity"),
                 "asset_id": by_ip.get(e.src_ip), "src_ip": _inet(e.src_ip), "hostname": e.hostname,
                 "user_name": e.user, "process_hash": e.process_hash, "c2_domain": e.c2_domain,
                 "raw_payload": _json(e.data), "ingested_at": _now()} for e in events]
        async with self.sm() as s, s.begin():
            ids = (await s.execute(pg_insert(EventRow).returning(EventRow.id, sort_by_parameter_order=True), rows)).scalars().all()
        for e, i in zip(events, ids):
            e.id = i
        return list(ids)

    async def events_for_ip(self, src_ip: str, since: datetime) -> list[Event]:
        async with self.sm() as s:
            rows = (await s.execute(select(EventRow).where(EventRow.src_ip == cast(_inet(src_ip), INET), EventRow.ts >= since)
                                    .order_by(EventRow.ts))).scalars().all()
            return [Event(ts=r.ts, source=r.source, event_type=r.type, src_ip=_ip(r.src_ip), hostname=r.hostname,
                          user=r.user_name, process_hash=r.process_hash, c2_domain=r.c2_domain,
                          data=r.raw_payload or {}, id=r.id) for r in rows]

    async def link_events(self, iid: str, pairs: list[tuple[int, float]]) -> None:
        if not pairs:
            return
        async with self.sm() as s, s.begin():
            await s.execute(pg_insert(IncidentEvent).values(
                [{"incident_id": iid, "event_id": e, "correlation_weight": w} for e, w in pairs]
            ).on_conflict_do_nothing())

    async def incident_event_count(self, iid: str) -> int:
        async with self.sm() as s:
            return (await s.execute(select(func.count()).select_from(IncidentEvent)
                                    .where(IncidentEvent.incident_id == iid))).scalar_one()

    # ------------------------------------------------------------------ incidents
    @staticmethod
    def _split(fields: dict) -> tuple[dict, dict]:
        cols, ctx = {}, {}
        for k, v in fields.items():
            (cols if k in INCIDENT_COLUMNS else ctx)[k] = v
        if "src_ip" in cols and isinstance(cols["src_ip"], str):
            cols["src_ip"] = _inet(cols["src_ip"])
        if "correlation_keys" in cols:
            cols["correlation_keys"] = sorted(cols["correlation_keys"])
        if "attack_source" in cols:
            cols["attack_source"] = _json(cols["attack_source"])
        return cols, _json(ctx)

    @staticmethod
    def _inc_dict(r: IncidentRow, hostname: str | None = None) -> dict:
        d = _row(r)
        ctx = d.pop("context") or {}
        d = {**ctx, **d}
        d["src_ip"] = _ip(d["src_ip"])
        d["correlation_keys"] = list(d.get("correlation_keys") or [])
        d.setdefault("detections", [])
        d.setdefault("simulation", {})
        if hostname is not None:
            d["hostname"] = hostname
        return d

    # The ORM sends NULL for any column it is not given (it ignores database DEFAULTs), so every
    # NOT NULL column without a value from the caller gets an explicit default here.
    INCIDENT_DEFAULTS = {"approvals_required": 0, "fast_path": False, "auto_executed": False, "false_positive": False,
                         "sla_breached": False, "cycle": 1, "remediation_attempts": 0, "correlation_keys": []}

    async def create_incident(self, fields: dict) -> str:
        iid = str(uuid.uuid4())
        cols, ctx = self._split({**self.INCIDENT_DEFAULTS, **fields})
        async with self.sm() as s, s.begin():
            s.add(IncidentRow(id=iid, context=ctx, version=1, updated_at=_now(), **cols))
            await s.flush()
            s.add(IncidentTransition(incident_id=iid, from_state=None, to_state=fields["state"], actor="ACRS",
                                     detail={}, at=_now()))
        return iid

    async def get_incident(self, iid: str) -> dict | None:
        async with self.sm() as s:
            r = await s.get(IncidentRow, iid)
            return self._inc_dict(r) if r else None

    async def update_incident(self, iid: str, **fields) -> None:
        cols, ctx = self._split(fields)
        values: dict[str, Any] = dict(cols)
        if ctx:
            values["context"] = IncidentRow.context.op("||")(literal(ctx, JSONB))
        if not values:
            return
        async with self.sm() as s, s.begin():
            await s.execute(update(IncidentRow).where(IncidentRow.id == iid).values(**values))

    async def transition(self, iid: str, from_state: str, to_state: str, actor: str, detail: dict,
                         fields: dict) -> bool:
        cols, ctx = self._split(fields)
        values: dict[str, Any] = {**cols, "state": to_state, "version": IncidentRow.version + 1}
        if ctx:
            values["context"] = IncidentRow.context.op("||")(literal(ctx, JSONB))
        async with self.sm() as s, s.begin():
            res = await s.execute(update(IncidentRow)
                                  .where(IncidentRow.id == iid, IncidentRow.state == from_state).values(**values))
            if res.rowcount != 1:
                return False
            s.add(IncidentTransition(incident_id=iid, from_state=from_state, to_state=to_state, actor=actor,
                                     detail=_json(detail), at=_now()))
        return True

    async def list_transitions(self, iid: str) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(IncidentTransition).where(IncidentTransition.incident_id == iid)
                                    .order_by(IncidentTransition.id))).scalars().all()
            return [{k: v for k, v in _row(r).items() if k != "id"} for r in rows]

    async def list_incidents(self, state: str | None = None, limit: int = 100) -> list[dict]:
        stmt = (select(IncidentRow, AssetRow.hostname).outerjoin(AssetRow, AssetRow.id == IncidentRow.asset_id)
                .order_by(IncidentRow.detected_at.desc()).limit(limit))
        if state:
            stmt = stmt.where(IncidentRow.state == state)
        async with self.sm() as s:
            return [self._inc_dict(r, h) for r, h in (await s.execute(stmt)).all()]

    async def open_incidents_since(self, since: datetime) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(IncidentRow.id, IncidentRow.correlation_keys, IncidentRow.last_seen)
                                    .where(IncidentRow.state.not_in(TERMINAL_VALUES),
                                           IncidentRow.last_seen >= since))).all()
            return [{"id": str(i), "keys": list(k or []), "last_seen": ls} for i, k, ls in rows]

    async def count_auto_contained_since(self, since: datetime) -> int:
        async with self.sm() as s:
            return (await s.execute(select(func.count()).select_from(IncidentRow).where(
                IncidentRow.auto_executed.is_(True), IncidentRow.false_positive.is_(False),
                IncidentRow.state.not_in(TERMINAL_VALUES), IncidentRow.decided_at >= since))).scalar_one()

    async def fast_path_assets_in_segment(self, segment: str, since: datetime, before: datetime,
                                          exclude_asset_id: int | None) -> int:
        async with self.sm() as s:
            return (await s.execute(select(func.count(func.distinct(IncidentRow.asset_id))).where(
                IncidentRow.fast_path.is_(True), IncidentRow.segment == segment,
                IncidentRow.detected_at >= since, IncidentRow.detected_at < before,
                IncidentRow.asset_id.is_distinct_from(exclude_asset_id)))).scalar_one()

    async def overdue_containments(self, before: datetime) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(IncidentRow).where(
                IncidentRow.deadline_at < before,
                or_(IncidentRow.state == State.CONTAIN.value,
                    and_(IncidentRow.state == State.VERIFY.value, IncidentRow.contained_at.is_(None)))))).scalars().all()
            return [self._inc_dict(r) for r in rows]

    async def resumable_incidents(self) -> list[str]:
        async with self.sm() as s:
            rows = (await s.execute(select(IncidentRow.id).where(IncidentRow.state.in_(AUTOMATED_VALUES),
                                                                 IncidentRow.hold_reason.is_(None)))).scalars().all()
            return [str(r) for r in rows]

    # ------------------------------------------------------------------ actions
    async def add_action(self, iid: str, cycle: int, level: str, r: CommandResult, manual: bool) -> bool:
        key = (f"{iid}:{cycle}:manual:{uuid.uuid4()}:{r.command.name}" if manual
               else f"{iid}:{cycle}:{r.command.name}:{r.command.target}")
        values = {"id": str(uuid.uuid4()), "incident_id": iid, "cycle": cycle, "level": level,
                  "action_type": r.command.name, "layer": r.command.layer, "target": r.command.target,
                  "params": _json(r.command.params), "provider": r.provider,
                  "status": "succeeded" if r.ok else "failed", "attempts": r.attempts, "manual": manual,
                  "result": {"message": r.message}, "undo": _json(r.undo), "duration_ms": r.duration_ms,
                  "idempotency_key": key, "started_at": _now(), "finished_at": _now()}
        stmt = pg_insert(ResponseAction).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["idempotency_key"],
            set_={k: stmt.excluded[k] for k in ("status", "attempts", "result", "undo", "duration_ms", "finished_at")},
            where=ResponseAction.status != "succeeded")
        async with self.sm() as s, s.begin():
            res = await s.execute(stmt)
        return res.rowcount == 1

    async def list_actions(self, iid: str) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(ResponseAction).where(ResponseAction.incident_id == iid)
                                    .order_by(ResponseAction.started_at))).scalars().all()
            return [_row(r) for r in rows]

    async def succeeded_action_names(self, iid: str, cycle: int | None, include_manual: bool = False) -> set[str]:
        conds = [ResponseAction.incident_id == iid, ResponseAction.status == "succeeded"]
        if cycle is not None:
            conds.append(ResponseAction.cycle == cycle)
        if not include_manual:
            conds.append(ResponseAction.manual.is_(False))
        async with self.sm() as s:
            return set((await s.execute(select(ResponseAction.action_type).where(*conds))).scalars().all())

    async def release_actions(self, iid: str, status: str = "released") -> int:
        async with self.sm() as s, s.begin():
            res = await s.execute(update(ResponseAction).where(ResponseAction.incident_id == iid,
                                                               ResponseAction.status == "succeeded")
                                  .values(status=status, finished_at=_now()))
            return res.rowcount

    # ------------------------------------------------------------------ checks / approvals
    async def add_checks(self, iid: str, cycle: int, checks: list[dict]) -> None:
        async with self.sm() as s, s.begin():
            s.add_all([VerificationCheck(incident_id=iid, cycle=cycle, check_name=c["check_name"],
                                         passed=bool(c["passed"]), details=_json(c.get("details", {})),
                                         checked_at=_now()) for c in checks])

    async def list_checks(self, iid: str) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(VerificationCheck).where(VerificationCheck.incident_id == iid)
                                    .order_by(VerificationCheck.id))).scalars().all()
            return [_row(r) for r in rows]

    async def add_approval(self, iid: str, approver: str, level: str) -> bool:
        async with self.sm() as s, s.begin():
            res = await s.execute(pg_insert(Approval).values(incident_id=iid, approver=approver, level=level,
                                                             created_at=_now()).on_conflict_do_nothing())
            return res.rowcount == 1

    async def list_approvals(self, iid: str, level: str | None = None) -> list[dict]:
        stmt = select(Approval).where(Approval.incident_id == iid).order_by(Approval.id)
        if level:
            stmt = stmt.where(Approval.level == level)
        async with self.sm() as s:
            return [{k: v for k, v in _row(r).items() if k != "id"} for r in (await s.execute(stmt)).scalars().all()]

    # ------------------------------------------------------------------ evidence / audit
    async def last_chain_hash(self, iid: str) -> str | None:
        async with self.sm() as s:
            return (await s.execute(select(Evidence.chain_hash).where(Evidence.incident_id == iid)
                                    .order_by(Evidence.id.desc()).limit(1))).scalar_one_or_none()

    async def add_evidence(self, iid: str, records: list[dict]) -> None:
        today = _now().date()
        async with self.sm() as s, s.begin():
            s.add_all([Evidence(incident_id=iid, kind=r["kind"], uri=r["uri"], sha256=r["sha256"],
                                size_bytes=r["size_bytes"], collector=r["collector"], actor=r["actor"],
                                collected_at=r["collected_at"], prev_hash=r["prev_hash"], chain_hash=r["chain_hash"],
                                retention_days=r["retention_days"],
                                retention_until=today + timedelta(days=r["retention_days"]), legal_hold=False)
                       for r in records])

    async def list_evidence(self, iid: str) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(Evidence).where(Evidence.incident_id == iid).order_by(Evidence.id)))\
                .scalars().all()
            return [_row(r) for r in rows]

    async def audit(self, actor: str, action: str, target: str | None, reason: str, incident_id: str | None = None,
                    metadata: dict | None = None) -> None:
        async with self.sm() as s, s.begin():
            s.add(AuditLog(actor=actor, action=action, target=target, reason=reason, timestamp=_now(),
                           incident_id=incident_id, meta=_json(metadata or {})))

    async def list_audit(self, incident_id: str | None = None, limit: int = 200) -> list[dict]:
        stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if incident_id:
            stmt = select(AuditLog).where(AuditLog.incident_id == incident_id).order_by(AuditLog.id).limit(limit)
        async with self.sm() as s:
            out = []
            for r in (await s.execute(stmt)).scalars().all():
                d = _row(r)
                d["metadata"] = d.pop("meta")
                out.append(d)
            return out

    # ------------------------------------------------------------------ response memory / reports
    async def list_patterns(self) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(ResponsePattern).order_by(ResponsePattern.created_at.desc()))).scalars().all()
            return [{**_row(r), "commands": list(r.commands or [])} for r in rows]

    async def get_pattern(self, pid: str) -> dict | None:
        async with self.sm() as s:
            r = await s.get(ResponsePattern, pid)
            return {**_row(r), "commands": list(r.commands or [])} if r else None

    async def create_pattern(self, fields: dict) -> str:
        pid = str(uuid.uuid4())
        async with self.sm() as s, s.begin():
            s.add(ResponsePattern(id=pid, fingerprint=_json(fields["fingerprint"]), level=fields["level"],
                                  commands=list(fields.get("commands") or []), status=fields["status"],
                                  hits=int(fields.get("hits", 0)), occurrences=int(fields.get("occurrences", 1)),
                                  source_incident=fields.get("source_incident"), notes=fields.get("notes", ""),
                                  created_at=_now()))
        return pid

    async def update_pattern(self, pid: str, **fields) -> None:
        async with self.sm() as s, s.begin():
            await s.execute(update(ResponsePattern).where(ResponsePattern.id == pid).values(**fields))

    async def incidents_between(self, start: datetime, end: datetime) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(IncidentRow).where(IncidentRow.detected_at >= start,
                                                              IncidentRow.detected_at <= end))).scalars().all()
            return [self._inc_dict(r) for r in rows]

    async def add_report(self, start: datetime, end: datetime, body: dict) -> int:
        async with self.sm() as s, s.begin():
            r = HourlyReport(window_start=start, window_end=end, generated_at=_now(), kpis=_json(body["kpis"]),
                             body=_json(body))
            s.add(r)
            await s.flush()
            return r.id

    async def list_reports(self, limit: int = 48) -> list[dict]:
        async with self.sm() as s:
            rows = (await s.execute(select(HourlyReport).order_by(HourlyReport.id.desc()).limit(limit))).scalars().all()
            return [_row(r) for r in rows]

    # ------------------------------------------------------------------ demo
    async def reset(self) -> None:
        """Demo only: TRUNCATE bypasses the row-level append-only triggers by design."""
        async with self.sm() as s, s.begin():
            await s.execute(text("TRUNCATE incident_events, incident_transitions, response_actions, "
                                 "verification_checks, approvals, evidence, audit_logs, risk_history, incidents, "
                                 "events RESTART IDENTITY CASCADE"))
            await s.execute(update(AssetRow).values(status="healthy", network_stage=None, current_risk=0))
            await s.execute(update(AssetRow).where(AssetRow.hostname == "ERP-PROD-01").values(in_change_window=True))


__all__ = ["SqlStore", "AsyncSession", "delete"]
