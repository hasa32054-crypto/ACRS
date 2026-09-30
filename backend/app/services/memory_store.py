"""In-memory Store. Used by the test-suite and by ACRS_STORE=memory (run without PostgreSQL).

It implements exactly the same async interface as SqlStore, so the lifecycle
orchestrator cannot tell them apart.
"""
from __future__ import annotations

import copy
import itertools
import uuid
from datetime import datetime, timezone

from ..engines.state_machine import AUTOMATED, TERMINAL
from ..engines.types import Asset, CommandResult, Event, State
from .seed_data import asset_rows

INCIDENT_DEFAULTS = {
    "asset_id": None, "tier": None, "segment": None, "title": "", "attack_type": None, "entry_path": None,
    "entry": None, "attack_source": None, "detections": [], "mitre": [], "risk_score": None, "confidence": None,
    "risk": None, "decision": None, "level": None, "pending_level": None, "approvals_required": 0,
    "hold_reason": None, "hold_cleared": False, "escalation_reason": None, "escalated_from": None,
    "simulation": {}, "correlation_keys": [], "related_incidents": [], "cycle": 1, "remediation_attempts": 0,
    "deadline_at": None, "observe_until": None, "network_stage": None, "lessons": None, "attribution": None,
    "verification": None, "pipeline": None, "gate": None, "verified_cycle": None, "manual_override": False,
    "decided_at": None, "contained_at": None, "closed_at": None, "mttc_ms": None, "sla_breached": False,
    "false_positive": False, "auto_executed": False, "fast_path": False, "version": 1, "memory": None,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class InMemoryStore:
    def __init__(self, seed: bool = True):
        self._ids = itertools.count(1)
        self.users: dict[str, dict] = {}
        self.reset_all(seed)

    def reset_all(self, seed: bool = True) -> None:
        self.assets: dict[int, dict] = {}
        if seed:
            for r in asset_rows():
                self.assets[r["id"]] = {**r, "status": "healthy", "network_stage": None, "current_risk": 0}
        self.events: list[Event] = []
        self.incidents: dict[str, dict] = {}
        self.transitions: list[dict] = []
        self.incident_events: list[tuple[str, int, float]] = []
        self.actions: dict[str, dict] = {}
        self.checks: list[dict] = []
        self.approvals: list[dict] = []
        self.evidence: list[dict] = []
        self.audit_log: list[dict] = []
        self.risk: list[dict] = []
        if not hasattr(self, "patterns"):
            self.patterns: dict[str, dict] = {}
        self.reports: list[dict] = []

    async def reset(self) -> None:
        self.reset_all(True)

    # ------------------------------------------------------------------ users
    async def get_user(self, username: str) -> dict | None:
        return copy.deepcopy(self.users.get(username))

    async def upsert_user(self, username: str, password_hash: str, role: str) -> None:
        self.users.setdefault(username, {"id": len(self.users) + 1, "username": username,
                                         "password_hash": password_hash, "role": role})

    # ------------------------------------------------------------------ assets
    async def list_assets(self) -> list[dict]:
        return sorted(copy.deepcopy(list(self.assets.values())), key=lambda a: (a["tier"], a["hostname"]))

    async def get_asset(self, asset_id: int) -> dict | None:
        return copy.deepcopy(self.assets.get(asset_id))

    async def assets_by_ip(self) -> dict[str, Asset]:
        keys = Asset.__dataclass_fields__.keys()
        return {a["ip"]: Asset(**{k: a[k] for k in keys if k in a}) for a in self.assets.values()}

    async def update_asset(self, asset_id: int, **fields) -> None:
        if asset_id in self.assets:
            self.assets[asset_id].update(fields)

    async def record_risk(self, asset_id: int, score: int) -> None:
        self.risk.append({"asset_id": asset_id, "ts": _now(), "score": score})
        await self.update_asset(asset_id, current_risk=score)

    async def risk_history(self, asset_id: int, since: datetime) -> list[dict]:
        return [r for r in self.risk if r["asset_id"] == asset_id and r["ts"] >= since]

    # ------------------------------------------------------------------ events
    async def insert_events(self, events: list[Event]) -> list[int]:
        ids = []
        for e in events:
            e.id = next(self._ids)
            self.events.append(e)
            ids.append(e.id)
        return ids

    async def events_for_ip(self, src_ip: str, since: datetime) -> list[Event]:
        return sorted([e for e in self.events if e.src_ip == src_ip and e.ts >= since], key=lambda e: e.ts)

    async def link_events(self, iid: str, pairs: list[tuple[int, float]]) -> None:
        have = {(i, e) for i, e, _ in self.incident_events}
        for eid, w in pairs:
            if (iid, eid) not in have:
                self.incident_events.append((iid, eid, w))

    async def incident_event_count(self, iid: str) -> int:
        return sum(1 for i, _, _ in self.incident_events if i == iid)

    # ------------------------------------------------------------------ incidents
    async def create_incident(self, fields: dict) -> str:
        iid = str(uuid.uuid4())
        self.incidents[iid] = {**copy.deepcopy(INCIDENT_DEFAULTS), **fields, "id": iid, "updated_at": _now()}
        self.transitions.append({"incident_id": iid, "from_state": None, "to_state": fields["state"],
                                 "at": _now(), "actor": "ACRS", "detail": {}})
        return iid

    async def get_incident(self, iid: str) -> dict | None:
        inc = self.incidents.get(iid)
        return copy.deepcopy(inc) if inc else None

    async def update_incident(self, iid: str, **fields) -> None:
        if iid in self.incidents:
            self.incidents[iid].update(copy.deepcopy(fields))
            self.incidents[iid]["updated_at"] = _now()

    async def transition(self, iid: str, from_state: str, to_state: str, actor: str, detail: dict,
                         fields: dict) -> bool:
        inc = self.incidents.get(iid)
        if inc is None or inc["state"] != from_state:
            return False
        inc.update(copy.deepcopy(fields))
        inc["state"] = to_state
        inc["version"] += 1
        inc["updated_at"] = _now()
        self.transitions.append({"incident_id": iid, "from_state": from_state, "to_state": to_state,
                                 "at": _now(), "actor": actor, "detail": detail})
        return True

    async def list_transitions(self, iid: str) -> list[dict]:
        return [t for t in self.transitions if t["incident_id"] == iid]

    async def list_incidents(self, state: str | None = None, limit: int = 100) -> list[dict]:
        rows = [copy.deepcopy(i) for i in self.incidents.values() if state is None or i["state"] == state]
        rows.sort(key=lambda i: i["detected_at"], reverse=True)
        for r in rows:
            a = self.assets.get(r.get("asset_id")) or {}
            r["hostname"] = a.get("hostname")
        return rows[:limit]

    async def open_incidents_since(self, since: datetime) -> list[dict]:
        return [{"id": i["id"], "keys": list(i["correlation_keys"]), "last_seen": i["last_seen"]}
                for i in self.incidents.values()
                if i["state"] not in {s.value for s in TERMINAL} and i["last_seen"] >= since]

    async def count_auto_contained_since(self, since: datetime) -> int:
        terminal = {s.value for s in TERMINAL}
        return sum(1 for i in self.incidents.values() if i["auto_executed"] and not i["false_positive"]
                   and i["state"] not in terminal and i["decided_at"] and i["decided_at"] >= since)

    async def fast_path_assets_in_segment(self, segment: str, since: datetime, before: datetime,
                                          exclude_asset_id: int | None) -> int:
        return len({i["asset_id"] for i in self.incidents.values()
                    if i["fast_path"] and i["segment"] == segment and since <= i["detected_at"] < before
                    and i["asset_id"] != exclude_asset_id})

    async def overdue_containments(self, before: datetime) -> list[dict]:
        out = []
        for i in self.incidents.values():
            if i["deadline_at"] and i["deadline_at"] < before and (
                    i["state"] == State.CONTAIN.value
                    or (i["state"] == State.VERIFY.value and not i["contained_at"])):
                out.append(copy.deepcopy(i))
        return out

    async def resumable_incidents(self) -> list[str]:
        auto = {s.value for s in AUTOMATED}
        return [i["id"] for i in self.incidents.values() if i["state"] in auto and not i["hold_reason"]]

    # ------------------------------------------------------------------ actions / checks / approvals
    async def add_action(self, iid: str, cycle: int, level: str, r: CommandResult, manual: bool) -> bool:
        key = f"{iid}:{cycle}:{'manual:' + str(len(self.actions)) if manual else ''}{r.command.name}:{r.command.target}"
        if key in self.actions and self.actions[key]["status"] == "succeeded":
            return False
        self.actions[key] = {"id": str(uuid.uuid4()), "incident_id": iid, "cycle": cycle, "level": level,
                             "action_type": r.command.name, "layer": r.command.layer, "target": r.command.target,
                             "params": r.command.params, "provider": r.provider,
                             "status": "succeeded" if r.ok else "failed", "attempts": r.attempts,
                             "result": {"message": r.message}, "undo": r.undo, "manual": manual,
                             "duration_ms": r.duration_ms, "started_at": _now(), "finished_at": _now()}
        return True

    async def list_actions(self, iid: str) -> list[dict]:
        return [copy.deepcopy(a) for a in self.actions.values() if a["incident_id"] == iid]

    async def succeeded_action_names(self, iid: str, cycle: int | None, include_manual: bool = False) -> set[str]:
        return {a["action_type"] for a in self.actions.values()
                if a["incident_id"] == iid and a["status"] == "succeeded"
                and (cycle is None or a["cycle"] == cycle) and (include_manual or not a["manual"])}

    async def release_actions(self, iid: str, status: str = "released") -> int:
        n = 0
        for a in self.actions.values():
            if a["incident_id"] == iid and a["status"] == "succeeded":
                a["status"] = status
                n += 1
        return n

    async def add_checks(self, iid: str, cycle: int, checks: list[dict]) -> None:
        for c in checks:
            self.checks.append({"incident_id": iid, "cycle": cycle, "checked_at": _now(), **c})

    async def list_checks(self, iid: str) -> list[dict]:
        return [c for c in self.checks if c["incident_id"] == iid]

    async def add_approval(self, iid: str, approver: str, level: str) -> bool:
        if any(a for a in self.approvals if a["incident_id"] == iid and a["approver"] == approver
               and a["level"] == level):
            return False
        self.approvals.append({"incident_id": iid, "approver": approver, "level": level, "created_at": _now()})
        return True

    async def list_approvals(self, iid: str, level: str | None = None) -> list[dict]:
        return [a for a in self.approvals if a["incident_id"] == iid and (level is None or a["level"] == level)]

    # ------------------------------------------------------------------ evidence / audit
    async def last_chain_hash(self, iid: str) -> str | None:
        rows = [e for e in self.evidence if e["incident_id"] == iid]
        return rows[-1]["chain_hash"] if rows else None

    async def add_evidence(self, iid: str, records: list[dict]) -> None:
        self.evidence.extend({**r, "incident_id": iid} for r in records)

    async def list_evidence(self, iid: str) -> list[dict]:
        return [e for e in self.evidence if e["incident_id"] == iid]

    async def audit(self, actor: str, action: str, target: str | None, reason: str, incident_id: str | None = None,
                    metadata: dict | None = None) -> None:
        self.audit_log.append({"id": len(self.audit_log) + 1, "actor": actor, "action": action, "target": target,
                               "reason": reason, "timestamp": _now(), "incident_id": incident_id,
                               "metadata": metadata or {}})

    async def list_audit(self, incident_id: str | None = None, limit: int = 200) -> list[dict]:
        rows = [a for a in self.audit_log if incident_id is None or a["incident_id"] == incident_id]
        return rows[-limit:]

    # ------------------------------------------------------------------ response memory / reports
    async def list_patterns(self) -> list[dict]:
        return sorted(copy.deepcopy(list(self.patterns.values())), key=lambda p: p["created_at"], reverse=True)

    async def get_pattern(self, pid: str) -> dict | None:
        return copy.deepcopy(self.patterns.get(pid))

    async def create_pattern(self, fields: dict) -> str:
        pid = str(uuid.uuid4())
        self.patterns[pid] = {"id": pid, "created_at": _now(), "approved_by": None, "approved_at": None,
                              "last_used_at": None, "notes": "", **copy.deepcopy(fields)}
        return pid

    async def update_pattern(self, pid: str, **fields) -> None:
        if pid in self.patterns:
            self.patterns[pid].update(copy.deepcopy(fields))

    async def incidents_between(self, start: datetime, end: datetime) -> list[dict]:
        return [copy.deepcopy(i) for i in self.incidents.values() if start <= i["detected_at"] <= end]

    async def add_report(self, start: datetime, end: datetime, body: dict) -> int:
        rid = len(self.reports) + 1
        self.reports.append({"id": rid, "window_start": start, "window_end": end, "generated_at": _now(),
                             "kpis": body["kpis"], "body": body})
        return rid

    async def list_reports(self, limit: int = 48) -> list[dict]:
        return list(reversed(self.reports))[:limit]
