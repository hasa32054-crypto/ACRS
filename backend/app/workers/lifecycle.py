"""Incident lifecycle orchestrator.

DETECT -> UNDERSTAND -> IDENTIFY_ENTRY -> ATTRIBUTE_ASSET -> RISK -> DECIDE -> CONTAIN -> VERIFY
-> REMEDIATE -> HARDEN -> OBSERVE -> RE_ENTRY -> LEARN -> CLOSE

The runner is state-driven: it reads the incident's current state from the store,
runs that state's handler, and records the transition atomically (compare-and-set
on the current state). If a human changes the state meanwhile (rollback, approval),
the compare-and-set fails and the runner stops. This also makes runners resumable
after a restart.

This module depends only on the engines, a Store and a Publisher (stdlib only).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

from ..engines import state_machine as sm
from ..engines.correlation import correlation_weight, keys_for, match_incident
from ..engines.decision import decide
from ..engines.detection import detect
from ..engines.entry import attack_source, classify, identify_entry
from ..engines import memory as rmem
from ..engines import reports as rreports
from ..engines.evidence import GENESIS, collect, verify_chain
from ..engines.policy import (CIRCUIT_BREAKER_WINDOW_S, CORRELATION_WINDOW_S, DETECTION_LOOKBACK_S,
                              MAX_CONTAINMENT_CYCLES, MAX_REMEDIATION_ATTEMPTS, OBSERVATION_CHECKS,
                              OBSERVATION_WINDOW_S, REENTRY_DWELL_S, RETRY_INTERVAL_S, SEGMENT_RESTRICT_WINDOW_S)
from ..engines.recovery import FAILURE_STAGE, REENTRY_STAGES, gate, observation_check, run_pipeline
from ..engines.response import (ENGINEER_COMMANDS, FAILURE_PROFILES, ResponseEngine, SimulatedController,
                                plan, plan_hardening, verify_containment)
from ..engines.risk import assess, attribute
from ..engines.types import (Asset, Attribution, Command, CommandResult, Detection, Event, Factor, Level,
                             RiskAssessment, State)

log = logging.getLogger("acrs.lifecycle")

ASSET_STATUS = {
    Level.RESTRICT: "restricted", Level.EMERGENCY_RESTRICT: "restricted", Level.COMPENSATING: "restricted",
    Level.SURGICAL: "quarantined", Level.FULL_ISOLATION: "isolated",
}
APPROVABLE_STATES = {State.PENDING_APPROVAL, State.MONITOR, State.CONTAIN, State.VERIFY, State.REMEDIATE,
                     State.HARDEN, State.OBSERVE, State.ESCALATED}


class ActionError(Exception):
    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


class Publisher(Protocol):
    async def publish(self, message: dict) -> None: ...


def now() -> datetime:
    return datetime.now(timezone.utc)


def jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return jsonable(asdict(obj))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in obj]
    return obj


@dataclass
class Settings:
    time_scale: float = 1.0          # multiplies every timer (tests use a tiny value)
    stage_pacing_s: float = 0.15     # visible pacing of analysis stages; 5 stages stay < 1 s
    latency_scale: float = 1.0       # simulated controller latency
    pipeline_stage_s: float = 0.3


class Orchestrator:
    def __init__(self, store, publisher: Publisher, settings: Settings | None = None, controller=None):
        self.store = store
        self.pub = publisher
        self.s = settings or Settings()
        self.engine = ResponseEngine(controller or SimulatedController(self.s.latency_scale),
                                     retry_interval_s=RETRY_INTERVAL_S * self.s.time_scale)
        self.tasks: dict[str, asyncio.Task] = {}
        self._ip_locks: dict[str, asyncio.Lock] = {}
        self.handlers = {
            State.DETECT: self._detect, State.UNDERSTAND: self._understand,
            State.IDENTIFY_ENTRY: self._identify_entry, State.ATTRIBUTE_ASSET: self._attribute,
            State.RISK: self._risk, State.DECIDE: self._decide, State.CONTAIN: self._contain,
            State.VERIFY: self._verify, State.REMEDIATE: self._remediate, State.HARDEN: self._harden,
            State.OBSERVE: self._observe, State.RE_ENTRY: self._re_entry, State.LEARN: self._learn,
        }

    # ------------------------------------------------------------------ helpers
    def t(self, seconds: float) -> float:
        return seconds * self.s.time_scale

    async def emit(self, kind: str, incident_id: str | None, **payload) -> None:
        try:
            await self.pub.publish(jsonable({"type": kind, "incident_id": incident_id, "at": now(), **payload}))
        except Exception:  # noqa: BLE001 – live updates must never block containment
            log.warning("publish failed", exc_info=True)

    async def _asset(self, inc: dict) -> Asset:
        if inc.get("asset_id"):
            row = await self.store.get_asset(inc["asset_id"])
            if row:
                return asset_from_row(row)
        ip = inc["src_ip"]
        return Asset(id=0, hostname=f"unknown-{ip}", ip=ip, tier=2, role="unknown", segment="unknown",
                     owner="unassigned", criticality="medium")

    @staticmethod
    def _detections(inc: dict) -> list[Detection]:
        return [Detection(**d) for d in inc.get("detections") or []]

    async def _events(self, inc: dict) -> list[Event]:
        return await self.store.events_for_ip(inc["src_ip"], now() - timedelta(seconds=DETECTION_LOOKBACK_S))

    async def _move(self, inc: dict, to: State, fields: dict | None = None, detail: dict | None = None,
                    actor: str = "ACRS") -> bool:
        frm = State(inc["state"])
        sm.check(frm, to)
        fields = jsonable(fields or {})
        for k in ("contained_at", "closed_at", "decided_at", "deadline_at", "observe_until"):
            if k in (fields or {}) and isinstance(fields[k], str):
                fields[k] = datetime.fromisoformat(fields[k])
        ok = await self.store.transition(inc["id"], frm.value, to.value, actor, jsonable(detail or {}), fields)
        if ok:
            await self.emit("state", inc["id"], state=to.value, previous=frm.value, detail=jsonable(detail or {}),
                            fields={k: v for k, v in fields.items() if k in ("level", "pending_level", "deadline_at",
                                                                            "risk_score", "confidence", "hold_reason",
                                                                            "escalation_reason", "network_stage")})
        return ok

    async def _escalate(self, inc: dict, reason: str, frm: str | None = None) -> tuple:
        await self.store.audit("ACRS", "ESCALATED_TO_EMERGENCY_QUEUE", inc.get("src_ip"), reason, inc["id"],
                               {"from": frm or inc["state"]})
        await self.emit("emergency", inc["id"], reason=reason)
        return (State.ESCALATED, {"escalation_reason": reason, "escalated_from": frm or inc["state"],
                                  "sla_breached": True}, {"reason": reason})

    # ------------------------------------------------------------------ ingest
    async def ingest(self, events: list[Event], actor: str = "ingest", simulation: dict | None = None) -> list[str]:
        await self.store.insert_events(events)
        result: list[str] = []
        for ip in sorted({e.src_ip for e in events}):
            lock = self._ip_locks.setdefault(ip, asyncio.Lock())
            async with lock:
                iid = await self._process_ip(ip, [e for e in events if e.src_ip == ip], actor, simulation)
            if iid and iid not in result:
                result.append(iid)
        return result

    async def _process_ip(self, ip: str, new_events: list[Event], actor: str, simulation: dict | None) -> str | None:
        t0 = now()
        window = await self.store.events_for_ip(ip, t0 - timedelta(seconds=DETECTION_LOOKBACK_S))
        detections = detect(window)
        if not detections:
            return None
        assets = await self.store.assets_by_ip()
        asset = assets.get(ip)
        keys = keys_for(new_events, detections, asset.id if asset else None)
        open_incs = await self.store.open_incidents_since(t0 - timedelta(seconds=CORRELATION_WINDOW_S))
        merge, related = match_incident(keys, open_incs, t0)
        fast = any(d.fast_path for d in detections)
        if merge:
            existing = await self.store.get_incident(merge)
            if existing and not (fast and not existing.get("fast_path")):
                await self.store.link_events(merge, [(e.id, correlation_weight(e, detections)) for e in new_events if e.id])
                await self.store.update_incident(merge, last_seen=t0,
                                                 correlation_keys=sorted(set(existing.get("correlation_keys") or []) | keys))
                await self.store.audit(actor, "EVENTS_CORRELATED", ip, "shared correlation key inside 5 min window",
                                       merge, {"events": len(new_events)})
                await self.emit("correlated", merge, events=len(new_events))
                return merge
        recent = [e for e in window if (window[-1].ts - e.ts).total_seconds() <= 3600]
        top = max(detections, key=lambda d: d.strength)
        iid = await self.store.create_incident({
            "state": State.DETECT.value, "src_ip": ip, "asset_id": asset.id if asset else None,
            "tier": asset.tier if asset else None, "segment": asset.segment if asset else None,
            "title": f"{top.title} on {asset.hostname if asset else ip}",
            "detections": jsonable(detections), "fast_path": fast, "correlation_keys": sorted(keys),
            "related_incidents": related, "simulation": simulation or {},
            "started_at": min(e.ts for e in recent), "detected_at": t0, "last_seen": t0,
            "cycle": 1, "remediation_attempts": 0,
        })
        await self.store.link_events(iid, [(e.id, correlation_weight(e, detections)) for e in window if e.id])
        await self.store.audit("ACRS", "INCIDENT_DETECTED", ip, top.title, iid,
                               {"rules": sorted({d.rule_id for d in detections}), "simulation": simulation or {}})
        await self.emit("state", iid, state=State.DETECT.value, previous=None, detail={"detections": len(detections)})
        self.spawn(iid)
        return iid

    # ------------------------------------------------------------------ runner
    def spawn(self, iid: str) -> None:
        task = self.tasks.get(iid)
        if task and not task.done():
            return
        self.tasks[iid] = asyncio.create_task(self.run(iid), name=f"incident-{iid}")

    async def run(self, iid: str) -> None:
        try:
            while True:
                inc = await self.store.get_incident(iid)
                if inc is None or inc.get("hold_reason"):
                    return
                handler = self.handlers.get(State(inc["state"]))
                if handler is None:
                    return
                step = await handler(inc)
                if step is None:
                    return
                nxt, fields, detail = step
                fresh = await self.store.get_incident(iid)
                if fresh is None or fresh["state"] != inc["state"]:
                    return  # a human moved it meanwhile
                if not await self._move(fresh, nxt, fields, detail):
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("runner failed for %s", iid)
            inc = await self.store.get_incident(iid)
            if inc and sm.can(inc["state"], State.ESCALATED):
                step = await self._escalate(inc, f"Internal error in {inc['state']}: {exc}")
                await self._move(inc, *step)
        finally:
            current = self.tasks.get(iid)
            if current is asyncio.current_task():
                self.tasks.pop(iid, None)

    async def pace(self) -> None:
        await asyncio.sleep(self.s.stage_pacing_s)

    # ------------------------------------------------------------------ analysis stages
    async def _detect(self, inc):
        await self.pace()
        dets = self._detections(inc)
        return State.UNDERSTAND, {"attack_type": classify(dets)}, {
            "detections": len(dets), "rules": sorted({d.rule_id for d in dets})}

    async def _understand(self, inc):
        await self.pace()
        dets = self._detections(inc)
        mitre = sorted({t for d in dets for t in d.mitre})
        return State.IDENTIFY_ENTRY, {"mitre": mitre}, {
            "attack_type": inc.get("attack_type"), "mitre": mitre,
            "correlation_keys": len(inc.get("correlation_keys") or []),
            "related_incidents": inc.get("related_incidents") or []}

    async def _identify_entry(self, inc):
        await self.pace()
        entry = identify_entry(await self._events(inc), self._detections(inc))
        return State.ATTRIBUTE_ASSET, {"entry": entry, "entry_path": entry["path"]}, {"entry_path": entry["path"]}

    async def _attribute(self, inc):
        await self.pace()
        events = await self._events(inc)
        attr = attribute(inc["src_ip"], events, await self.store.assets_by_ip())
        fields = {"attribution": {"ok": attr.ok, "conflict": attr.conflict, "notes": attr.notes}}
        if attr.asset:
            fields.update(asset_id=attr.asset.id, tier=attr.asset.tier, segment=attr.asset.segment)
        return State.RISK, fields, {"asset": attr.asset.hostname if attr.asset else None, "notes": attr.notes}

    async def _risk(self, inc):
        await self.pace()
        events = await self._events(inc)
        asset = await self._asset(inc) if inc.get("asset_id") else None
        dets = self._detections(inc)
        ra = assess(dets, asset, events, bool((inc.get("attribution") or {}).get("conflict")))
        if asset:
            await self.store.record_risk(asset.id, ra.risk)
        src = attack_source(events, dets, ra.confidence, inc.get("entry_path") or "unknown")
        return State.DECIDE, {"risk_score": ra.risk, "confidence": ra.confidence, "risk": jsonable(ra),
                              "attack_source": src}, {"risk": ra.risk, "confidence": ra.confidence}

    async def _decide(self, inc):
        t0 = now()
        asset = await self._asset(inc)
        dets = self._detections(inc)
        attribution = (inc.get("attribution") or {})
        r = inc.get("risk") or {}
        ra = RiskAssessment(risk=inc["risk_score"], confidence=inc["confidence"],
                            risk_factors=[Factor(**f) for f in r.get("risk_factors", [])],
                            confidence_factors=[Factor(**f) for f in r.get("confidence_factors", [])],
                            adjustments=r.get("adjustments", {}), distinct_sources=r.get("distinct_sources", 0),
                            blast_radius=r.get("blast_radius", {}))
        attr = Attribution(asset if inc.get("asset_id") else None, bool(attribution.get("ok")),
                           bool(attribution.get("conflict")), attribution.get("notes", []))
        recent_auto = await self.store.count_auto_contained_since(t0 - timedelta(seconds=CIRCUIT_BREAKER_WINDOW_S))
        seg_hits = 0
        if inc.get("fast_path") and inc.get("segment"):
            seg_hits = await self.store.fast_path_assets_in_segment(
                inc["segment"], t0 - timedelta(seconds=SEGMENT_RESTRICT_WINDOW_S), inc["detected_at"], inc.get("asset_id"))
        d = decide(attr, ra, dets, recent_auto, seg_hits)
        mem = await self._memory_lookup(inc, asset, d)
        if mem.get("applied"):
            d.hold_after_verify = None
            d.reasons.append(f"Response Memory: approved pattern {mem['pattern_id'][:8]} "
                             f"matched at {mem['score'] * 100:.1f}% (no confirmation pause)")
        fields: dict[str, Any] = {"decision": jsonable(d), "decided_at": t0, "level": d.level.value, "memory": mem}
        pending = d.escalation_level if (d.approvals_required and d.escalation_level) else None
        if d.auto_execute and d.level != Level.MONITOR:
            deadline = t0 + timedelta(seconds=self.t(d.deadline_s))
            fields.update(auto_executed=True, deadline_at=deadline, pending_level=pending.value if pending else None,
                          approvals_required=d.approvals_required if pending else 0)
            await self.emit("timer", inc["id"], timer="containment", seconds=self.t(d.deadline_s), deadline_at=deadline)
            return State.CONTAIN, fields, {"level": d.level.value, "reasons": d.reasons}
        if d.level != Level.MONITOR:
            fields.update(pending_level=d.level.value, approvals_required=max(1, d.approvals_required))
            return State.PENDING_APPROVAL, fields, {"level": d.level.value, "reasons": d.reasons}
        fields.update(pending_level=pending.value if pending else None,
                      approvals_required=d.approvals_required if pending else 0)
        return State.MONITOR, fields, {"reasons": d.reasons}

    async def _memory_lookup(self, inc: dict, asset: Asset, d) -> dict:
        fp = rmem.fingerprint({**inc, "level": d.level.value}, asset.role, asset.environment)
        pattern, score = rmem.best_match(fp, await self.store.list_patterns())
        if pattern is None:
            return {"applied": False, "best_score": score}
        ok, reason = rmem.may_apply(pattern, jsonable(d), inc.get("tier"))
        if ok:
            await self.store.update_pattern(pattern["id"], hits=int(pattern.get("hits") or 0) + 1, last_used_at=now())
            await self.store.audit("ACRS", "RESPONSE_PATTERN_APPLIED", inc["src_ip"], reason, inc["id"],
                                   {"pattern_id": pattern["id"], "similarity": score})
            await self.emit("result", inc["id"], banner="RESPONSE_PATTERN_APPLIED", pattern_id=pattern["id"],
                            similarity=score)
        return {"applied": ok, "pattern_id": pattern["id"], "score": score, "reason": reason}

    # ------------------------------------------------------------------ containment
    async def _contain(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        level = Level(inc["level"])
        asset = await self._asset(inc)
        dets = self._detections(inc)
        seg = bool((inc.get("decision") or {}).get("segment_restrict"))
        done = await self.store.succeeded_action_names(iid, cycle)
        cmds = [c for c in plan(level, asset, dets, seg) if c.name not in done]
        sim = inc.get("simulation") or {}
        failing = frozenset() if inc.get("manual_override") else frozenset(FAILURE_PROFILES.get(sim.get("failure"), set()))
        deadline_at = inc.get("deadline_at") or (now() + timedelta(seconds=self.t(15)))
        deadline_mono = time.monotonic() + max(0.0, (deadline_at - now()).total_seconds())

        async def on_result(r: CommandResult) -> None:
            await self.store.add_action(iid, cycle, level.value, r, manual=False)
            await self.store.audit("ACRS", r.command.name, r.command.target,
                                   f"containment {level.value}: {r.message}", iid,
                                   {"result": "success" if r.ok else "failed", "attempts": r.attempts,
                                    "layer": r.command.layer, "params": jsonable(r.command.params)})
            await self.emit("command", iid, command=r.command.name, target=r.command.target, ok=r.ok,
                            attempts=r.attempts, duration_ms=r.duration_ms)

        prev_chain = await self.store.last_chain_hash(iid) or GENESIS
        results, evidence = await asyncio.gather(
            self.engine.execute(cmds, deadline_mono, failing, on_result),
            asyncio.to_thread(collect, iid, asset, level, await self._events(inc), dets, prev_chain, "ACRS"),
        )
        await self.store.add_evidence(iid, evidence)
        failed = [r for r in results if not r.ok and r.command.critical]
        if failed:
            return await self._escalate(
                inc, f"Isolation controller unavailable: {', '.join(r.command.name for r in failed)} "
                     f"not applied within the {self._deadline_label(inc)} deadline", "CONTAIN")
        if asset.id:
            await self.store.update_asset(asset.id, status=ASSET_STATUS.get(level, "restricted"), network_stage=0)
        return State.VERIFY, {}, {"commands": len(results), "level": level.value}

    def _deadline_label(self, inc: dict) -> str:
        d = (inc.get("decision") or {}).get("deadline_s")
        return f"{d:g}s" if d else "tier"

    async def _verify(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        if inc.get("contained_at") and inc.get("verified_cycle") == cycle:
            return State.REMEDIATE, {}, {"resumed": True}
        level = Level(inc["level"])
        asset = await self._asset(inc)
        succeeded = await self.store.succeeded_action_names(iid, cycle, include_manual=True)
        probes = verify_containment(level, succeeded, asset)
        await self.store.add_checks(iid, cycle, [{"check_name": f"probe:{p['probe']}", "passed": p["pass"],
                                                  "details": p} for p in probes])
        if not all(p["pass"] for p in probes):
            return await self._escalate(inc, "Containment probes failed after enforcement", "VERIFY")
        t = now()
        fields: dict[str, Any] = {"verification": probes, "verified_cycle": cycle}
        if not inc.get("contained_at"):
            base = inc.get("decided_at") or t
            fields.update(contained_at=t, mttc_ms=int((t - base).total_seconds() * 1000))
        await self.emit("result", iid, banner="THREAT_CONTAINED", level=level.value, mttc_ms=fields.get("mttc_ms"))
        hold = (inc.get("decision") or {}).get("hold_after_verify") if cycle == 1 and not inc.get("hold_cleared") else None
        if hold:
            await self.store.update_incident(iid, hold_reason=hold, **fields)
            await self.store.audit("ACRS", "AWAITING_CONFIRMATION", inc["src_ip"], hold, iid, {})
            await self.emit("hold", iid, reason=hold)
            return None
        return State.REMEDIATE, fields, {"probes": len(probes)}

    # ------------------------------------------------------------------ recovery
    async def _remediate(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        attempt = int(inc.get("remediation_attempts") or 0) + 1
        asset = await self._asset(inc)
        if asset.id:
            await self.store.update_asset(asset.id, status="remediating")
        sim = inc.get("simulation") or {}
        fail_stage = None if inc.get("manual_override") else FAILURE_STAGE.get(sim.get("failure"))
        await self.emit("progress", iid, stage="REMEDIATE", attempt=attempt)
        pipeline = await run_pipeline(asset, self._detections(inc), fail_stage, self.t(self.s.pipeline_stage_s) or 0)
        chain_ok, _ = verify_chain(await self.store.list_evidence(iid))
        g = gate(pipeline, chain_ok)
        await self.store.add_checks(iid, cycle, [{"check_name": f"gate:{i['check']}", "passed": i["passed"],
                                                  "details": {"description": i["description"], "attempt": attempt}}
                                                 for i in g["items"]])
        fields = {"remediation_attempts": attempt, "pipeline": pipeline, "gate": g}
        if g["passed"]:
            return State.HARDEN, fields, {"gate": "passed", "attempt": attempt}
        failed = [i["check"] for i in g["items"] if not i["passed"]]
        if attempt < MAX_REMEDIATION_ATTEMPTS:
            await self.store.audit("ACRS", "VERIFICATION_GATE_FAILED", inc["src_ip"], f"retrying: {failed}", iid, {})
            return State.REMEDIATE, fields, {"gate": "failed", "failed_checks": failed, "retry": True}
        await self.store.update_incident(iid, **fields)
        return await self._escalate(inc, f"Verification Gate failed {attempt} times: {', '.join(failed)}", "REMEDIATE")

    async def _harden(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        asset = await self._asset(inc)
        entry = inc.get("entry") or {"path": "unknown", "vector": "unknown", "harden": {}}
        results = await self.engine.execute(plan_hardening(asset, entry), time.monotonic() + 30)
        for r in results:
            await self.store.add_action(iid, cycle, "HARDEN", r, manual=False)
            await self.store.audit("ACRS", r.command.name, r.command.target, f"harden entry: {entry.get('path')}",
                                   iid, {"result": "success" if r.ok else "failed", "params": jsonable(r.command.params)})
        await self.emit("result", iid, banner="ENTRY_POINT_HARDENED", entry_path=entry.get("path"))
        until = now() + timedelta(seconds=self.t(OBSERVATION_WINDOW_S))
        await self.emit("timer", iid, timer="observation", seconds=self.t(OBSERVATION_WINDOW_S), deadline_at=until)
        return State.OBSERVE, {"observe_until": until}, {"entry_path": entry.get("path")}

    async def _observe(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        sim = inc.get("simulation") or {}
        inject = sim.get("failure") == "ioc_return" and cycle == 1 and not inc.get("manual_override")
        interval = self.t(OBSERVATION_WINDOW_S) / OBSERVATION_CHECKS
        for i in range(OBSERVATION_CHECKS):
            await asyncio.sleep(interval)
            cur = await self.store.get_incident(iid)
            if cur is None or cur["state"] != State.OBSERVE.value:
                return None
            c = observation_check(i, inject)
            await self.store.add_checks(iid, cycle, [{"check_name": f"observe:{c['check']}", "passed": c["clean"],
                                                      "details": c}])
            await self.emit("observation", iid, **c)
            if not c["clean"]:
                if cycle >= MAX_CONTAINMENT_CYCLES:
                    return await self._escalate(inc, f"IoB returned again after {cycle} cycles", "OBSERVE")
                await self.store.audit("ACRS", "IOB_DURING_OBSERVATION", inc["src_ip"], c["finding"], iid,
                                       {"action": "kept in isolation, remediation restarted"})
                return State.REMEDIATE, {"cycle": cycle + 1, "remediation_attempts": 0}, {"iob": c["finding"]}
        return State.RE_ENTRY, {"network_stage": 0}, {"observation": "clean"}

    async def _re_entry(self, inc):
        iid, cycle = inc["id"], inc.get("cycle", 1)
        asset = await self._asset(inc)
        for stage in range(1, len(REENTRY_STAGES)):
            await asyncio.sleep(self.t(REENTRY_DWELL_S))
            cur = await self.store.get_incident(iid)
            if cur is None or cur["state"] != State.RE_ENTRY.value:
                return None
            cmd = Command("SET_NETWORK_STAGE", "network", asset.hostname, {"stage": REENTRY_STAGES[stage]})
            [r] = await self.engine.execute([cmd], time.monotonic() + 30)
            await self.store.add_action(iid, cycle, "RE_ENTRY", r, manual=False)
            if asset.id:
                await self.store.update_asset(asset.id, status="reentry", network_stage=stage)
            await self.store.update_incident(iid, network_stage=stage)
            await self.emit("reentry", iid, stage=stage, name=REENTRY_STAGES[stage])
        await self._undo_all(iid, "released")
        if asset.id:
            await self.store.update_asset(asset.id, status="healthy", network_stage=None)
            await self.store.record_risk(asset.id, 15)  # Zero Trust: starts elevated, decays with posture checks
        return State.LEARN, {}, {"network": "Full"}

    async def _learn(self, inc):
        await self.pace()
        lessons = {
            "attack_type": inc.get("attack_type"), "entry_path": inc.get("entry_path"), "level": inc.get("level"),
            "mttc_ms": inc.get("mttc_ms"), "cycles": inc.get("cycle"),
            "commands": sorted({a["action_type"] for a in await self.store.list_actions(inc["id"])
                                if a["status"] in ("succeeded", "released")}),
        }
        asset = await self._asset(inc)
        fp = rmem.fingerprint(inc, asset.role, asset.environment)
        existing, score = rmem.best_match(fp, await self.store.list_patterns(), approved_only=False)
        if existing:
            await self.store.update_pattern(existing["id"], occurrences=int(existing.get("occurrences") or 1) + 1)
            lessons["pattern"] = {"id": existing["id"], "status": existing["status"], "similarity": score}
        elif inc.get("tier") != 0 and inc.get("asset_id"):
            pid = await self.store.create_pattern({
                "fingerprint": fp, "level": inc.get("level"), "commands": lessons["commands"],
                "status": "PENDING_VALIDATION", "source_incident": inc["id"], "hits": 0, "occurrences": 1})
            lessons["pattern"] = {"id": pid, "status": "PENDING_VALIDATION"}
            await self.store.audit("ACRS", "RESPONSE_PATTERN_SAVED", inc["src_ip"],
                                   "awaiting engineer validation", inc["id"], {"pattern_id": pid})
            await self.emit("result", inc["id"], banner="RESPONSE_PATTERN_SAVED", pattern_id=pid)
        await self.emit("result", inc["id"], banner="THREAT_NEUTRALIZED")
        return State.CLOSE, {"lessons": lessons, "closed_at": now()}, {"lessons": lessons}

    # ------------------------------------------------------------------ human actions
    async def approve(self, iid: str, who: str) -> dict:
        inc = await self._require(iid)
        pending = inc.get("pending_level")
        if not pending:
            raise ActionError("Nothing is waiting for approval on this incident")
        if State(inc["state"]) not in APPROVABLE_STATES:
            raise ActionError(f"Approval is not possible in state {inc['state']}")
        if not await self.store.add_approval(iid, who, pending):
            raise ActionError(f"{who} already approved {pending}: a different approver is required")
        count = len(await self.store.list_approvals(iid, pending))
        required = max(1, int(inc.get("approvals_required") or 1))
        await self.store.audit(who, "APPROVAL_RECORDED", inc["src_ip"], f"{pending} {count}/{required}", iid, {})
        await self.emit("approval", iid, level=pending, approvals=count, required=required)
        if count < required:
            return {"executed": False, "approvals": count, "required": required}
        level = Level(pending)
        if State(inc["state"]) in (State.PENDING_APPROVAL, State.MONITOR):
            t0 = now()
            deadline = t0 + timedelta(seconds=self.t((inc.get("decision") or {}).get("deadline_s") or 15))
            await self._move(inc, State.CONTAIN, {"level": level.value, "pending_level": None, "approvals_required": 0,
                                                  "decided_at": t0, "deadline_at": deadline}, {"approved_by": who}, who)
            await self.emit("timer", iid, timer="containment", seconds=(deadline - t0).total_seconds(),
                            deadline_at=deadline)
            self.spawn(iid)
            return {"executed": True, "level": level.value}
        # Escalation on an incident that is already contained: apply the extra commands now.
        asset = await self._asset(inc)
        cycle = inc.get("cycle", 1)
        done = await self.store.succeeded_action_names(iid, cycle, include_manual=True)
        cmds = [c for c in plan(level, asset, self._detections(inc)) if c.name not in done]
        results = await self.engine.execute(cmds, time.monotonic() + 30)
        for r in results:
            await self.store.add_action(iid, cycle, level.value, r, manual=True)
            await self.store.audit(who, r.command.name, r.command.target, f"approved escalation to {level.value}",
                                   iid, {"result": "success" if r.ok else "failed"})
        if asset.id:
            await self.store.update_asset(asset.id, status=ASSET_STATUS.get(level, "isolated"))
        await self.store.update_incident(iid, level=level.value, pending_level=None, approvals_required=0,
                                         hold_reason=None, hold_cleared=True)
        if State(inc["state"]) == State.VERIFY:
            self.spawn(iid)
        return {"executed": True, "level": level.value, "commands": len(results)}

    async def confirm(self, iid: str, who: str) -> dict:
        inc = await self._require(iid)
        if not inc.get("hold_reason"):
            raise ActionError("Automation is not paused on this incident")
        await self.store.update_incident(iid, hold_reason=None, hold_cleared=True)
        await self.store.audit(who, "AUTOMATION_CONFIRMED", inc["src_ip"], inc["hold_reason"], iid, {})
        await self.emit("hold_cleared", iid, by=who)
        self.spawn(iid)
        return {"resumed": True}

    async def rollback(self, iid: str, who: str, reason: str) -> dict:
        inc = await self._require(iid)
        if State(inc["state"]) in sm.TERMINAL:
            raise ActionError("Incident is already closed or rolled back")
        task = self.tasks.pop(iid, None)
        if task and not task.done():
            task.cancel()
        t0 = time.monotonic()
        undone = await self._undo_all(iid, "rolled_back")
        await self._move(inc, State.ROLLED_BACK, {"false_positive": True, "closed_at": now(), "hold_reason": None,
                                                 "pending_level": None}, {"reason": reason}, who)
        if inc.get("asset_id"):
            await self.store.update_asset(inc["asset_id"], status="healthy", network_stage=None)
            await self.store.record_risk(inc["asset_id"], 10)
        ms = int((time.monotonic() - t0) * 1000)
        await self.store.audit(who, "FALSE_POSITIVE_ROLLBACK", inc["src_ip"], reason, iid,
                               {"actions_undone": undone, "rollback_ms": ms,
                                "rules_for_tuning": sorted({d["rule_id"] for d in inc.get("detections") or []})})
        return {"actions_undone": undone, "rollback_ms": ms}

    async def engineer_command(self, iid: str, who: str, command: str) -> dict:
        if command not in ENGINEER_COMMANDS:
            raise ActionError(f"Unknown command {command}", 422)
        inc = await self._require(iid)
        if State(inc["state"]) in sm.TERMINAL:
            raise ActionError("Incident is closed")
        cycle = inc.get("cycle", 1)
        asset = await self._asset(inc)
        level = Level(inc.get("level") or Level.SURGICAL.value)
        if command == "RUN_VERIFICATION":
            return await self._engineer_verify(inc, who, asset, level)
        template = next((c for c in plan(Level.SURGICAL, asset, self._detections(inc)) if c.name == command), None)
        cmd = template or Command(command, "network", asset.hostname, {})
        [r] = await self.engine.execute([cmd], time.monotonic() + 30)  # manual path: no injected outage
        await self.store.add_action(iid, cycle, "MANUAL", r, manual=True)
        await self.store.audit(who, command, cmd.target, "Engineer Mode command", iid,
                               {"result": "success" if r.ok else "failed"})
        await self.emit("command", iid, command=command, target=cmd.target, ok=r.ok, manual=True, by=who)
        return {"command": command, "ok": r.ok, "message": r.message}

    async def _engineer_verify(self, inc: dict, who: str, asset: Asset, level: Level) -> dict:
        iid, cycle = inc["id"], inc.get("cycle", 1)
        succeeded = await self.store.succeeded_action_names(iid, cycle, include_manual=True)
        probes = verify_containment(level, succeeded, asset)
        passed = all(p["pass"] for p in probes)
        await self.store.audit(who, "RUN_VERIFICATION", inc["src_ip"], "passed" if passed else "failed", iid,
                               {"probes": probes})
        if State(inc["state"]) != State.ESCALATED:
            return {"passed": passed, "probes": probes}
        frm = inc.get("escalated_from")
        if frm in (State.CONTAIN.value, State.VERIFY.value):
            if not passed:
                return {"passed": False, "probes": probes, "hint": "apply ISOLATE_ASSET first"}
            await self._move(inc, State.VERIFY, {"manual_override": True, "escalation_reason": None}, {"by": who}, who)
        else:
            await self._move(inc, State.REMEDIATE, {"manual_override": True, "remediation_attempts": 0,
                                                    "escalation_reason": None}, {"by": who}, who)
        self.spawn(iid)
        return {"passed": passed, "probes": probes, "resumed": True}

    async def _undo_all(self, iid: str, status: str) -> int:
        """Replay undo records in reverse order through the controllers, then mark the actions."""
        rows = [a for a in await self.store.list_actions(iid) if a["status"] == "succeeded"]
        results = [CommandResult(Command(a["action_type"], a["layer"], a["target"], a.get("params") or {}),
                                 True, 1, 0, a.get("provider") or "", "", a.get("undo") or {}) for a in rows]
        await self.engine.undo(results)
        return await self.store.release_actions(iid, status=status)

    async def _require(self, iid: str) -> dict:
        inc = await self.store.get_incident(iid)
        if not inc:
            raise ActionError("Incident not found", 404)
        return inc

    # ------------------------------------------------------------------ watchdog
    async def sweep(self) -> int:
        """Escalate incidents whose containment deadline passed with no live runner (e.g. after a crash)."""
        n = 0
        for inc in await self.store.overdue_containments(now() - timedelta(seconds=2)):
            if inc["id"] in self.tasks and not self.tasks[inc["id"]].done():
                continue
            step = await self._escalate(inc, "Containment deadline exceeded (no active runner)", inc["state"])
            if await self._move(inc, *step):
                n += 1
        return n

    async def resume(self) -> int:
        n = 0
        for iid in await self.store.resumable_incidents():
            self.spawn(iid)
            n += 1
        return n

    async def generate_report(self, window_s: float = 3600) -> dict:
        end = now()
        start = end - timedelta(seconds=window_s)
        body = rreports.build(await self.store.incidents_between(start, end), start, end,
                              len(await self.store.list_assets()))
        rid = await self.store.add_report(start, end, body)
        await self.emit("report", None, report_id=rid, kpis=body["kpis"])
        return {"id": rid, **body}

    async def report_loop(self) -> None:
        interval = max(5.0, self.t(3600))
        while True:
            await asyncio.sleep(interval)
            try:
                await self.generate_report(interval)
            except Exception:  # noqa: BLE001
                log.warning("hourly report failed", exc_info=True)

    async def review_pattern(self, pattern_id: str, who: str, approve: bool, note: str = "") -> dict:
        p = await self.store.get_pattern(pattern_id)
        if not p:
            raise ActionError("Pattern not found", 404)
        if p["status"] != "PENDING_VALIDATION":
            raise ActionError(f"Pattern is already {p['status']}")
        status = "APPROVED" if approve else "REJECTED"
        await self.store.update_pattern(pattern_id, status=status, approved_by=who, approved_at=now(), notes=note)
        await self.store.audit(who, f"RESPONSE_PATTERN_{status}", pattern_id, note or status,
                               p.get("source_incident"), {"level": p["level"]})
        await self.emit("pattern", None, pattern_id=pattern_id, status=status)
        return {"id": pattern_id, "status": status}

    async def watchdog(self, interval_s: float = 1.0) -> None:
        while True:
            try:
                await self.sweep()
            except Exception:  # noqa: BLE001
                log.warning("sweep failed", exc_info=True)
            await asyncio.sleep(interval_s)


def asset_from_row(row: dict) -> Asset:
    keys = Asset.__dataclass_fields__.keys()
    return Asset(**{k: row[k] for k in keys if k in row})
