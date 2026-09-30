from fastapi import APIRouter, Depends, HTTPException, Query

from ..core.security import current_user, require
from ..engines.evidence import verify_chain
from ..schemas.api import CommandIn, IncidentSummary, RollbackIn
from ..workers.lifecycle import ActionError
from .deps import orch, store, valid_id

router = APIRouter(tags=["incidents"])


def _guard(exc: ActionError):
    raise HTTPException(exc.status, str(exc))


@router.get("/incidents", response_model=list[IncidentSummary])
async def list_incidents(state: str | None = None, limit: int = Query(100, ge=1, le=500),
                         _: dict = Depends(current_user), st=Depends(store)):
    return await st.list_incidents(state=state, limit=limit)


@router.get("/emergency-queue", response_model=list[IncidentSummary])
async def emergency_queue(_: dict = Depends(current_user), st=Depends(store)):
    """Incidents ACRS could not finish on its own: the only place a human is required."""
    return await st.list_incidents(state="ESCALATED", limit=200)


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, _: dict = Depends(current_user), st=Depends(store)):
    iid = valid_id(incident_id)
    inc = await st.get_incident(iid)
    if not inc:
        raise HTTPException(404, "Incident not found")
    evidence = await st.list_evidence(iid)
    ok, broken = verify_chain(evidence)
    asset = await st.get_asset(inc["asset_id"]) if inc.get("asset_id") else None
    return {
        "incident": inc, "asset": asset,
        "transitions": await st.list_transitions(iid),
        "actions": await st.list_actions(iid),
        "checks": await st.list_checks(iid),
        "approvals": await st.list_approvals(iid),
        "evidence": evidence, "chain_ok": ok, "chain_broken_at": broken,
        "event_count": await st.incident_event_count(iid),
        "audit": await st.list_audit(iid),
    }


@router.post("/incidents/{incident_id}/approve")
async def approve(incident_id: str, user: dict = Depends(require("analyst")), o=Depends(orch)):
    try:
        return await o.approve(valid_id(incident_id), user["username"])
    except ActionError as e:
        _guard(e)


@router.post("/incidents/{incident_id}/confirm")
async def confirm(incident_id: str, user: dict = Depends(require("analyst")), o=Depends(orch)):
    try:
        return await o.confirm(valid_id(incident_id), user["username"])
    except ActionError as e:
        _guard(e)


@router.post("/incidents/{incident_id}/rollback")
async def rollback(incident_id: str, body: RollbackIn, user: dict = Depends(require("analyst")), o=Depends(orch)):
    try:
        return await o.rollback(valid_id(incident_id), user["username"], body.reason)
    except ActionError as e:
        _guard(e)


@router.post("/incidents/{incident_id}/commands")
async def engineer_command(incident_id: str, body: CommandIn, user: dict = Depends(require("engineer")),
                           o=Depends(orch)):
    """Engineer Mode: ISOLATE_ASSET, BLOCK_C2, PROTECT_DATABASE, REVOKE_SESSION, RUN_VERIFICATION."""
    try:
        return await o.engineer_command(valid_id(incident_id), user["username"], body.command)
    except ActionError as e:
        _guard(e)
