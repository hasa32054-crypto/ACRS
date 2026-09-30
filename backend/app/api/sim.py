from fastapi import APIRouter, Depends, HTTPException

from ..core.security import current_user, require
from ..schemas.api import SimRunIn
from ..services import simulators
from .deps import orch

router = APIRouter(prefix="/sim", tags=["simulation"])


@router.get("/scenarios")
async def scenarios(_: dict = Depends(current_user)):
    return [{"id": k, "category": v["category"], "title_ar": v["title_ar"], "title_en": v["title_en"],
             "default_failure": v["failure"] or "integration_down", "edge_case": v["edge"],
             "target": simulators.target(k)} for k, v in simulators.SCENARIOS.items()]


@router.post("/scenarios/{scenario_id}/run")
async def run(scenario_id: str, body: SimRunIn | None = None, user: dict = Depends(require("analyst")),
              o=Depends(orch)):
    """Attack Simulation Lab: synthetic telemetry only. No real network operation takes place."""
    if scenario_id not in simulators.SCENARIOS:
        raise HTTPException(404, "Unknown scenario")
    body = body or SimRunIn()
    events, profile = simulators.build(scenario_id, body.mode, body.failure)
    await o.store.audit(user["username"], "SIMULATION_STARTED", scenario_id, body.mode, metadata=profile)
    ids = await o.ingest(events, actor=user["username"], simulation=profile)
    return {"scenario": scenario_id, "mode": body.mode, "failure": profile["failure"], "events": len(events),
            "incident_ids": ids}
