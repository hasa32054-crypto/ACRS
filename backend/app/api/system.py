import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..core.security import ROLES, current_user, require
from ..engines import policy
from ..engines.state_machine import MAIN_PATH
from .deps import store

router = APIRouter(tags=["system"])


@router.get("/health")
async def health(request: Request):
    st = request.app.state
    db = "memory"
    if hasattr(st.store, "ping"):
        try:
            await asyncio.wait_for(st.store.ping(), 2)
            db = "ok"
        except Exception:  # noqa: BLE001
            db = "down"
    redis = "disabled"
    if hasattr(st.publisher, "ping"):
        redis = "ok" if await st.publisher.ping() else "down"
    return {"status": "ok" if db != "down" else "degraded", "database": db, "redis": redis,
            "simulation_only": True, "notice": "Simulation Only - No Real Network Operations",
            "active_runners": sum(1 for t in st.orchestrator.tasks.values() if not t.done())}


@router.get("/system/policy")
async def get_policy(_: dict = Depends(current_user)):
    return {"tier_policy": policy.TIER_POLICY, "observation_window_s": policy.OBSERVATION_WINDOW_S,
            "medium_floor": policy.MEDIUM_FLOOR, "min_auto_confidence": policy.MIN_AUTO_CONFIDENCE,
            "risk_weights": policy.RISK_WEIGHTS, "confidence_weights": policy.CONFIDENCE_WEIGHTS,
            "circuit_breaker_max": policy.CIRCUIT_BREAKER_MAX, "roles": ROLES,
            "state_machine": [s.value for s in MAIN_PATH]}


@router.get("/system/guards")
async def guards(_: dict = Depends(current_user), st=Depends(store)):
    """Circuit breaker status, so the console can explain why new incidents wait for a human."""
    from datetime import datetime, timedelta, timezone

    from ..engines.policy import CIRCUIT_BREAKER_MAX
    count = await st.count_auto_contained_since(datetime.now(timezone.utc) - timedelta(minutes=10))
    return {"circuit_breaker": {"open_auto_containments": count, "limit": CIRCUIT_BREAKER_MAX, "window_min": 10,
                                "tripped": count >= CIRCUIT_BREAKER_MAX}}


@router.get("/audit")
async def audit(limit: int = Query(200, ge=1, le=1000), incident_id: str | None = None,
                _: dict = Depends(require("analyst")), st=Depends(store)):
    return await st.list_audit(incident_id, limit)


@router.post("/system/reset")
async def reset(request: Request, user: dict = Depends(require("admin"))):
    st = request.app.state
    if not st.config.demo_mode:
        raise HTTPException(403, "Reset is only available in demo mode")
    for t in list(st.orchestrator.tasks.values()):
        t.cancel()
    st.orchestrator.tasks.clear()
    await st.store.reset()
    await st.store.audit(user["username"], "DEMO_RESET", None, "all incidents cleared")
    return {"reset": True}
