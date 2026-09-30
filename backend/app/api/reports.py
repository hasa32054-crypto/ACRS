from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from ..core.security import current_user, require
from ..engines import reports as rreports
from .deps import orch, store

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/kpis")
async def kpis(hours: float = Query(24, gt=0, le=720), _: dict = Depends(current_user), st=Depends(store)):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    return rreports.build(await st.incidents_between(start, end), start, end, len(await st.list_assets()))


@router.get("/hourly")
async def hourly(limit: int = Query(48, ge=1, le=500), _: dict = Depends(current_user), st=Depends(store)):
    return await st.list_reports(limit)


@router.post("/hourly/generate")
async def generate(_: dict = Depends(require("analyst")), o=Depends(orch)):
    return await o.generate_report(3600)
