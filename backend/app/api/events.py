from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.security import require
from ..engines.types import Event
from ..schemas.api import IngestIn, IngestOut
from .deps import orch

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=IngestOut)
async def ingest(body: IngestIn, request: Request, user: dict = Depends(require("analyst")), o=Depends(orch)):
    allowed, remaining = await request.app.state.ratelimiter.hit(user["username"], len(body.events))
    if not allowed:
        raise HTTPException(429, "Ingest rate limit exceeded", headers={"Retry-After": "60"})
    now = datetime.now(timezone.utc)

    def ts(v):
        if v is None:
            return now
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)

    events = [Event(ts=ts(e.ts), source=e.source, event_type=e.type, src_ip=str(e.src_ip), hostname=e.hostname,
                    user=e.user, process_hash=e.process_hash, c2_domain=e.c2_domain,
                    data={**e.payload, "severity": e.severity, "event_id": e.event_id})
              for e in body.events]
    ids = await o.ingest(events, actor=user["username"])
    return IngestOut(accepted=len(events), incident_ids=ids)
