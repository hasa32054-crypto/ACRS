from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.security import current_user, require
from ..engines.memory import SIMILARITY_THRESHOLD
from ..workers.lifecycle import ActionError
from .deps import orch, store

router = APIRouter(prefix="/memory", tags=["response memory"])


class ReviewIn(BaseModel):
    note: str = Field(default="", max_length=500)


@router.get("/patterns")
async def patterns(_: dict = Depends(current_user), st=Depends(store)):
    return {"threshold": SIMILARITY_THRESHOLD, "patterns": await st.list_patterns()}


async def _review(pattern_id: str, user: dict, approve: bool, body: ReviewIn | None, o):
    try:
        return await o.review_pattern(pattern_id, user["username"], approve, (body or ReviewIn()).note)
    except ActionError as e:
        raise HTTPException(e.status, str(e)) from None


@router.post("/patterns/{pattern_id}/approve")
async def approve(pattern_id: str, body: ReviewIn | None = None, user: dict = Depends(require("engineer")),
                  o=Depends(orch)):
    """Only engineers approve patterns; approved patterns are reused at >= 96 % similarity."""
    return await _review(pattern_id, user, True, body, o)


@router.post("/patterns/{pattern_id}/reject")
async def reject(pattern_id: str, body: ReviewIn | None = None, user: dict = Depends(require("engineer")),
                 o=Depends(orch)):
    return await _review(pattern_id, user, False, body, o)
