from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..core.security import current_user, require
from ..schemas.api import ChangeWindowIn
from .deps import store

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
async def list_assets(_: dict = Depends(current_user), st=Depends(store)):
    return await st.list_assets()


@router.get("/{asset_id}")
async def get_asset(asset_id: int, _: dict = Depends(current_user), st=Depends(store)):
    a = await st.get_asset(asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    incidents = [i for i in await st.list_incidents(limit=500) if i.get("asset_id") == asset_id]
    return {"asset": a, "risk_history": await st.risk_history(asset_id, since), "incidents": incidents[:20]}


@router.patch("/{asset_id}/change-window")
async def set_change_window(asset_id: int, body: ChangeWindowIn, user: dict = Depends(require("engineer")),
                            st=Depends(store)):
    if not await st.get_asset(asset_id):
        raise HTTPException(404, "Asset not found")
    await st.update_asset(asset_id, in_change_window=body.in_change_window)
    await st.audit(user["username"], "CHANGE_WINDOW_SET", str(asset_id), str(body.in_change_window))
    return {"asset_id": asset_id, "in_change_window": body.in_change_window}
