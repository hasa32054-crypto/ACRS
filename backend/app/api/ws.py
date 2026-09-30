"""WebSocket live updates. Auth: ?token=<JWT> (browsers cannot set headers on WebSocket)."""
import asyncio
import contextlib

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder

from ..core.security import decode_token

router = APIRouter()


async def _serve(ws: WebSocket, token: str | None, incident_id: str | None) -> None:
    state = ws.app.state
    try:
        decode_token(token or "", state.config.jwt_secret)
    except jwt.PyJWTError:
        await ws.close(code=4401)
        return
    await ws.accept()
    if incident_id:
        snapshot = await state.store.get_incident(incident_id)
    else:
        snapshot = await state.store.list_incidents(limit=50)
    await ws.send_json(jsonable_encoder({"type": "snapshot", "incident_id": incident_id, "data": snapshot}))

    async def pump():
        async for msg in state.publisher.subscribe():
            if incident_id is None or msg.get("incident_id") == incident_id:
                await ws.send_json(msg)

    task = asyncio.create_task(pump())
    try:
        while True:
            await ws.receive_text()  # keepalive pings from the client
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


@router.websocket("/ws/incidents")
async def ws_all(websocket: WebSocket, token: str | None = None):
    await _serve(websocket, token, None)


@router.websocket("/ws/incidents/{incident_id}")
async def ws_one(websocket: WebSocket, incident_id: str, token: str | None = None):
    await _serve(websocket, token, incident_id)
