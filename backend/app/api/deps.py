import uuid

from fastapi import HTTPException, Request

from ..workers.lifecycle import Orchestrator


def orch(request: Request) -> Orchestrator:
    return request.app.state.orchestrator


def store(request: Request):
    return request.app.state.store


def valid_id(incident_id: str) -> str:
    try:
        return str(uuid.UUID(incident_id))
    except ValueError:
        raise HTTPException(404, "Incident not found") from None
