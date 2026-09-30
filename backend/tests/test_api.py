"""API tests (FastAPI TestClient, in-memory store, scaled timers). Run inside the container: make test"""
import os
import time

os.environ.update({"ACRS_STORE": "memory", "ACRS_JWT_SECRET": "test-secret-" + "x" * 40,
                   "ACRS_SEED_PASSWORD": "test-password-123", "ACRS_TIME_SCALE": "0.02",
                   "ACRS_STAGE_PACING_S": "0"})
os.environ.pop("REDIS_URL", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

PW = "test-password-123"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def token(client, user):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def wait_state(client, h, iid, *states, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        inc = client.get(f"/api/v1/incidents/{iid}", headers=h).json()["incident"]
        if inc["state"] in states:
            return inc
        time.sleep(0.05)
    raise AssertionError(f"stuck in {inc['state']}")


def test_health_and_simulation_notice(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["simulation_only"] is True
    assert r.headers["X-ACRS-Mode"] == "simulation-only"


def test_auth_and_rbac(client):
    assert client.post("/api/v1/auth/login", json={"username": "analyst", "password": "nope"}).status_code == 401
    assert client.get("/api/v1/incidents").status_code == 401
    viewer = token(client, "viewer")
    assert client.get("/api/v1/assets", headers=viewer).status_code == 200
    assert len(client.get("/api/v1/assets", headers=viewer).json()) == 20
    assert client.post("/api/v1/sim/scenarios/tier1_c2_hr/run", headers=viewer).status_code == 403


def test_ingest_validation(client):
    h = token(client, "connector")
    bad = client.post("/api/v1/events/ingest", headers=h,
                      json={"events": [{"source": "carrier-pigeon", "type": "net_conn", "src_ip": "10.0.0.1"}]})
    assert bad.status_code == 422
    ok = client.post("/api/v1/events/ingest", headers=h,
                     json={"events": [{"source": "firewall", "type": "net_conn", "src_ip": "10.20.1.12",
                                       "payload": {"dest_ip": "20.1.1.1", "dest_port": 443}}]})
    assert ok.status_code == 200 and ok.json() == {"accepted": 1, "incident_ids": []}


def test_full_lifecycle_via_api(client):
    h = token(client, "analyst")
    r = client.post("/api/v1/sim/scenarios/tier2_workstation/run", headers=h, json={"mode": "success"})
    assert r.status_code == 200, r.text
    [iid] = r.json()["incident_ids"]
    inc = wait_state(client, h, iid, "CLOSE")
    assert inc["level"] == "FULL_ISOLATION"
    detail = client.get(f"/api/v1/incidents/{iid}", headers=h).json()
    assert detail["chain_ok"] is True
    assert [t["to_state"] for t in detail["transitions"]][-1] == "CLOSE"
    assert any(a["actor"] == "ACRS" for a in detail["audit"])


def test_two_person_rule_and_engineer_mode(client):
    a1, a2, eng = token(client, "analyst"), token(client, "analyst2"), token(client, "engineer")
    [iid] = client.post("/api/v1/sim/scenarios/tier0_dc_cred_dump/run", headers=a1).json()["incident_ids"]
    wait_state(client, a1, iid, "OBSERVE", "REMEDIATE", "HARDEN")
    assert client.post(f"/api/v1/incidents/{iid}/approve", headers=a1).json()["executed"] is False
    assert client.post(f"/api/v1/incidents/{iid}/approve", headers=a1).status_code == 409
    assert client.post(f"/api/v1/incidents/{iid}/approve", headers=a2).json()["executed"] is True
    assert client.post(f"/api/v1/incidents/{iid}/commands", headers=a1,
                       json={"command": "RUN_VERIFICATION"}).status_code == 403
    assert client.post(f"/api/v1/incidents/{iid}/commands", headers=eng,
                       json={"command": "RUN_VERIFICATION"}).status_code == 200


def test_emergency_queue(client):
    h = token(client, "analyst")
    [iid] = client.post("/api/v1/sim/scenarios/tier1_c2_hr/run", headers=h,
                        json={"mode": "failure"}).json()["incident_ids"]
    wait_state(client, h, iid, "ESCALATED")
    assert iid in [i["id"] for i in client.get("/api/v1/emergency-queue", headers=h).json()]


def test_websocket(client):
    h = token(client, "viewer")
    raw = h["Authorization"].split()[1]
    with client.websocket_connect(f"/ws/incidents?token={raw}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/incidents?token=bad") as ws:
            ws.receive_json()


def test_phase_b_endpoints(client):
    viewer, analyst, eng = token(client, "viewer"), token(client, "analyst"), token(client, "engineer")
    assert len(client.get("/api/v1/sim/scenarios", headers=viewer).json()) == 40
    g = client.get("/api/v1/system/guards", headers=viewer).json()["circuit_breaker"]
    assert g["limit"] >= 1 and isinstance(g["tripped"], bool)
    k = client.get("/api/v1/reports/kpis?hours=24", headers=viewer)
    assert k.status_code == 200 and "kpis" in k.json()
    assert client.post("/api/v1/reports/hourly/generate", headers=viewer).status_code == 403
    assert client.post("/api/v1/reports/hourly/generate", headers=analyst).status_code == 200
    assert len(client.get("/api/v1/reports/hourly", headers=viewer).json()) >= 1
    patterns = client.get("/api/v1/memory/patterns", headers=viewer).json()
    assert patterns["threshold"] == 0.96
    pending = [p for p in patterns["patterns"] if p["status"] == "PENDING_VALIDATION"]
    if pending:
        pid = pending[0]["id"]
        assert client.post(f"/api/v1/memory/patterns/{pid}/approve", headers=analyst).status_code == 403
        assert client.post(f"/api/v1/memory/patterns/{pid}/approve", headers=eng).json()["status"] == "APPROVED"
        assert client.post(f"/api/v1/memory/patterns/{pid}/approve", headers=eng).status_code == 409
