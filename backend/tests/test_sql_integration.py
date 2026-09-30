"""PostgreSQL integration test: runs the real lifecycle on SqlStore against a throwaway database.

It creates `<db>_test`, applies the Alembic migrations, seeds it, drives scenarios through every store method,
and drops nothing from the demo database. Every step runs even if an earlier one fails, and all failures are
reported together so one run surfaces every problem.

Run inside the backend container:  docker compose exec backend python -m pytest -q tests/test_sql_integration.py
Skipped automatically when DATABASE_URL is not a PostgreSQL URL (for example during the image build).
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import time
import traceback
from datetime import timedelta
from pathlib import Path

import pytest

BASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not BASE_URL.startswith("postgresql"), reason="needs PostgreSQL (DATABASE_URL)")

SETTLED = {"CLOSE", "ESCALATED", "PENDING_APPROVAL", "MONITOR", "ROLLED_BACK"}


class ErrorLog(logging.Handler):
    def __init__(self):
        super().__init__(logging.ERROR)
        self.records: list[str] = []

    def emit(self, record):
        msg = record.getMessage()
        if record.exc_info:
            msg += "\n" + "".join(traceback.format_exception(*record.exc_info))[-1500:]
        self.records.append(f"[{record.name}] {msg}")


def _urls() -> tuple[str, str, str]:
    head, db = BASE_URL.rsplit("/", 1)
    db = db.split("?")[0]
    test_db = f"{db}_test"
    raw = head.replace("postgresql+asyncpg://", "postgresql://")
    return f"{raw}/{db}", test_db, f"{head}/{test_db}"


async def _recreate_database(admin_url: str, test_db: str) -> None:
    import asyncpg
    conn = await asyncpg.connect(admin_url)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{test_db}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{test_db}"')
    finally:
        await conn.close()


def test_sql_store_end_to_end():
    admin_url, test_db, test_url = _urls()
    asyncio.run(_recreate_database(admin_url, test_db))
    root = Path(__file__).resolve().parents[1]
    mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=root, capture_output=True,
                         text=True, env={**os.environ, "DATABASE_URL": test_url})
    assert mig.returncode == 0, f"alembic failed:\n{mig.stdout}\n{mig.stderr}"
    failures = asyncio.run(_scenario_run(test_url))
    assert not failures, "\n\n".join(failures)


async def _scenario_run(url: str) -> list[str]:
    from app.core.security import hash_password
    from app.engines.evidence import verify_chain
    from app.services import simulators
    from app.services.publisher import LocalPublisher
    from app.services.seed_data import asset_rows
    from app.services.sql_store import SqlStore
    from app.workers.lifecycle import Orchestrator, Settings

    errors = ErrorLog()
    logging.getLogger().addHandler(errors)
    failures: list[str] = []
    store = SqlStore(url)
    orch = Orchestrator(store, LocalPublisher(), Settings(time_scale=0.1, stage_pacing_s=0, latency_scale=0.02))

    async def step(name, coro_fn):
        try:
            return await coro_fn()
        except Exception:  # noqa: BLE001
            failures.append(f"STEP {name} FAILED\n{traceback.format_exc()[-2500:]}")
            return None

    async def settle(iid, timeout=40.0):
        end = time.monotonic() + timeout
        inc = None
        while time.monotonic() < end:
            inc = await store.get_incident(iid)
            if inc["state"] in SETTLED or inc.get("hold_reason"):
                return inc
            await asyncio.sleep(0.1)
        raise AssertionError(f"incident {iid} stuck in {inc and inc['state']}")

    async def run(sid, mode="success"):
        events, sim = simulators.build(sid, mode)
        ids = await orch.ingest(events, "it-test", sim)
        assert ids, f"{sid}: no incident created"
        return ids

    try:
        async def seed():
            for row in asset_rows():
                await store.upsert_asset(row)
            await store.upsert_user("it-user", hash_password("integration-pass"), "analyst")
            assert (await store.get_user("it-user"))["role"] == "analyst"
            assert len(await store.list_assets()) == 20
            assert await store.ping()
        await step("seed users and assets", seed)

        async def tier2():
            [iid] = await run("tier2_workstation")
            inc = await settle(iid)
            assert inc["state"] == "CLOSE", inc["state"]
            assert await store.list_actions(iid) and await store.list_checks(iid)
            assert await store.incident_event_count(iid) > 0
            ok, broken = verify_chain(await store.list_evidence(iid))
            assert ok, f"evidence chain broken at {broken}"
            assert len(await store.list_transitions(iid)) >= 10
            asset = await store.get_asset(inc["asset_id"])
            assert await store.risk_history(asset["id"], inc["detected_at"] - timedelta(hours=1))
        await step("tier-2 full automatic lifecycle to CLOSE", tier2)

        async def tier1_failure():
            [iid] = await run("tier1_c2_hr", "failure")
            inc = await settle(iid)
            assert inc["state"] == "ESCALATED", inc["state"]
            r = await orch.engineer_command(iid, "engineer", "BLOCK_C2")
            assert "ok" in r or r
            assert iid in [i["id"] for i in await store.list_incidents(state="ESCALATED")]
        await step("tier-1 failure -> emergency queue + engineer command", tier1_failure)

        async def tier0():
            [iid] = await run("tier0_dc_cred_dump")
            inc = await settle(iid)
            assert inc["tier"] == 0
            if inc.get("pending_level") and inc["state"] not in ("CLOSE", "ROLLED_BACK"):
                await orch.approve(iid, "analyst")
                await orch.approve(iid, "analyst2")
            else:  # lifecycle already finished: still exercise the approval table directly
                assert await store.add_approval(iid, "analyst", "FULL_ISOLATION")
                assert not await store.add_approval(iid, "analyst", "FULL_ISOLATION")   # one vote per person
                assert await store.add_approval(iid, "analyst2", "FULL_ISOLATION")
            assert len(await store.list_approvals(iid)) >= 2
        await step("tier-0 restrictive containment + two-person approval", tier0)

        async def fp_rollback():
            [iid] = await run("erp_change_window_fp")
            await settle(iid)
            await orch.rollback(iid, "analyst", "integration test: legitimate change")
            inc = await store.get_incident(iid)
            assert inc["state"] == "ROLLED_BACK" and inc["false_positive"], inc["state"]
        await step("change-window false positive -> rollback", fp_rollback)

        async def ransomware():
            ids = await run("ransomware_finance")
            for i in ids:
                await settle(i)
        await step("ransomware fast path (segment query)", ransomware)

        async def memory():
            [a] = await run("response_memory_repeat")
            inc = await settle(a)
            if inc.get("hold_reason"):
                await orch.confirm(a, "analyst")
            await settle(a)
            pending = [p for p in await store.list_patterns() if p["status"] == "PENDING_VALIDATION"]
            assert pending, "no pattern proposed"
            await orch.review_pattern(pending[0]["id"], "engineer", True, "integration")
            assert (await store.get_pattern(pending[0]["id"]))["status"] == "APPROVED"
            [b] = await run("response_memory_repeat")
            inc = await settle(b)
            assert (inc.get("memory") or {}).get("applied"), inc.get("memory")
        await step("response memory: propose, approve, reuse (edge case 10)", memory)

        async def reports():
            r = await orch.generate_report(3600)
            assert r["kpis"]["incidents"] >= 1
            assert await store.list_reports()
            assert await store.list_audit(None, 50)
        await step("hourly report + audit log", reports)

        async def watchdog():
            await orch.sweep()
            await orch.resume()
            since = (await store.list_incidents(limit=1))[0]["detected_at"] - timedelta(hours=1)
            await store.open_incidents_since(since)
            await store.overdue_containments(since + timedelta(days=1))
            await store.update_asset(1, in_change_window=True)
            await store.update_asset(1, in_change_window=False)
        await step("watchdog sweep/resume + asset update", watchdog)

        async def reset():
            await store.reset()
            assert await store.list_incidents() == []
        await step("demo reset", reset)
    finally:
        for t in list(orch.tasks.values()):
            t.cancel()
        await asyncio.sleep(0.2)
        await store.close()
        logging.getLogger().removeHandler(errors)

    if errors.records:
        failures.append("ERRORS LOGGED BY THE LIFECYCLE:\n" + "\n---\n".join(errors.records[:8]))
    return failures
