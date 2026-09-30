"""End-to-end run of both policies through the real incident lifecycle (orchestrator, controllers, verification).

    python -m research.e2e_timing

Real timers (7 / 15 / 90 s deadlines) and the simulated controllers' real latency are used. Only the decision
function differs between the two arms. Measures, per incident: time from decision to verified containment,
time from detection to containment, and where the incident stopped.
"""
from __future__ import annotations

import asyncio
import json
import statistics
from pathlib import Path

from app.engines.decision import decide as acrs_decide
from app.services import simulators
from app.services.memory_store import InMemoryStore
from app.services.publisher import LocalPublisher
from app.workers import lifecycle
from app.workers.lifecycle import Orchestrator, Settings

from research.experiment import uniform_decide

OUT = Path(__file__).parent / "results"
STOP = {"PENDING_APPROVAL", "MONITOR", "ESCALATED", "ROLLED_BACK", "CLOSE"}


async def one(sid: str, timeout: float = 40.0) -> list[dict]:
    store = InMemoryStore()
    orch = Orchestrator(store, LocalPublisher(), Settings(time_scale=1.0, stage_pacing_s=0.0, latency_scale=1.0))
    events, sim = simulators.build(sid, "success")
    ids = await orch.ingest(events, "experiment", sim)
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    rows = []
    for iid in ids:
        while loop.time() < end:
            inc = await store.get_incident(iid)
            if inc.get("contained_at") or inc["state"] in STOP or inc.get("hold_reason"):
                break
            await asyncio.sleep(0.05)
        inc = await store.get_incident(iid)
        ms = lambda a, b: round((inc[b] - inc[a]).total_seconds() * 1000) if inc.get(a) and inc.get(b) else None
        rows.append({"scenario": sid, "tier": inc.get("tier"), "level": inc.get("level"), "state": inc["state"],
                     "decide_to_contain_ms": ms("decided_at", "contained_at"),
                     "detect_to_contain_ms": ms("detected_at", "contained_at"),
                     "deadline_s": (inc.get("decision") or {}).get("deadline_s")})
    for t in orch.tasks.values():
        t.cancel()
    return rows


async def arm(policy) -> list[dict]:
    lifecycle.decide = policy
    try:
        parts = await asyncio.gather(*(one(s) for s in simulators.SCENARIOS))
    finally:
        lifecycle.decide = acrs_decide
    return [r for p in parts for r in p]


def stats(rows: list[dict]) -> dict:
    v = sorted(r["decide_to_contain_ms"] for r in rows if r["decide_to_contain_ms"] is not None)
    p95 = v[min(len(v) - 1, round(0.95 * (len(v) - 1)))] if v else None
    return {"contained": len(v), "incidents": len(rows), "median_ms": statistics.median(v) if v else None,
            "p95_ms": p95, "max_ms": max(v) if v else None,
            "within_deadline": sum(1 for r in rows if r["decide_to_contain_ms"] is not None and r["deadline_s"]
                                   and r["decide_to_contain_ms"] <= r["deadline_s"] * 1000)}


async def main() -> None:
    OUT.mkdir(exist_ok=True)
    base = await arm(uniform_decide)
    acrs = await arm(acrs_decide)
    res = {"note": "Simulated controllers with realistic latency; real 7/15/90 s deadlines.",
           "baseline": {"summary": stats(base), "rows": base}, "acrs": {"summary": stats(acrs), "rows": acrs}}
    (OUT / "e2e_timing.json").write_text(json.dumps(res, indent=1, default=str))
    print("baseline", res["baseline"]["summary"])
    print("acrs    ", res["acrs"]["summary"])


if __name__ == "__main__":
    asyncio.run(main())
