"""ACRS API. SIMULATION ONLY - no real network operations."""
from __future__ import annotations

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .api import assets, auth, events, incidents, memory, reports, sim, system, ws
from .core import logging as acrs_logging
from .core.config import load
from .services.memory_store import InMemoryStore
from .services.publisher import LocalPublisher, RedisPublisher
from .services.ratelimit import RateLimiter
from .workers.lifecycle import Orchestrator, Settings

acrs_logging.setup()


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load()
    if config.store == "sql":
        from .services.sql_store import SqlStore
        store = SqlStore(config.database_url)
    else:
        store = InMemoryStore()
        from .seed import seed_users
        await seed_users(store, config.seed_password)
    publisher = RedisPublisher(config.redis_url) if config.redis_url else LocalPublisher()
    orchestrator = Orchestrator(store, publisher, Settings(time_scale=config.time_scale,
                                                           stage_pacing_s=config.stage_pacing_s))
    app.state.config, app.state.store, app.state.publisher = config, store, publisher
    app.state.orchestrator = orchestrator
    app.state.ratelimiter = RateLimiter(config.ingest_rate_per_min, config.redis_url)
    await orchestrator.resume()
    watchdog = asyncio.create_task(orchestrator.watchdog())
    reporter = asyncio.create_task(orchestrator.report_loop())
    try:
        yield
    finally:
        watchdog.cancel()
        reporter.cancel()
        for t in list(orchestrator.tasks.values()):
            t.cancel()
        with contextlib.suppress(Exception):
            await publisher.close()
        if hasattr(store, "close"):
            await store.close()


app = FastAPI(
    title="ACRS - Adaptive Cyber Response System",
    contact={"name": "Hassan Abdullah Alyenbawi"},
    license_info={"name": "Proprietary - All rights reserved (see LICENSE)"},
    version="2.0.0",
    description="**Simulation Only - No Real Network Operations.** "
                "Isolate the infected part, not the whole organisation.",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware,
                   allow_origins=[o.strip() for o in os.environ.get("ACRS_CORS_ORIGINS", "http://localhost:8080").split(",")],
                   allow_credentials=False, allow_methods=["GET", "POST", "PATCH"],
                   allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-ACRS-Mode"] = "simulation-only"
    return response


for r in (auth.router, events.router, incidents.router, assets.router, sim.router, system.router, memory.router,
          reports.router):
    app.include_router(r, prefix="/api/v1")
app.include_router(ws.router)
