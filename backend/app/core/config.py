"""Runtime configuration from environment variables. No credentials are hard-coded."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    store: str
    database_url: str | None
    redis_url: str | None
    jwt_secret: str
    jwt_ttl_min: int
    cors_origins: list[str]
    time_scale: float
    stage_pacing_s: float
    ingest_rate_per_min: int
    seed_password: str | None
    demo_mode: bool


def load() -> Config:
    store = os.environ.get("ACRS_STORE", "sql").lower()
    secret = os.environ.get("ACRS_JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("ACRS_JWT_SECRET must be set and at least 32 characters (see .env.example)")
    db = os.environ.get("DATABASE_URL")
    if store == "sql" and not db:
        raise RuntimeError("ACRS_STORE=sql needs DATABASE_URL")
    return Config(
        store=store, database_url=db, redis_url=os.environ.get("REDIS_URL") or None,
        jwt_secret=secret, jwt_ttl_min=int(os.environ.get("ACRS_JWT_TTL_MIN", "480")),
        cors_origins=[o.strip() for o in os.environ.get("ACRS_CORS_ORIGINS", "http://localhost:8080").split(",") if o.strip()],
        time_scale=float(os.environ.get("ACRS_TIME_SCALE", "1")),
        stage_pacing_s=float(os.environ.get("ACRS_STAGE_PACING_S", "0.15")),
        ingest_rate_per_min=int(os.environ.get("ACRS_INGEST_RATE_PER_MIN", "600")),
        seed_password=os.environ.get("ACRS_SEED_PASSWORD") or None,
        demo_mode=os.environ.get("ACRS_DEMO_MODE", "true").lower() == "true",
    )
