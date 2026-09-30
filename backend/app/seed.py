"""Idempotent seed: 20 CMDB assets + demo users. Run: python -m app.seed

Passwords come from ACRS_SEED_PASSWORD. Nothing is hard-coded.
"""
from __future__ import annotations

import asyncio
import logging
import os

from .core.security import hash_password
from .services.seed_data import asset_rows

log = logging.getLogger("acrs.seed")

USERS = [("admin", "admin"), ("engineer", "engineer"), ("analyst", "analyst"), ("analyst2", "analyst"),
         ("viewer", "viewer"), ("connector", "analyst")]


async def seed_users(store, password: str | None) -> None:
    if not password or len(password) < 10:
        raise RuntimeError("ACRS_SEED_PASSWORD must be set (10+ characters)")
    for username, role in USERS:
        await store.upsert_user(username, hash_password(password), role)


async def main() -> None:
    from .services.sql_store import SqlStore
    store = SqlStore(os.environ["DATABASE_URL"])
    try:
        for row in asset_rows():
            await store.upsert_asset(row)
        await seed_users(store, os.environ.get("ACRS_SEED_PASSWORD"))
        print(f"seed: {len(asset_rows())} assets, {len(USERS)} users (idempotent)")
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(main())
