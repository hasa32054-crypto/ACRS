"""Fixed-window rate limiter for the ingest API (Redis when available, in-process otherwise). Fail-open."""
from __future__ import annotations

import logging
import time

log = logging.getLogger("acrs.ratelimit")


class RateLimiter:
    def __init__(self, per_minute: int, redis_url: str | None = None):
        self.per_minute = per_minute
        self.redis = None
        self.local: dict[str, tuple[int, int]] = {}
        if redis_url:
            import redis.asyncio as aioredis
            self.redis = aioredis.from_url(redis_url, decode_responses=True)

    async def hit(self, key: str, cost: int = 1) -> tuple[bool, int]:
        window = int(time.time() // 60)
        if self.redis is not None:
            try:
                k = f"acrs:rl:{key}:{window}"
                n = await self.redis.incrby(k, cost)
                if n == cost:
                    await self.redis.expire(k, 65)
                return n <= self.per_minute, max(0, self.per_minute - n)
            except Exception:  # noqa: BLE001
                log.warning("rate limiter unavailable, failing open", exc_info=True)
                return True, self.per_minute
        w, n = self.local.get(key, (window, 0))
        n = n + cost if w == window else cost
        self.local[key] = (window, n)
        return n <= self.per_minute, max(0, self.per_minute - n)
