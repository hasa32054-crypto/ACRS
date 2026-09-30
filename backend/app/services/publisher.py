"""Live update fan-out for WebSockets.

LocalPublisher  in-process queues (tests, single worker, no Redis)
RedisPublisher  Redis pub/sub, so several API workers share one event stream

Publishing is fail-open: a broken Redis never blocks containment.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator

log = logging.getLogger("acrs.publisher")
CHANNEL = "acrs:events"


class LocalPublisher:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue] = set()
        self.history: list[dict] = []

    async def publish(self, message: dict) -> None:
        self.history.append(message)
        del self.history[:-500]
        for q in list(self._subs):
            if q.full():
                continue
            q.put_nowait(message)

    async def subscribe(self) -> AsyncIterator[dict]:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subs.discard(q)

    async def close(self) -> None:
        self._subs.clear()


class RedisPublisher:
    def __init__(self, url: str) -> None:
        import redis.asyncio as aioredis  # lazy: only needed when Redis is configured
        self.redis = aioredis.from_url(url, decode_responses=True)

    async def publish(self, message: dict) -> None:
        try:
            await self.redis.publish(CHANNEL, json.dumps(message, default=str))
        except Exception:  # noqa: BLE001
            log.warning("redis publish failed (fail-open)", exc_info=True)

    async def subscribe(self) -> AsyncIterator[dict]:
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(CHANNEL)
        try:
            async for msg in pubsub.listen():
                if msg.get("type") == "message":
                    yield json.loads(msg["data"])
        finally:
            await pubsub.unsubscribe(CHANNEL)
            await pubsub.aclose()

    async def ping(self) -> bool:
        try:
            return bool(await self.redis.ping())
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        await self.redis.aclose()
