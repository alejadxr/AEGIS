"""
Redis Streams event pipeline with in-memory fallback.

Provides sub-5ms event publishing with optional Redis persistence.
When Redis is unavailable, gracefully degrades to asyncio.Queue.

Supported streams:
  - security_events
  - scan_events
  - honeypot_events
  - action_events
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger("aegis.event_stream")

# ---------------------------------------------------------------------------
# Stream names
# ---------------------------------------------------------------------------
STREAMS = (
    "security_events",
    "scan_events",
    "honeypot_events",
    "action_events",
)


# ---------------------------------------------------------------------------
# In-memory stream (asyncio.Queue based)
# ---------------------------------------------------------------------------

class _MemoryStream:
    """Single in-memory stream backed by asyncio.Queue."""

    def __init__(self, name: str, maxsize: int = 10_000):
        self.name = name
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subscribers: list[Callable[..., Coroutine]] = []
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def subscribe(self, callback: Callable[..., Coroutine]):
        self._subscribers.append(callback)

    async def publish(self, data: dict) -> str:
        """Publish event, returns event_id. Target: <5ms."""
        event_id = str(uuid.uuid4())
        enriched = {
            "event_id": event_id,
            "stream": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "published_at_ns": time.monotonic_ns(),
            **data,
        }
        try:
            self._queue.put_nowait(enriched)
        except asyncio.QueueFull:
            # Drop oldest to make room
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self._queue.put_nowait(enriched)
        return event_id

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._dispatch_loop(), name=f"stream_{self.name}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _dispatch_loop(self):
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                for cb in self._subscribers:
                    try:
                        await cb(event)
                    except Exception as e:
                        logger.error(f"Stream '{self.name}' subscriber error: {e}")
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break


# ---------------------------------------------------------------------------
# Redis stream wrapper
# ---------------------------------------------------------------------------

class _RedisStream:
    """Single stream backed by Redis Streams (XADD/XREAD)."""

    def __init__(self, name: str, redis_client):
        self.name = name
        self._redis = redis_client
        self._subscribers: list[Callable[..., Coroutine]] = []
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_id = "0-0"

    def subscribe(self, callback: Callable[..., Coroutine]):
        self._subscribers.append(callback)

    async def publish(self, data: dict) -> str:
        """Publish via XADD. Target: <5ms."""
        event_id = str(uuid.uuid4())
        enriched = {
            "event_id": event_id,
            "stream": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "data": json.dumps(data, default=str),
        }
        # Add priority field for consumer ordering
        if "priority" in data:
            enriched["priority"] = str(data["priority"])
        try:
            await self._redis.xadd(self.name, enriched, maxlen=10_000)
        except Exception as e:
            logger.error(f"Redis XADD failed on '{self.name}': {e}")
        return event_id

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._read_loop(), name=f"redis_stream_{self.name}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _read_loop(self):
        while self._running:
            try:
                results = await self._redis.xread(
                    {self.name: self._last_id},
                    count=100,
                    block=500,
                )
                if not results:
                    continue
                for stream_name, messages in results:
                    for msg_id, fields in messages:
                        self._last_id = msg_id
                        # Deserialize
                        event = {}
                        for k, v in fields.items():
                            key = k.decode() if isinstance(k, bytes) else k
                            val = v.decode() if isinstance(v, bytes) else v
                            if key == "data":
                                try:
                                    event.update(json.loads(val))
                                except (json.JSONDecodeError, TypeError):
                                    event[key] = val
                            else:
                                event[key] = val
                        for cb in self._subscribers:
                            try:
                                await cb(event)
                            except Exception as e:
                                logger.error(f"Redis stream '{self.name}' subscriber error: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Redis XREAD error on '{self.name}': {e}")
                await asyncio.sleep(1)


# ---------------------------------------------------------------------------
# EventStream manager
# ---------------------------------------------------------------------------

class EventStream:
    """
    Manages multiple named streams with Redis or in-memory backend.

    Usage:
        stream = EventStream(redis_url="redis://localhost:6379", use_redis=True)
        await stream.start()
        stream.subscribe("security_events", my_handler)
        await stream.publish("security_events", {"type": "brute_force", ...})
    """

    def __init__(self, redis_url: str = "", use_redis: bool = False):
        self._redis_url = redis_url
        self._use_redis = use_redis
        self._redis_client = None
        self._streams: dict[str, _MemoryStream | _RedisStream] = {}
        self._started = False

    async def start(self):
        """Initialize streams. Attempts Redis, falls back to memory."""
        if self._use_redis and self._redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis_client = aioredis.from_url(
                    self._redis_url,
                    decode_responses=False,
                )
                await self._redis_client.ping()
                logger.info(f"EventStream: Redis connected at {self._redis_url}")
                for name in STREAMS:
                    self._streams[name] = _RedisStream(name, self._redis_client)
            except Exception as e:
                logger.warning(f"EventStream: Redis unavailable ({e}), falling back to memory")
                self._redis_client = None
                self._use_redis = False
                for name in STREAMS:
                    self._streams[name] = _MemoryStream(name)
        else:
            logger.info("EventStream: Using in-memory streams")
            for name in STREAMS:
                self._streams[name] = _MemoryStream(name)

        for stream in self._streams.values():
            await stream.start()

        self._started = True
        logger.info(f"EventStream started with {len(self._streams)} streams (redis={self._use_redis})")

    async def stop(self):
        for stream in self._streams.values():
            await stream.stop()
        if self._redis_client:
            await self._redis_client.aclose()
            self._redis_client = None
        self._started = False
        logger.info("EventStream stopped")

    def subscribe(self, stream_name: str, callback: Callable[..., Coroutine]):
        """Subscribe to a named stream."""
        if stream_name not in self._streams:
            # Auto-create stream on demand
            self._streams[stream_name] = _MemoryStream(stream_name)
        self._streams[stream_name].subscribe(callback)
        logger.debug(f"EventStream: subscribed to '{stream_name}'")

    async def publish(self, stream_name: str, data: dict) -> str:
        """Publish event to a named stream. Returns event_id."""
        if stream_name not in self._streams:
            self._streams[stream_name] = _MemoryStream(stream_name)
            if self._started:
                await self._streams[stream_name].start()
        return await self._streams[stream_name].publish(data)

    @property
    def is_redis(self) -> bool:
        return self._use_redis and self._redis_client is not None

    def stats(self) -> dict:
        return {
            "backend": "redis" if self.is_redis else "memory",
            "streams": list(self._streams.keys()),
            "stream_count": len(self._streams),
            "started": self._started,
        }
