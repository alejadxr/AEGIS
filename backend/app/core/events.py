"""
Enhanced async event bus with priority support, timestamps, and optional
Redis Streams integration.

When Redis is available: publishes to both Redis Streams AND in-memory handlers.
When Redis is unavailable: in-memory only (graceful degradation).

Target: event processing <5ms.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger("aegis.events")

# Priority levels (lower number = higher priority)
PRIORITY_CRITICAL = 0
PRIORITY_HIGH = 1
PRIORITY_MEDIUM = 2
PRIORITY_LOW = 3


class _PriorityItem:
    """Wrapper for priority queue ordering."""

    __slots__ = ("priority", "seq", "event_type", "data")

    _seq_counter = 0

    def __init__(self, priority: int, event_type: str, data: Any):
        self.priority = priority
        self.seq = _PriorityItem._seq_counter
        _PriorityItem._seq_counter += 1
        self.event_type = event_type
        self.data = data

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.seq < other.seq


class EventBus:
    """In-memory async event bus with pub/sub pattern, priority support,
    and optional Redis Streams forwarding."""

    def __init__(self):
        self._subscribers: dict[str, list[Callable[..., Coroutine]]] = {}
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._running = False
        self._task: asyncio.Task | None = None
        self._event_stream = None  # Optional EventStream for Redis
        self._stats = {
            "events_published": 0,
            "events_processed": 0,
            "avg_process_time_ms": 0.0,
            "total_process_time_ms": 0.0,
        }

    def set_event_stream(self, event_stream):
        """Wire up the Redis EventStream for dual publishing."""
        self._event_stream = event_stream
        logger.info("EventBus: Redis EventStream connected for dual publishing")

    def subscribe(self, event_type: str, handler: Callable[..., Coroutine]):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
        logger.info(f"Subscribed handler to '{event_type}'")

    def unsubscribe(self, event_type: str, handler: Callable[..., Coroutine]):
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                h for h in self._subscribers[event_type] if h != handler
            ]

    async def publish(self, event_type: str, data: Any = None, priority: int = PRIORITY_MEDIUM):
        """Publish an event. Enriches with event_id and timestamp automatically.
        Target: <5ms for the publish call itself."""
        # Enrich event data
        if isinstance(data, dict):
            if "event_id" not in data:
                data["event_id"] = str(uuid.uuid4())
            if "timestamp" not in data:
                data["timestamp"] = datetime.now(timezone.utc).isoformat()
            if "priority" not in data:
                data["priority"] = priority

        # In-memory priority queue (always)
        item = _PriorityItem(priority, event_type, data)
        await self._queue.put(item)
        self._stats["events_published"] += 1

        # Redis Streams forwarding (if available, fire-and-forget)
        if self._event_stream:
            stream_map = {
                "alert_processed": "security_events",
                "correlation_triggered": "security_events",
                "scan_completed": "scan_events",
                "honeypot_deployed": "honeypot_events",
                "honeypot_interaction": "honeypot_events",
                "action_executed": "action_events",
                "action_requires_approval": "action_events",
                "playbook_executed": "security_events",
                "fast_triage_completed": "security_events",
            }
            stream_name = stream_map.get(event_type, "security_events")
            try:
                event_payload = data if isinstance(data, dict) else {"data": data}
                event_payload["_event_type"] = event_type
                await self._event_stream.publish(stream_name, event_payload)
            except Exception as e:
                logger.debug(f"Redis stream publish failed (non-fatal): {e}")

        logger.debug(f"Published event '{event_type}' (priority={priority})")

    async def publish_critical(self, event_type: str, data: Any = None):
        """Convenience: publish with critical priority."""
        await self.publish(event_type, data, priority=PRIORITY_CRITICAL)

    async def publish_high(self, event_type: str, data: Any = None):
        """Convenience: publish with high priority."""
        await self.publish(event_type, data, priority=PRIORITY_HIGH)

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._process_events())
        logger.info("Event bus started (priority-enabled)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Event bus stopped")

    async def _process_events(self):
        while self._running:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                start_ns = time.monotonic_ns()

                handlers = self._subscribers.get(item.event_type, [])
                for handler in handlers:
                    try:
                        await handler(item.data)
                    except Exception as e:
                        logger.error(f"Event handler error for '{item.event_type}': {e}")

                elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000
                self._stats["events_processed"] += 1
                self._stats["total_process_time_ms"] += elapsed_ms
                if self._stats["events_processed"] > 0:
                    self._stats["avg_process_time_ms"] = (
                        self._stats["total_process_time_ms"] / self._stats["events_processed"]
                    )

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    def stats(self) -> dict:
        return {
            **self._stats,
            "subscribers": {k: len(v) for k, v in self._subscribers.items()},
            "queue_size": self._queue.qsize(),
            "has_redis_stream": self._event_stream is not None,
        }


# Singleton
event_bus = EventBus()
