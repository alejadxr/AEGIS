"""Bounded fire-and-forget task offloader for event-bus handlers.

`EventBus._process_events` (core/events.py) runs subscriber handlers
sequentially and awaits each one directly — all event types share that one
worker loop, so a handler that performs slow I/O (DB round-trip, outbound
HTTP call) stalls delivery of every other queued event, including
higher-priority security events, behind it.

`fire_and_forget` lets a handler hand its slow tail off to a background
task instead of awaiting it inline, so the event-bus loop moves on
immediately. Concurrency is capped by a semaphore (avoid hammering the DB /
remote hosts with a burst of simultaneous calls) and total scheduled tasks
are capped by `_MAX_INFLIGHT` (avoid unbounded task/coroutine growth during
an event storm — same bounding philosophy as core/mem_bounds.py). Exceptions
are logged and never propagate back to the event bus.
"""
import asyncio
import logging
from typing import Coroutine

logger = logging.getLogger("aegis.bg_tasks")

_MAX_CONCURRENT = 50
_MAX_INFLIGHT = 500

_semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
_inflight: set[asyncio.Task] = set()
_dropped = 0


async def _run(coro: Coroutine, label: str) -> None:
    async with _semaphore:
        try:
            await coro
        except Exception:
            logger.exception(f"bg_tasks: background task '{label}' failed")


def fire_and_forget(coro: Coroutine, label: str = "task") -> "asyncio.Task | None":
    """Schedule `coro` on a background task and return immediately.

    Returns None (and drops `coro`) if `_MAX_INFLIGHT` tasks are already
    scheduled — a hard backstop so a burst of events can't grow the task set
    without bound. The caller's hot path is never blocked either way.
    """
    global _dropped
    if len(_inflight) >= _MAX_INFLIGHT:
        _dropped += 1
        coro.close()
        logger.warning(
            f"bg_tasks: dropping '{label}' — {_MAX_INFLIGHT} tasks already in flight "
            f"(dropped_total={_dropped})"
        )
        return None

    task = asyncio.create_task(_run(coro, label))
    _inflight.add(task)
    task.add_done_callback(_inflight.discard)
    return task


async def drain(timeout: float = 5.0) -> None:
    """Best-effort wait for in-flight background tasks to finish.

    Call during shutdown, before dependencies the tasks rely on (DB engine,
    HTTP clients) are torn down. Any task still pending after `timeout` is
    cancelled rather than awaited indefinitely.
    """
    if not _inflight:
        return
    tasks = list(_inflight)
    _, pending = await asyncio.wait(tasks, timeout=timeout)
    for t in pending:
        t.cancel()


def stats() -> dict:
    return {
        "inflight": len(_inflight),
        "dropped_total": _dropped,
        "max_concurrent": _MAX_CONCURRENT,
        "max_inflight": _MAX_INFLIGHT,
    }
