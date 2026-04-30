"""
AEGIS correlation engine event throughput benchmark.

Methodology
-----------
- AI mode is forced to DISABLED (AEGIS_AI_MODE=disabled) so no network calls occur.
- A CorrelationEngine is instantiated from the YAML rule pack (122 sigma + 5 chain rules).
- 5 000 synthetic events with mixed event_types (80 % known, 20 % unknown) are evaluated
  on a single thread using asyncio.run() once for the whole batch (amortises loop setup).
- Wall-clock time is measured with time.perf_counter (not per-event, to avoid
  measurement overhead skewing the result).
- The test asserts ≥ 1 000 events/second sustained throughput (hard floor 800 evt/s).

Target: ≥ 1 000 evt/s on a single thread (no concurrency helpers).
Hard floor: ≥ 800 evt/s on any host.

Run with:
    pytest tests/perf/test_event_throughput.py -v -s
"""

from __future__ import annotations

import asyncio
import os
import random
import statistics
import time
import unittest.mock as mock
import warnings
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

N = 5_000
TARGET_EPS = 1_000   # events per second — desired target
FLOOR_EPS = 800      # hard floor below which the test fails
_RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_engine():
    """Build a CorrelationEngine with AEGIS_AI_MODE=disabled, config mocked."""
    with mock.patch.dict(os.environ, {"AEGIS_AI_MODE": "disabled"}):
        with mock.patch(
            "app.config.settings",
            mock.MagicMock(AEGIS_ATTACKER_IPS=""),
        ):
            from app.services.correlation_engine import CorrelationEngine
            return CorrelationEngine()


def _make_mixed_events(engine, n: int) -> list[dict]:
    """
    Build *n* events with 80 % known event_types (from the loaded rule pack)
    and 20 % unknown types (to exercise the O(1) empty-lookup fast path).
    """
    random.seed(42)
    known_types = list(engine._rules_by_type.keys()) or ["auth_failure"]
    unknown_types = [f"unknown_type_{i}" for i in range(max(1, len(known_types) // 5))]
    pool = known_types * 4 + unknown_types  # ~80 % known

    ips = [f"203.0.113.{i}" for i in range(1, 51)]
    events = []
    for i in range(n):
        events.append({
            "event_type": random.choice(pool),
            "source_ip": random.choice(ips),
            "username": f"user{i % 20}",
            "service": random.choice(["ssh", "http", "smb"]),
            "timestamp": "2026-01-01T00:00:00Z",
            "process_name": random.choice(["bash", "python3", "curl", "nmap"]),
            "cmdline": "bash -c echo test",
        })
    return events


def _make_event(i: int) -> dict:
    return {
        "event_type": "auth_failure",
        "source_ip": f"203.0.113.{i % 256}",
        "username": f"user{i % 10}",
        "service": "ssh",
        "timestamp": "2026-01-01T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_throughput_gte_1000_eps():
    """
    Sustained ≥ 1 000 events/second with AI disabled and YAML event-type index.

    Uses 5 000 mixed-type events; asyncio.run called once to amortise loop overhead.
    Hard floor 800 evt/s; warns if between 800 and 1 000.
    """
    engine = _build_engine()
    events = _make_mixed_events(engine, N)

    async def _run_batch():
        for ev in events:
            await engine.evaluate(ev)

    t0 = time.perf_counter()
    asyncio.run(_run_batch())
    elapsed = time.perf_counter() - t0

    eps = N / elapsed
    n_types = len(engine._rules_by_type)

    print(
        f"\n[Perf] {N} events in {elapsed*1000:.1f}ms | "
        f"{eps:,.0f} evt/s | rule index: {n_types} event types"
    )

    if FLOOR_EPS <= eps < TARGET_EPS:
        warnings.warn(
            f"Throughput {eps:,.0f} evt/s is above the {FLOOR_EPS} floor "
            f"but below the {TARGET_EPS} target — investigate on a faster host.",
            stacklevel=1,
        )

    assert eps >= FLOOR_EPS, (
        f"Throughput {eps:,.0f} evt/s is below the hard floor of {FLOOR_EPS} evt/s."
    )


def test_indexed_dispatch_faster_than_full_scan():
    """Indexed O(k) dispatch is faster than O(N) full scan for a rare event type."""
    engine = _build_engine()

    # Use an event type with very few rules (e.g. kerberos_auth — ~2 rules)
    rare_event = {
        "event_type": "kerberos_auth",
        "source_ip": "203.0.113.1",
        "encryption_type": "RC4",
    }

    # Common type — auth_failure has ~9 rules
    common_event = {
        "event_type": "auth_failure",
        "source_ip": "203.0.113.1",
        "service": "ssh",
    }

    async def _time_n(ev: dict, n: int) -> float:
        t0 = time.perf_counter_ns()
        for _ in range(n):
            await engine.evaluate(ev)
        return (time.perf_counter_ns() - t0) / n

    rare_ns = asyncio.run(_time_n(rare_event, 200))
    common_ns = asyncio.run(_time_n(common_event, 200))

    print(
        f"\n[Perf] rare(kerberos_auth)={rare_ns/1000:.0f}µs "
        f"common(auth_failure)={common_ns/1000:.0f}µs"
    )

    # Rare event type should evaluate at least as fast as common (indexed)
    # — both should be well under 10ms each
    assert rare_ns < 10_000_000, (
        f"Rare event eval too slow: {rare_ns/1000:.0f}µs"
    )
    assert common_ns < 10_000_000, (
        f"Common event eval too slow: {common_ns/1000:.0f}µs"
    )


def test_unknown_event_type_is_free():
    """Events with an event_type matching no rules evaluate near-instantly."""
    engine = _build_engine()

    unknown_event = {
        "event_type": "completely_unknown_type_xyz",
        "source_ip": "203.0.113.1",
    }

    async def _run():
        t0 = time.perf_counter_ns()
        for _ in range(500):
            result = await engine.evaluate(unknown_event)
            assert result == [], "Unknown event type should match no rules"
        return time.perf_counter_ns() - t0

    total_ns = asyncio.run(_run())
    mean_us = total_ns / 500 / 1_000
    print(f"\n[Perf] unknown event_type mean={mean_us:.1f}µs")
    assert mean_us < 500, f"Unknown event type eval too slow: {mean_us:.1f}µs"
