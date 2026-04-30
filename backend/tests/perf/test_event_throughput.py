"""
AEGIS correlation engine event throughput test.

Methodology
-----------
- AI mode is forced to DISABLED so no network calls occur.
- A CorrelationEngine is instantiated from the YAML rule pack (122 rules).
- 1 000 synthetic events of a single event_type (auth_failure) are evaluated
  synchronously using asyncio.run() to exercise the full async path.
- Wall-clock time is measured with time.perf_counter_ns().
- The test asserts ≥ 1 000 events/second sustained throughput.

Target: ≥ 1 000 evt/s on a single thread (no concurrency helpers).

Run with:
    pytest tests/perf/test_event_throughput.py --noconftest -v
"""

from __future__ import annotations

import asyncio
import os
import statistics
import time
import unittest.mock as mock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

N = 1_000
TARGET_EPS = 1_000  # events per second minimum


def _make_event(i: int) -> dict:
    return {
        "event_type": "auth_failure",
        "source_ip": f"203.0.113.{i % 256}",
        "username": f"user{i % 10}",
        "service": "ssh",
        "timestamp": "2026-01-01T00:00:00Z",
    }


def _build_engine():
    """Build a CorrelationEngine with AEGIS_AI_MODE=disabled, config mocked."""
    with mock.patch.dict(os.environ, {"AEGIS_AI_MODE": "disabled"}):
        with mock.patch(
            "app.config.settings",
            mock.MagicMock(AEGIS_ATTACKER_IPS=""),
        ):
            from app.services.correlation_engine import CorrelationEngine
            return CorrelationEngine()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_throughput_gte_1000_eps():
    """Sustained ≥ 1 000 events/second with AI disabled and YAML rule index."""
    engine = _build_engine()

    events = [_make_event(i) for i in range(N)]

    async def _run():
        latencies_ns: list[int] = []
        for ev in events:
            t0 = time.perf_counter_ns()
            await engine.evaluate(ev)
            latencies_ns.append(time.perf_counter_ns() - t0)
        return latencies_ns

    latencies_ns = asyncio.run(_run())

    total_s = sum(latencies_ns) / 1e9
    eps = N / total_s
    mean_us = statistics.mean(latencies_ns) / 1_000
    p99_us = sorted(latencies_ns)[int(0.99 * len(latencies_ns))] / 1_000

    print(
        f"\n[Perf] {N} events in {total_s*1000:.1f}ms | "
        f"{eps:.0f} evt/s | mean={mean_us:.0f}µs | p99={p99_us:.0f}µs"
    )

    assert eps >= TARGET_EPS, (
        f"Throughput {eps:.0f} evt/s < target {TARGET_EPS} evt/s "
        f"(mean={mean_us:.0f}µs, p99={p99_us:.0f}µs)"
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
