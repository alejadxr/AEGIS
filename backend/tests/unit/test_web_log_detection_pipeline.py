"""Tailed web-log lines must reach a rule and become an incident, and the
log_watcher must expose / act on its own liveness.

Regression: from 2026-10-03 the web pipeline produced zero incidents while
secret-file scanners (/.env, /.git, ...) probed landing-app. The pipeline
was alive; no rule covered that traffic.
"""
import asyncio
import os

import pytest

from app.core import events as events_mod
from app.services.correlation_engine import CorrelationEngine
from app.services.log_watcher import LogWatcher

ENV_LINE = (
    '2026-10-05 13:30:53: [AEGIS] {"ts":"2026-10-05T17:30:53.169Z",'
    '"app":"landing-app","src_ip":"45.33.32.156","method":"GET",'
    '"path":"/.env","status":200,"ua":"curl/8.7.1","host":"example.com"}'
)


def _line(path):
    return ENV_LINE.replace('"/.env"', f'"{path}"')


async def test_env_probe_line_creates_incident_through_real_pipeline(monkeypatch):
    engine = CorrelationEngine()
    incidents = []

    async def fake_create(rule, alert):
        incidents.append(rule["id"])

    monkeypatch.setattr(engine, "_create_incident", fake_create)

    async def route(topic, data=None, *a, **k):
        if topic == "log_event":
            await engine._on_normalized_event(data)

    monkeypatch.setattr(events_mod.event_bus, "publish", route)

    lw = LogWatcher()
    # The exact production line, then two more probes from the same scanner.
    for line in (ENV_LINE, _line("/.git/config"), _line("/config/.env")):
        await lw._process_line(line, source="extra")
    await asyncio.sleep(0.05)

    assert "sigma_web_sensitive_file_probe" in incidents
    stats = lw.liveness()
    assert stats["lines_processed"] == 3
    assert stats["events_published"] == 3
    assert engine.stats()["last_rule_fired_at"] is not None


async def test_single_env_probe_alone_is_not_an_incident(monkeypatch):
    engine = CorrelationEngine()
    fired = await engine.evaluate(
        {"event_type": "http_request", "source_ip": "45.33.32.156",
         "request_path": "/.env", "request_method": "GET"}
    )
    assert fired == []


def test_check_liveness_flags_growth_without_reads(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("a\n")
    lw = LogWatcher()
    lw._tail_paths = [str(f)]
    assert lw.check_liveness(now=0) is False  # baseline size recorded
    f.write_text("a\nb\n")
    assert lw.check_liveness(now=10) is False  # growth seen, not yet stalled
    assert lw.check_liveness(now=10 + lw._STALL_SECONDS) is True
    lw._stats["lines_read"] += 1  # a line gets read -> recovered
    assert lw.check_liveness(now=10 + lw._STALL_SECONDS + 1) is False


def test_check_liveness_quiet_files_are_not_a_stall(tmp_path):
    f = tmp_path / "x.log"
    f.write_text("a\n")
    lw = LogWatcher()
    lw._tail_paths = [str(f)]
    lw.check_liveness(now=0)
    assert lw.check_liveness(now=10_000) is False


async def test_restart_tail_replaces_task(monkeypatch):
    lw = LogWatcher()
    lw._running = True

    async def forever():
        await asyncio.sleep(3600)

    monkeypatch.setattr(lw, "_watch_loop", forever)
    lw._task = asyncio.create_task(forever())
    old = lw._task
    await lw._restart_tail()
    assert old.cancelled() and lw._task is not old
    assert lw.liveness()["tail_restarts"] == 1
    lw._task.cancel()
