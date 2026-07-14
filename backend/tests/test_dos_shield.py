"""
Unit tests for the DoS Shield core detection engine (owner A).

Pure, no network, no DB. Uses fake-clock injection via the record_request(now=...)
parameter (the interface_contract guarantees `now` defaults to time.monotonic()
but is caller-overridable), so no monkeypatching of the clock is required.

Covered:
  * monitor mode never returns throttle/block (detection only)
  * per-IP flood trips dos.http_flood at DOS_PER_IP_RPS
  * subnet + global aggregate detection (distributed flood)
  * expensive-path tighter budget
  * _is_safe_ip exemption is honored by escalate()
  * cache-bust query strings + numeric ids map to same normalized key
  * _subnet_key IPv4 /24 and IPv6 /64
  * under-attack set/clear hysteresis
  * active mode returns block after threshold
  * escalate() calls ip_blocker_service.block_ip + firewall_client.block_ip
    and skips safelisted IPs
  * event payloads carry event_type + source_ip
  * slow-loris concurrency heuristic
"""

import asyncio

import pytest

import app.services.dos_shield as ds_mod
from app.services.dos_shield import (
    DoSShield,
    Verdict,
    MODE_MONITOR,
    MODE_ACTIVE,
    ACTION_ALLOW,
    ACTION_THROTTLE,
    ACTION_BLOCK,
    REASON_PER_IP,
    REASON_SUBNET,
    REASON_GLOBAL,
    REASON_EXPENSIVE,
    EVT_HTTP_FLOOD,
    EVT_DISTRIBUTED,
    EVT_EXPENSIVE,
)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
class _FakeBus:
    """Records every publish() call synchronously."""

    def __init__(self):
        self.published = []

    async def publish(self, event_type, data=None, priority=None):
        self.published.append((event_type, data, priority))


def _make_shield(monkeypatch, **overrides):
    """Build a fresh DoSShield with deterministic, test-friendly thresholds."""
    from app.config import settings

    defaults = {
        "AEGIS_DOS_MODE": "monitor",
        "AEGIS_DOS_PER_IP_RPS": 10,
        "AEGIS_DOS_PER_IP_WINDOW": 10,
        "AEGIS_DOS_SUBNET_RPS": 40,
        "AEGIS_DOS_SUBNET_WINDOW": 10,
        "AEGIS_DOS_GLOBAL_RPS": 50,
        "AEGIS_DOS_GLOBAL_WINDOW": 10,
        "AEGIS_DOS_EXPENSIVE_RPM": 6,
        "AEGIS_DOS_EXPENSIVE_PATHS": "/api/v1/ask,/api/v1/surface/scan",
        "AEGIS_DOS_CONCURRENCY_PER_IP": 20,
        "AEGIS_DOS_SLOW_REQUEST_SECONDS": 25,
        "AEGIS_DOS_BLOCK_DURATION": 900,
        "AEGIS_DOS_UNDER_ATTACK_FACTOR": 0.5,
        "AEGIS_DOS_EVENT_COOLDOWN": 30,
        "AEGIS_DOS_NETSHIELD": "0",
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        monkeypatch.setattr(settings, k, v, raising=False)

    shield = DoSShield()
    bus = _FakeBus()
    shield.register_event_bus(bus)
    return shield, bus


# --------------------------------------------------------------------------- #
# Path normalization / subnet key
# --------------------------------------------------------------------------- #
def test_normalize_path_strips_query_and_ids(monkeypatch):
    shield, _ = _make_shield(monkeypatch)
    assert shield._normalize_path("/api/v1/threats?window=1h") == "/api/v1/threats"
    assert shield._normalize_path("/api/v1/threats?window=2h") == "/api/v1/threats"
    assert shield._normalize_path("/api/v1/asset/123") == "/api/v1/asset/{id}"
    assert shield._normalize_path("/api/v1/asset/123/") == "/api/v1/asset/{id}"
    assert shield._normalize_path("/") == "/"


def test_cache_bust_maps_to_same_key(monkeypatch):
    """Randomized query strings must NOT dilute the per-IP counter."""
    shield, _ = _make_shield(monkeypatch)
    ip = "203.0.113.7"
    t = 1000.0
    # 60 requests in 1s, each with a distinct cache-busting query string
    v = None
    for i in range(60):
        v = shield.record_request(ip, f"/api/v1/threats?nonce={i}", "GET", now=t + i * 0.01)
    # per_ip_rps = 60 / window(10) = 6 rps... push more to exceed 10rps threshold
    for i in range(60, 150):
        v = shield.record_request(ip, f"/api/v1/threats?nonce={i}", "GET", now=t + i * 0.001)
    assert v.reason == REASON_PER_IP
    assert v.detail["path"] == "/api/v1/threats"


def test_subnet_key(monkeypatch):
    shield, _ = _make_shield(monkeypatch)
    assert shield._subnet_key("203.0.113.55") == "203.0.113.0/24"
    assert shield._subnet_key("malformed") == "malformed"
    # IPv6 -> /64
    assert shield._subnet_key("2001:db8::1").endswith("/64")


# --------------------------------------------------------------------------- #
# Monitor mode
# --------------------------------------------------------------------------- #
def test_monitor_mode_never_blocks(monkeypatch):
    shield, bus = _make_shield(monkeypatch, AEGIS_DOS_MODE="monitor")
    assert shield.mode == MODE_MONITOR
    ip = "203.0.113.10"
    t = 500.0
    last = None
    # 200 requests in 1s => 20 rps > 10 rps threshold
    for i in range(200):
        last = shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.005)
    # detection populated (reason set even when event is cooldown-suppressed)...
    assert last.reason == REASON_PER_IP
    # ...but action ALWAYS allow in monitor mode
    assert last.action == ACTION_ALLOW
    assert last.retry_after == 0
    # the flood event was published at least once during the burst
    assert any(p[0] == EVT_HTTP_FLOOD for p in bus.published)


# --------------------------------------------------------------------------- #
# Per-IP flood
# --------------------------------------------------------------------------- #
def test_per_ip_flood_trips(monkeypatch):
    shield, bus = _make_shield(monkeypatch, AEGIS_DOS_MODE="active", AEGIS_DOS_PER_IP_RPS=10)
    ip = "203.0.113.20"
    t = 100.0
    verdict = None
    # 150 requests within a fraction of a second => rps = 150/10 = 15 > 10
    for i in range(150):
        verdict = shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.001)
    assert verdict.reason == REASON_PER_IP
    assert verdict.action == ACTION_BLOCK
    assert verdict.retry_after > 0
    # event published with correct type + source_ip
    names = [p[0] for p in bus.published]
    assert EVT_HTTP_FLOOD in names
    payload = next(p[1] for p in bus.published if p[0] == EVT_HTTP_FLOOD)
    assert payload["event_type"] == EVT_HTTP_FLOOD
    assert payload["source_ip"] == ip


def test_below_threshold_allows(monkeypatch):
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_MODE="active", AEGIS_DOS_PER_IP_RPS=10)
    ip = "203.0.113.21"
    t = 100.0
    verdict = None
    # 50 requests over the 10s window => 5 rps < 10 rps
    for i in range(50):
        verdict = shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.1)
    assert verdict.reason == ""
    assert verdict.action == ACTION_ALLOW


# --------------------------------------------------------------------------- #
# Distributed / aggregate
# --------------------------------------------------------------------------- #
def test_subnet_flood_trips_distributed(monkeypatch):
    """Many IPs in one /24, each below per-IP limit, still trip subnet flood."""
    # keep global high enough that subnet trips first: raise global so global
    # doesn't dominate; set subnet low
    shield, bus = _make_shield(
        monkeypatch,
        AEGIS_DOS_MODE="active",
        AEGIS_DOS_SUBNET_RPS=40,
        AEGIS_DOS_GLOBAL_RPS=100000,  # effectively disable global for this test
        AEGIS_DOS_PER_IP_RPS=1000,    # each IP stays under per-IP
    )
    t = 200.0
    verdict = None
    # 500 requests spread across 100 IPs in the /24 => 5 per IP (under per-IP),
    # subnet total 500 / 10 = 50 rps > 40
    for i in range(500):
        ip = f"203.0.113.{i % 100 + 1}"
        verdict = shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.001)
    assert verdict.reason == REASON_SUBNET
    assert verdict.action == ACTION_THROTTLE
    names = [p[0] for p in bus.published]
    assert EVT_DISTRIBUTED in names


def test_global_flood_trips_and_under_attack(monkeypatch):
    """Fully distributed flood across many /24s trips global + under_attack."""
    shield, bus = _make_shield(
        monkeypatch,
        AEGIS_DOS_MODE="active",
        AEGIS_DOS_GLOBAL_RPS=50,
        AEGIS_DOS_SUBNET_RPS=100000,  # disable subnet
        AEGIS_DOS_PER_IP_RPS=100000,  # disable per-IP
    )
    t = 300.0
    verdict = None
    # 700 requests across 700 distinct subnets => global 700/10 = 70 rps > 50
    for i in range(700):
        a = (i // 256) % 200 + 1
        b = i % 256
        ip = f"51.{a}.{b}.1"
        verdict = shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.001)
    assert verdict.reason == REASON_GLOBAL
    assert shield.under_attack is True
    names = [p[0] for p in bus.published]
    assert EVT_DISTRIBUTED in names
    assert "dos.under_attack" in names


def test_under_attack_hysteresis_clears(monkeypatch):
    shield, _ = _make_shield(
        monkeypatch,
        AEGIS_DOS_MODE="monitor",
        AEGIS_DOS_GLOBAL_RPS=50,
        AEGIS_DOS_SUBNET_RPS=100000,
        AEGIS_DOS_PER_IP_RPS=100000,
    )
    t = 0.0
    # drive global above threshold
    for i in range(700):
        ip = f"51.{i % 200 + 1}.{i % 256}.1"
        shield.record_request(ip, "/x", "GET", now=t + i * 0.001)
    assert shield.under_attack is True
    # now go quiet: advance clock well past the window so global window empties,
    # then send a trickle. global_rps should fall below 50*0.6=30 and clear.
    t2 = 100.0
    for i in range(5):
        shield.record_request("51.9.9.1", "/x", "GET", now=t2 + i * 1.0)
    assert shield.under_attack is False


# --------------------------------------------------------------------------- #
# Expensive path
# --------------------------------------------------------------------------- #
def test_expensive_path_tighter_budget(monkeypatch):
    """Expensive endpoints trip at a much lower budget (6/min default)."""
    shield, bus = _make_shield(
        monkeypatch,
        AEGIS_DOS_MODE="active",
        AEGIS_DOS_EXPENSIVE_RPM=6,
        AEGIS_DOS_PER_IP_RPS=1000,  # ensure per-IP does not trip first
    )
    ip = "203.0.113.30"
    t = 400.0
    verdict = None
    # 8 requests to /api/v1/ask within a minute => > 6 budget
    for i in range(8):
        verdict = shield.record_request(ip, "/api/v1/ask", "POST", now=t + i * 0.5)
    assert verdict.reason == REASON_EXPENSIVE
    assert verdict.action == ACTION_BLOCK
    names = [p[0] for p in bus.published]
    assert EVT_EXPENSIVE in names


def test_expensive_path_normal_traffic_ok(monkeypatch):
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_MODE="active", AEGIS_DOS_EXPENSIVE_RPM=6)
    ip = "203.0.113.31"
    t = 400.0
    verdict = None
    for i in range(4):  # 4 < 6 budget
        verdict = shield.record_request(ip, "/api/v1/ask", "POST", now=t + i * 5.0)
    assert verdict.reason == ""
    assert verdict.action == ACTION_ALLOW


# --------------------------------------------------------------------------- #
# Slow-loris concurrency heuristic
# --------------------------------------------------------------------------- #
def test_slowloris_concurrency_trips(monkeypatch):
    shield, bus = _make_shield(
        monkeypatch,
        AEGIS_DOS_MODE="active",
        AEGIS_DOS_CONCURRENCY_PER_IP=20,
        AEGIS_DOS_PER_IP_RPS=100000,  # avoid per-IP flood interfering
    )
    ip = "203.0.113.40"
    t = 500.0
    # open 25 concurrent in-flight requests (> 20)
    for i in range(25):
        shield.begin_request(ip, now=t + i * 0.001)
    # a new request while 25 are in-flight -> slowloris
    verdict = shield.record_request(ip, "/api/v1/data", "GET", now=t + 0.1)
    assert verdict.reason == "slowloris"
    assert verdict.action == ACTION_BLOCK


def test_slow_request_duration_tick(monkeypatch):
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_SLOW_REQUEST_SECONDS=25)
    ip = "203.0.113.41"
    shield.begin_request(ip, now=0.0)
    assert shield._ip_state[ip].concurrency == 1
    shield.end_request(ip, now=30.0)  # 30s > 25s slow threshold
    st = shield._ip_state[ip]
    assert st.concurrency == 0
    assert st.slow_ticks == 1


# --------------------------------------------------------------------------- #
# Safelist / escalation
# --------------------------------------------------------------------------- #
def test_escalate_skips_safelisted(monkeypatch):
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_MODE="active")

    called = {"local": False, "fw": False}

    import app.core.ip_blocker as ipb

    def fake_block(ip):
        called["local"] = True
        return {"success": True, "ip": ip}

    monkeypatch.setattr(ipb.ip_blocker_service, "block_ip", fake_block)

    # 100.64.0.0/10 is Tailscale CGNAT => _is_safe_ip True
    result = asyncio.run(shield.escalate("100.64.1.2", REASON_PER_IP))
    assert result["blocked"] is False
    assert result["reason"] == "safelisted"
    assert called["local"] is False


def test_escalate_blocks_and_delegates(monkeypatch):
    shield, bus = _make_shield(monkeypatch, AEGIS_DOS_MODE="active")

    called = {"local": None, "fw": None}

    import app.core.ip_blocker as ipb
    import app.core.firewall_client as fwc

    def fake_local(ip):
        called["local"] = ip
        return {"success": True, "ip": ip}

    async def fake_fw(ip):
        called["fw"] = ip
        return {"success": True}

    monkeypatch.setattr(ipb.ip_blocker_service, "block_ip", fake_local)
    monkeypatch.setattr(fwc.firewall_client, "block_ip", fake_fw)

    result = asyncio.run(shield.escalate("203.0.113.99", REASON_PER_IP))
    assert result["blocked"] is True
    assert called["local"] == "203.0.113.99"
    assert called["fw"] == "203.0.113.99"
    # dedup: second escalate within block window is a no-op delegation
    called["local"] = None
    result2 = asyncio.run(shield.escalate("203.0.113.99", REASON_PER_IP))
    assert result2.get("deduped") is True
    assert called["local"] is None


# --------------------------------------------------------------------------- #
# Mode / snapshot
# --------------------------------------------------------------------------- #
def test_set_mode_validation(monkeypatch):
    shield, _ = _make_shield(monkeypatch)
    shield.set_mode(MODE_ACTIVE)
    assert shield.mode == MODE_ACTIVE
    shield.set_mode(MODE_MONITOR)
    assert shield.mode == MODE_MONITOR
    with pytest.raises(ValueError):
        shield.set_mode("bogus")


def test_snapshot_shape(monkeypatch):
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_MODE="monitor")
    t = 600.0
    for i in range(30):
        shield.record_request("203.0.113.50", "/api/v1/data", "GET", now=t + i * 0.01)
    snap = shield.snapshot()
    assert snap["mode"] == "monitor"
    assert set(snap.keys()) >= {
        "mode", "under_attack", "global_rps", "global_window_s",
        "netshield_enabled", "netshield_env_gate", "thresholds",
        "counters", "top_offenders",
    }
    assert snap["thresholds"]["per_ip_rps"] == 10
    assert isinstance(snap["top_offenders"], list)
    assert snap["counters"]["tracked_ips"] >= 1


def test_verdict_to_dict(monkeypatch):
    v = Verdict(action=ACTION_THROTTLE, reason=REASON_GLOBAL, ip="1.2.3.4",
                mode=MODE_ACTIVE, retry_after=10, event=EVT_DISTRIBUTED,
                detail={"global_rps": 70.0})
    d = v.to_dict()
    assert d["action"] == ACTION_THROTTLE
    assert d["ip"] == "1.2.3.4"
    assert d["detail"]["global_rps"] == 70.0


def test_event_cooldown_suppresses_duplicates(monkeypatch):
    shield, bus = _make_shield(
        monkeypatch, AEGIS_DOS_MODE="monitor", AEGIS_DOS_EVENT_COOLDOWN=30,
        AEGIS_DOS_PER_IP_RPS=10,
    )
    ip = "203.0.113.60"
    t = 700.0
    for i in range(200):
        shield.record_request(ip, "/api/v1/data", "GET", now=t + i * 0.001)
    flood_events = [p for p in bus.published if p[0] == EVT_HTTP_FLOOD]
    # within one cooldown window only one http_flood event for this (ip, reason)
    assert len(flood_events) == 1
