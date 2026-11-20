"""MikroTik switch monitor: client, health conditions, inventory, API.

The switch REST API is faked with httpx.MockTransport. Nothing here touches a
real switch or the network. Addresses are RFC 5737, MACs are the IANA
documentation block 00:00:5E:00:53:xx.
"""
import ast
import json
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from app.config import settings
from app.core import switch_client as sc
from app.models.incident import Incident
from app.services import switch_monitor as sm

T0 = 1_000_000.0
MIN = 60.0


# ------------------------------------------------------------------ fake switch
class FakeSwitch:
    """Serves RouterOS-shaped REST (every value a string) from mutable state."""

    def __init__(self):
        self.ports: dict[str, dict] = {}
        self.hosts: list[dict] = []
        self.fail = False
        self.requests: list[tuple[str, str]] = []
        self.resource = {"version": "7.15.2 (stable)", "board-name": "Test Board",
                         "uptime": "1d2h", "cpu-load": "3",
                         "free-memory": "300", "total-memory": "1000"}

    def port(self, name, running=True, rate="1Gbps", duplex=True, link_downs=0,
             rx_error=0, tx_error=0, fcs=0, align=0, rx_drop=0, tx_drop=0, txq=0,
             disabled=False, no_link=False):
        self.ports[name] = dict(locals(), self=None)
        del self.ports[name]["self"], self.ports[name]["name"]
        return self.ports[name]

    def set(self, name, **kw):
        self.ports[name].update(kw)

    def host(self, mac, port, local=False):
        self.hosts.append({".id": "*1", "bridge": "bridge", "mac-address": mac,
                           "on-interface": port, "interface": port,
                           "local": str(local).lower(), "dynamic": "true",
                           "disabled": "false", "invalid": "false"})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if self.fail:
            raise httpx.ConnectTimeout("timeout", request=request)
        assert request.headers["authorization"].startswith("Basic ")
        path = request.url.path.removeprefix("/rest")
        b = lambda v: str(v).lower()
        if path == "/interface":
            return httpx.Response(200, json=[{
                ".id": "*2", "name": n, "type": "ether", "disabled": b(p["disabled"]),
                "running": b(p["running"]), "link-downs": str(p["link_downs"]),
                "rx-error": str(p["rx_error"]), "tx-error": str(p["tx_error"]),
                "rx-drop": str(p["rx_drop"]), "tx-drop": str(p["tx_drop"]),
                "tx-queue-drop": str(p["txq"]), "mac-address": "00:00:5E:00:53:01",
            } for n, p in self.ports.items()] + [{"name": "bridge", "type": "bridge", "running": "true"}])
        if path == "/interface/ethernet":
            return httpx.Response(200, json=[{
                "name": n, "rx-fcs-error": str(p["fcs"]), "rx-align-error": str(p["align"]),
                "rx-overflow": "61"} for n, p in self.ports.items()])
        if path == "/interface/ethernet/monitor":
            assert request.method == "POST"
            name = json.loads(request.content)["numbers"]
            p = self.ports[name]
            if p["no_link"] or not p["running"]:
                return httpx.Response(200, json=[{"name": name, "status": "no-link",
                                                  "auto-negotiation": "done",
                                                  "link-partner-advertising": ""}])
            return httpx.Response(200, json=[{"name": name, "status": "link-ok",
                                              "rate": p["rate"], "full-duplex": b(p["duplex"]),
                                              "auto-negotiation": "done"}])
        if path == "/interface/bridge/host":
            return httpx.Response(200, json=self.hosts)
        if path == "/system/resource":
            return httpx.Response(200, json=self.resource)  # RouterOS returns an object
        return httpx.Response(404, json={"error": 404})


@pytest.fixture
def env(monkeypatch, tmp_path, db_factory):
    monkeypatch.setattr(settings, "AEGIS_SWITCH_URL", "http://192.0.2.10", raising=False)
    monkeypatch.setattr(settings, "AEGIS_SWITCH_USER", "aegis", raising=False)
    monkeypatch.setattr(settings, "AEGIS_SWITCH_PASSWORD", "test-pass", raising=False)
    monkeypatch.setattr(sc, "RETRY_BACKOFF", 0)
    monkeypatch.setenv("AEGIS_SWITCH_HOSTS_FILE", str(tmp_path / "switch_hosts.json"))
    fs = FakeSwitch()
    fs.port("ether1", rate="100Mbps")
    fs.port("ether2")
    fs.port("ether4", running=False, no_link=True)

    def make():
        client = sc.SwitchClient(transport=httpx.MockTransport(fs.handler))
        return sm.SwitchMonitor(session_factory=db_factory, client=client)

    class Env:
        pass
    e = Env()
    e.fs, e.make, e.db, e.hosts_file = fs, make, db_factory, tmp_path / "switch_hosts.json"
    return e


async def incidents(db):
    async with db() as s:
        return list((await s.execute(select(Incident).order_by(Incident.detected_at))).scalars())


async def reasons(db):
    return sorted(i.raw_alert["reason"] for i in await incidents(db)
                  if i.raw_alert.get("kind") == "switch_health")


async def baseline(env, mon, with_hosts=True):
    """One quiet cycle so deltas/transitions have a previous sample."""
    if with_hosts:
        env.fs.host("00:00:5E:00:53:10", "ether2")
    await mon.run_cycle(now=T0)


# ------------------------------------------------------------------ coercion
def test_coercion_is_defensive():
    assert sc.to_bool("true") is True and sc.to_bool("false") is False
    assert sc.to_bool(None) is None and sc.to_bool("maybe") is None and sc.to_bool(True) is True
    assert sc.to_int("61") == 61 and sc.to_int(" 7 ") == 7 and sc.to_int(5) == 5
    assert sc.to_int(None) is None and sc.to_int("x") is None and sc.to_int([1]) is None
    assert sc.to_int(True) is None
    assert sc.parse_rate_mbps("100Mbps") == 100 and sc.parse_rate_mbps("1Gbps") == 1000
    assert sc.parse_rate_mbps("2.5Gbps") == 2500
    assert sc.parse_rate_mbps(None) is None and sc.parse_rate_mbps("fast") is None


def test_normalize_interface_real_shape_and_garbage():
    raw = {".id": "*2", "name": "ether1", "type": "ether", "disabled": "false", "running": "true",
           "link-downs": "0", "rx-byte": "6045532626", "rx-error": "0", "rx-drop": "9",
           "tx-queue-drop": "3"}
    n = sc.normalize_interface(raw)
    assert n["running"] is True and n["disabled"] is False
    assert n["rx_byte"] == 6045532626 and n["rx_drop"] == 9 and n["tx_queue_drop"] == 3
    assert n["tx_error"] is None  # absent
    weird = sc.normalize_interface({"name": "x", "running": {"a": 1}, "link-downs": [3], "rx-error": None})
    assert weird["running"] is None and weird["link_downs"] is None and weird["rx_error"] is None


def test_normalize_monitor_without_link_has_no_rate_or_duplex():
    n = sc.normalize_monitor({"name": "ether4", "status": "no-link",
                              "auto-negotiation": "done", "link-partner-advertising": ""})
    assert n["rate"] is None and n["rate_mbps"] is None and n["full_duplex"] is None
    up = sc.normalize_monitor({"name": "ether1", "status": "link-ok", "rate": "100Mbps",
                               "full-duplex": "true"})
    assert up["rate_mbps"] == 100 and up["full_duplex"] is True


# ------------------------------------------------------------------ client
async def test_client_helpers_typed(env):
    c = sc.SwitchClient(transport=httpx.MockTransport(env.fs.handler))
    env.fs.host("00:00:5E:00:53:20", "ether2")
    ifaces = await c.get_interfaces()
    assert {i["name"] for i in ifaces} == {"ether1", "ether2", "ether4", "bridge"}
    assert (await c.get_ethernet())[0]["rx_overflow"] == 61
    assert (await c.monitor_port("ether1"))["rate_mbps"] == 100
    ether4 = await c.monitor_port("ether4")
    assert ether4["status"] == "no-link" and ether4["full_duplex"] is None
    assert (await c.get_bridge_hosts())[0]["mac"] == "00:00:5E:00:53:20"
    res = await c.get_resource()
    assert res["board"] == "Test Board" and res["cpu_load"] == 3 and res["total_memory"] == 1000


async def test_client_is_read_only(env):
    c = sc.SwitchClient(transport=httpx.MockTransport(env.fs.handler))
    for method, path in [("PUT", "/interface/ether1"), ("PATCH", "/interface/ether1"),
                         ("DELETE", "/interface/ether1"), ("POST", "/interface/ether1/disable"),
                         ("POST", "/system/reboot")]:
        assert await c._request(method, path, {}) is None
    assert env.fs.requests == []  # refused before anything left the process
    public = [m for m in dir(sc.SwitchClient) if not m.startswith("_")]
    assert all(m.startswith(("get_", "monitor_")) for m in public)


async def test_client_failures_are_swallowed(env):
    c = sc.SwitchClient(transport=httpx.MockTransport(env.fs.handler))
    env.fs.fail = True
    assert await c.get_interfaces() is None
    assert await c.get_bridge_hosts() is None
    assert await c.monitor_port("ether1") is None
    assert await c.get_resource() is None
    assert len(env.fs.requests) == 8  # one retry each

    def bad(request):
        return httpx.Response(401, json={"error": 401})
    unauth = sc.SwitchClient(transport=httpx.MockTransport(bad))
    assert await unauth.get_interfaces() is None

    html = sc.SwitchClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
    assert await html.get_interfaces() is None


# ------------------------------------------------------------------ disabled
async def test_disabled_without_url_is_total_noop(env, monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(settings, "AEGIS_SWITCH_URL", "", raising=False)
    mon = env.make()
    with caplog.at_level("DEBUG", logger="aegis"):
        await mon.start()
        await mon.run_cycle(now=T0)
        assert mon._task is None
        assert await sc.SwitchClient().get_interfaces() is None
    assert env.fs.requests == []
    assert not [r for r in caplog.records if r.name.startswith("aegis.switch")]
    assert not env.hosts_file.exists()
    assert await incidents(env.db) == []
    assert mon.status_view() == {"enabled": False}
    assert mon.ports_view() == {"enabled": False} and mon.devices_view() == {"enabled": False}


async def _api_client(monkeypatch, mon):
    from app.api import switch as switch_api
    from app.core.auth import get_auth_context
    from tests.unit.conftest import make_auth
    monkeypatch.setattr(switch_api, "switch_monitor", mon)
    app = FastAPI()
    app.include_router(switch_api.router, prefix="/api/v1")
    app.dependency_overrides[get_auth_context] = lambda: make_auth("viewer")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_api_disabled_returns_200_enabled_false(env, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_SWITCH_URL", "", raising=False)
    async with await _api_client(monkeypatch, env.make()) as c:
        for ep in ("status", "ports", "devices"):
            r = await c.get(f"/api/v1/switch/{ep}")
            assert r.status_code == 200 and r.json() == {"enabled": False}


async def test_api_requires_auth(monkeypatch):
    from app.api import switch as switch_api
    app = FastAPI()
    app.include_router(switch_api.router, prefix="/api/v1")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/switch/status")
    assert r.status_code in (401, 403)


async def test_api_endpoints_enabled(env, monkeypatch):
    env.fs.host("00:00:5E:00:53:10", "ether2")
    env.fs.host("00:00:5E:00:53:11", "ether2")
    env.fs.host("00:00:5E:00:53:01", "bridge", local=True)
    env.fs.host("B8:27:EB:00:00:01", "ether1")
    mon = env.make()
    await mon.run_cycle(now=T0)
    async with await _api_client(monkeypatch, mon) as c:
        st = (await c.get("/api/v1/switch/status")).json()
        assert st["enabled"] and st["board"] == "Test Board" and st["version"].startswith("7.15")
        assert st["cpu_load"] == 3 and st["memory"]["used_pct"] == 70.0
        ports = {p["name"]: p for p in (await c.get("/api/v1/switch/ports")).json()["ports"]}
        assert ports["ether2"]["devices"] == 2 and ports["ether1"]["devices"] == 1
        assert ports["ether1"]["rate"] == "100Mbps" and ports["ether1"]["full_duplex"] is True
        assert ports["ether4"]["running"] is False and ports["ether4"]["full_duplex"] is None
        assert ports["ether2"]["problems"] == []
        devs = (await c.get("/api/v1/switch/devices")).json()
        assert devs["count"] == 3  # local MAC excluded
        pi = next(d for d in devs["devices"] if d["mac"] == "B8:27:EB:00:00:01")
        assert pi["vendor"] == "Raspberry Pi" and pi["port"] == "ether1" and pi["online"]
        assert pi["first_seen"] and pi["last_seen"]


# ------------------------------------------------------------------ health conditions
async def test_quiet_switch_raises_nothing(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rx_error=50, rx_drop=900)   # below both thresholds
    await mon.run_cycle(now=T0 + MIN)
    assert await incidents(env.db) == []


async def test_high_absolute_counters_are_not_a_new_problem(env):
    env.fs.set("ether1", rx_error=999_999, rx_drop=9_999_999, fcs=5000)
    mon = env.make()
    await baseline(env, mon)
    await mon.run_cycle(now=T0 + MIN)
    assert await incidents(env.db) == []


async def test_link_flapping(env):
    env.fs.port("ether3")
    mon = env.make()
    await baseline(env, mon)
    await mon.run_cycle(now=T0 + MIN)
    env.fs.set("ether3", link_downs=2)
    await mon.run_cycle(now=T0 + 20 * MIN)
    assert await reasons(env.db) == []           # +2 is not enough
    env.fs.set("ether3", link_downs=3)
    await mon.run_cycle(now=T0 + 40 * MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("kind") == "switch_health"]
    assert [i.raw_alert["reason"] for i in inc] == ["link_flapping"]
    assert inc[0].severity == "high" and inc[0].raw_alert["port"] == "ether3"


async def test_link_downs_spread_over_more_than_an_hour_do_not_flap(env):
    mon = env.make()
    env.fs.port("ether3")
    await baseline(env, mon)
    for i, n in enumerate((1, 2, 3, 4)):
        env.fs.set("ether3", link_downs=n)
        await mon.run_cycle(now=T0 + (i + 1) * 40 * MIN)   # one new flap per 40 min
    assert "link_flapping" not in await reasons(env.db)


async def test_half_duplex(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False)
    await mon.run_cycle(now=T0 + MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("reason") == "half_duplex"]
    assert len(inc) == 1 and inc[0].severity == "high" and inc[0].raw_alert["port"] == "ether1"
    ports = {p["name"]: p for p in mon.ports_view()["ports"]}
    assert [p["reason"] for p in ports["ether1"]["problems"]] == ["half_duplex"]
    env.fs.set("ether1", duplex=True)            # state problems clear when fixed
    await mon.run_cycle(now=T0 + 2 * MIN)
    assert {p["name"]: p for p in mon.ports_view()["ports"]}["ether1"]["problems"] == []


async def test_half_duplex_not_reported_without_link(env):
    mon = env.make()
    await baseline(env, mon)
    await mon.run_cycle(now=T0 + MIN)            # ether4 has no link, no duplex info
    assert "half_duplex" not in await reasons(env.db)


async def test_errors_rising_sums_all_four_counters(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rx_error=30, tx_error=30, fcs=30, align=11)   # +101
    await mon.run_cycle(now=T0 + MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("reason") == "errors_rising"]
    assert len(inc) == 1 and inc[0].severity == "medium"


async def test_errors_at_threshold_do_not_fire(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rx_error=50, fcs=50)                          # exactly +100
    await mon.run_cycle(now=T0 + MIN)
    assert "errors_rising" not in await reasons(env.db)


async def test_drops_rising_sums_all_three_counters(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rx_drop=400, tx_drop=400, txq=201)            # +1001
    await mon.run_cycle(now=T0 + MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("reason") == "drops_rising"]
    assert len(inc) == 1 and inc[0].severity == "medium"


async def test_counter_reset_after_switch_reboot_is_not_an_alert(env):
    env.fs.set("ether2", rx_error=5000, rx_drop=50_000, link_downs=7)
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rx_error=3, rx_drop=2, link_downs=0)          # rebooted
    await mon.run_cycle(now=T0 + MIN)
    env.fs.set("ether2", rx_error=10, rx_drop=9, link_downs=1)
    await mon.run_cycle(now=T0 + 2 * MIN)
    assert await incidents(env.db) == []


async def test_speed_degraded_gigabit_to_100(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", rate="100Mbps")
    await mon.run_cycle(now=T0 + MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("reason") == "speed_degraded"]
    assert len(inc) == 1 and inc[0].severity == "medium" and inc[0].raw_alert["port"] == "ether2"


async def test_port_that_was_always_100_is_not_degraded(env):
    mon = env.make()
    await baseline(env, mon)                      # ether1 sits at 100Mbps by design
    await mon.run_cycle(now=T0 + MIN)
    assert "speed_degraded" not in await reasons(env.db)


async def test_port_down(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", running=False)
    await mon.run_cycle(now=T0 + MIN)
    inc = [i for i in await incidents(env.db) if i.raw_alert.get("reason") == "port_down"]
    assert len(inc) == 1 and inc[0].severity == "low" and inc[0].raw_alert["port"] == "ether2"


async def test_disabled_port_going_down_is_not_port_down(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether2", running=False, disabled=True)
    await mon.run_cycle(now=T0 + MIN)
    assert "port_down" not in await reasons(env.db)


async def test_port_never_up_is_not_port_down(env):
    mon = env.make()
    await baseline(env, mon)
    await mon.run_cycle(now=T0 + MIN)             # ether4 was down from the start
    assert "port_down" not in await reasons(env.db)


# ------------------------------------------------------------------ dedup
async def test_same_port_and_reason_is_not_repeated(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False)
    for i in range(1, 6):
        await mon.run_cycle(now=T0 + i * MIN)
    assert await reasons(env.db) == ["half_duplex"]


async def test_dedup_survives_restart_via_open_incident(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False)
    await mon.run_cycle(now=T0 + MIN)
    fresh = env.make()                             # new process: empty memory
    await fresh.run_cycle(now=T0 + 7 * 3600)       # past the 6h window, incident still open
    assert await reasons(env.db) == ["half_duplex"]


async def test_reraised_after_window_once_closed(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False)
    await mon.run_cycle(now=T0 + MIN)
    async with env.db() as s:
        for i in (await s.execute(select(Incident))).scalars():
            i.status = "resolved"
        await s.commit()
    await mon.run_cycle(now=T0 + 2 * MIN)          # inside window: still quiet
    assert len(await reasons(env.db)) == 1
    await mon.run_cycle(now=T0 + 7 * 3600)         # window over and nothing open
    assert await reasons(env.db) == ["half_duplex", "half_duplex"]


async def test_different_ports_same_reason_are_separate(env):
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False)
    env.fs.set("ether2", duplex=False)
    await mon.run_cycle(now=T0 + MIN)
    assert await reasons(env.db) == ["half_duplex", "half_duplex"]


# ------------------------------------------------------------------ inventory
async def test_first_cycle_seeds_silently_then_alerts(env):
    for i in range(1, 72):                          # a busy network on first boot
        env.fs.host(f"00:00:5E:00:53:{i:02X}", "ether2")
    mon = env.make()
    await mon.run_cycle(now=T0)
    assert await incidents(env.db) == []           # NOT 71 alerts
    assert env.hosts_file.exists()
    assert len(mon.devices_view()["devices"]) == 71
    await mon.run_cycle(now=T0 + MIN)              # nothing new -> still nothing
    assert await incidents(env.db) == []
    env.fs.host("B8:27:EB:00:53:99", "ether1")
    await mon.run_cycle(now=T0 + 2 * MIN)
    inc = await incidents(env.db)
    assert len(inc) == 1 and inc[0].severity == "low"
    assert "B8:27:EB:00:53:99" in inc[0].title and "ether1" in inc[0].title
    assert inc[0].raw_alert["vendor"] == "Raspberry Pi" and inc[0].raw_alert["seen_at"]
    await mon.run_cycle(now=T0 + 3 * MIN)          # already known: no repeat
    assert len(await incidents(env.db)) == 1


async def test_local_macs_are_not_inventoried(env):
    env.fs.host("00:00:5E:00:53:10", "ether2")
    env.fs.host("00:00:5E:00:53:01", "bridge", local=True)
    mon = env.make()
    await mon.run_cycle(now=T0)
    env.fs.host("00:00:5E:00:53:02", "bridge", local=True)
    await mon.run_cycle(now=T0 + MIN)
    assert [d["mac"] for d in mon.devices_view()["devices"]] == ["00:00:5E:00:53:10"]
    assert await incidents(env.db) == []


async def test_inventory_persists_across_restart_and_alerts_on_first_cycle(env):
    env.fs.host("00:00:5E:00:53:10", "ether2")
    await env.make().run_cycle(now=T0)             # seeds + saves
    data = json.loads(env.hosts_file.read_text())
    assert "00:00:5E:00:53:10" in data["hosts"]
    env.fs.host("00:00:5E:00:53:77", "ether3")
    restarted = env.make()
    await restarted.run_cycle(now=T0 + 5 * MIN)    # state exists: no silent seeding
    inc = await incidents(env.db)
    assert len(inc) == 1 and "00:00:5E:00:53:77" in inc[0].title
    saved = json.loads(env.hosts_file.read_text())["hosts"]
    assert saved["00:00:5E:00:53:10"]["first_seen"] != saved["00:00:5E:00:53:10"]["last_seen"]


async def test_corrupt_inventory_reseeds_silently(env):
    env.hosts_file.write_text("{not json")
    env.fs.host("00:00:5E:00:53:10", "ether2")
    mon = env.make()
    await mon.run_cycle(now=T0)
    assert await incidents(env.db) == []
    assert json.loads(env.hosts_file.read_text())["hosts"]


async def test_empty_first_poll_does_not_end_seeding(env):
    mon = env.make()
    await mon.run_cycle(now=T0)                    # bridge table still empty
    env.fs.host("00:00:5E:00:53:10", "ether2")
    await mon.run_cycle(now=T0 + MIN)              # this is the real seed
    assert await incidents(env.db) == []


async def test_device_moving_port_is_updated_not_alerted(env):
    env.fs.host("00:00:5E:00:53:10", "ether2")
    mon = env.make()
    await mon.run_cycle(now=T0)
    env.fs.hosts[0]["on-interface"] = "ether3"
    await mon.run_cycle(now=T0 + MIN)
    assert mon.devices_view()["devices"][0]["port"] == "ether3"
    assert await incidents(env.db) == []


def test_oui_lookup_offline_and_extensible(monkeypatch):
    assert sm.lookup_vendor("00:15:5d:aa:bb:cc") == "Microsoft (Hyper-V)"
    assert sm.lookup_vendor("08:00:27:00:00:01") == "VirtualBox"
    assert sm.lookup_vendor("00:00:5E:00:53:01").startswith("IANA")
    assert sm.lookup_vendor("02:11:22:33:44:55") == "desconocido"
    assert sm.lookup_vendor(None) == "desconocido"
    vendors = set(sm.OUI_VENDORS.values())
    assert {"Apple", "Raspberry Pi", "Espressif", "Intel", "TP-Link", "MikroTik",
            "Hewlett Packard"} <= vendors
    monkeypatch.setitem(sm.OUI_VENDORS, "02:11:22", "Acme")
    assert sm.lookup_vendor("02:11:22:33:44:55") == "Acme"


# ------------------------------------------------------------------ failure tolerance
async def test_switch_timeout_does_not_explode_or_wipe_state(env):
    env.fs.host("00:00:5E:00:53:10", "ether2")
    mon = env.make()
    await mon.run_cycle(now=T0)
    env.fs.fail = True
    await mon.run_cycle(now=T0 + MIN)              # must not raise
    assert mon.reachable is False
    assert await incidents(env.db) == []
    assert len(mon.devices_view()["devices"]) == 1  # inventory kept
    env.fs.fail = False
    await mon.run_cycle(now=T0 + 2 * MIN)
    assert mon.reachable is True and await incidents(env.db) == []


async def test_failed_monitor_call_does_not_erase_last_known_speed(env):
    mon = env.make()
    await baseline(env, mon)
    real = mon._client.monitor_port
    mon._client.monitor_port = AsyncMock(return_value=None)
    await mon.run_cycle(now=T0 + MIN)
    mon._client.monitor_port = real
    assert {p["name"]: p for p in mon.ports_view()["ports"]}["ether2"]["rate_mbps"] == 1000
    assert await incidents(env.db) == []


async def test_incident_store_failure_is_swallowed(env):
    def boom():
        raise RuntimeError("db down")
    mon = sm.SwitchMonitor(session_factory=boom,
                           client=sc.SwitchClient(transport=httpx.MockTransport(env.fs.handler)))
    env.fs.host("00:00:5E:00:53:10", "ether2")
    await mon.run_cycle(now=T0)
    env.fs.set("ether1", duplex=False)
    await mon.run_cycle(now=T0 + MIN)              # no raise


# ------------------------------------------------------------------ diagnostic only
async def test_never_blocks_and_never_carries_an_ip(env, ops_env):
    """Every health + inventory incident, with the firewall fully wired, must
    cause zero block calls and carry no source_ip for a responder to act on."""
    mon = env.make()
    await baseline(env, mon)
    env.fs.set("ether1", duplex=False, rx_error=500, rx_drop=5000)
    env.fs.set("ether2", rate="100Mbps", running=False)
    env.fs.host("00:00:5E:00:53:55", "ether3")
    await mon.run_cycle(now=T0 + MIN)
    inc = await incidents(env.db)
    assert len(inc) >= 5
    assert all(i.source_ip is None and i.source == "switch_monitor" for i in inc)
    assert not any(i.severity in ("critical",) for i in inc)
    ops_env.pi_block.assert_not_called()
    assert ops_env.sysfw.calls == []
    assert not ops_env.blocker._blocked


def test_modules_do_not_import_the_blocking_stack():
    root = Path(__file__).resolve().parents[2] / "app"
    banned = ("firewall_client", "firewall_local", "guardrails", "ip_blocker_service",
              "responder", "firewall_sync", "operator_block")
    for rel in ("core/switch_client.py", "services/switch_monitor.py", "api/switch.py"):
        tree = ast.parse((root / rel).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.add(node.module or "")
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
        assert not [n for n in names if any(b in n for b in banned)], (rel, names)


# ------------------------------------------------- inventory hygiene (audit M21)
async def test_burst_of_new_devices_is_one_incident(env):
    mon = env.make()
    await baseline(env, mon)
    for i in range(0x20, 0x2A):                     # ten phones with rotating MACs
        env.fs.host(f"00:00:5E:00:53:{i:02X}", "ether2")
    await mon.run_cycle(now=T0 + MIN)
    inc = await incidents(env.db)
    assert len(inc) == 1
    assert inc[0].raw_alert["kind"] == "switch_new_devices" and inc[0].raw_alert["count"] == 10
    assert "10 new devices" in inc[0].title


async def test_few_new_devices_still_get_individual_incidents(env):
    mon = env.make()
    await baseline(env, mon)
    for i in (0x30, 0x31):
        env.fs.host(f"00:00:5E:00:53:{i:02X}", "ether1")
    await mon.run_cycle(now=T0 + MIN)
    kinds = [i.raw_alert["kind"] for i in await incidents(env.db)]
    assert kinds == ["switch_new_device", "switch_new_device"]


async def test_unseen_devices_are_forgotten_and_visible_ones_kept(env):
    mon = env.make()
    await baseline(env, mon)                        # 00:00:5E:00:53:10 on ether2
    env.fs.host("00:00:5E:00:53:40", "ether1")
    await mon.run_cycle(now=T0 + MIN)
    env.fs.hosts = [h for h in env.fs.hosts if h["mac-address"].endswith(":10")]
    await mon.run_cycle(now=T0 + sm.INVENTORY_TTL_SECONDS + 10 * MIN)
    macs = {d["mac"] for d in mon.devices_view()["devices"]}
    assert macs == {"00:00:5E:00:53:10"}
    assert "00:00:5E:00:53:40" not in json.loads(env.hosts_file.read_text())["hosts"]


async def test_inventory_is_capped(env, monkeypatch):
    monkeypatch.setattr(sm, "INVENTORY_MAX_HOSTS", 5)
    mon = env.make()
    await baseline(env, mon)
    for i in range(0x50, 0x5A):
        mon._hosts[f"00:00:5E:00:53:{i:02X}"] = {"port": "ether2", "first_seen": sm._iso(T0),
                                                 "last_seen": sm._iso(T0 + i)}
    await mon.run_cycle(now=T0 + 500)
    assert len(mon._hosts) == 5 and "00:00:5E:00:53:10" in mon._hosts   # visible one survives
