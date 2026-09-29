"""Endpoint-agent telemetry must reach the Sigma engine, and an endpoint
detection must become an incident about the HOST without ever giving the
responder an address to block.

Before this, three things were broken in series:
  1. POST /edr/events stored the batch and published only `edr.batch` (a
     dashboard counter). The engine subscribes to `edr.event` /
     `edr.process_start`, so agent events never entered evaluate().
  2. _on_edr_event stamped source_ip=127.0.0.1 on every host event and
     _on_rule_triggered dropped any firing from an internal IP, so an endpoint
     rule could fire and still never become an incident.
  3. Host-scoped incidents all carry source_ip=NULL, so the dedup lookup would
     have folded every host's repeat of a rule into one row.

These drive the REAL engine, the REAL ingest route function and the REAL
ai_engine.process_alert; only the DB session and the bus transport are faked.
"""
from __future__ import annotations

import asyncio
import gzip
import json
from datetime import datetime
from types import SimpleNamespace

import pytest

HOST = "ws-finance-01.example.test"
AGENT_ID = "agent-0001"
CLIENT_ID = "client-0001"
T0 = 1_800_000_000.0


class _Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class _Bus:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    async def publish(self, topic, data=None, *a, **k):
        self.published.append((topic, data))

    publish_critical = publish
    publish_high = publish

    def subscribe(self, *a, **k):
        pass


@pytest.fixture
def engine(monkeypatch):
    from app.services import correlation_engine as ce

    monkeypatch.setattr(ce, "_now_ts", _Clock())
    eng = ce.CorrelationEngine()
    if getattr(eng, "_watcher", None) is not None:
        try:
            eng._watcher.stop()
        except Exception:
            pass
        eng._watcher = None
    eng._event_bus = _Bus()
    eng.incidents = []

    async def _create_incident(rule, alert):
        eng.incidents.append((rule.get("id"), alert))

    async def _fast_triage(event, matches):
        return None

    eng._create_incident = _create_incident
    eng._run_fast_triage = _fast_triage
    return eng


def run(coro, eng=None):
    async def _wrapped():
        result = await coro
        for _ in range(4):
            await asyncio.sleep(0)
        if eng is not None and eng._edr_batch_tasks:
            await asyncio.gather(*list(eng._edr_batch_tasks))
        for _ in range(4):
            await asyncio.sleep(0)
        return result
    return asyncio.run(_wrapped())


# ---------------------------------------------------------------------------
# A fake ingest environment: real route function, fake DB, capturing bus
# ---------------------------------------------------------------------------

class _FakeRequest:
    def __init__(self, payload: dict, gz: bool = False):
        raw = json.dumps(payload).encode()
        self._raw = gzip.compress(raw) if gz else raw
        self.headers = {"content-encoding": "gzip"} if gz else {}

    async def body(self):
        return self._raw


class _FakeDB:
    def __init__(self, agent):
        self.agent = agent
        self.rows = []

    async def get(self, _model, _id):
        return self.agent

    def add(self, row):
        self.rows.append(row)

    async def commit(self):
        pass


def _agent():
    return SimpleNamespace(id=AGENT_ID, client_id=CLIENT_ID, hostname=HOST)


def _agent_batch(n_noise=0):
    """What node-tauri/src-tauri/src/edr/uploader.rs POSTs."""
    events = [
        {"kind": "process_start", "at": "2026-09-29T10:00:00Z", "pid": 4242,
         "ppid": 1000, "process_name": "vssadmin.exe",
         "process_path": "C:\\Windows\\System32\\vssadmin.exe",
         "command_line": "vssadmin.exe delete shadows /all /quiet",
         "user": "EXAMPLE\\svc-backup"},
        # a kind the engine does not map yet: it must still be DELIVERED
        {"kind": "dns_query", "at": "2026-09-29T10:00:01Z", "target": "example.test"},
    ]
    for i in range(n_noise):
        events.append({"kind": "process_start", "at": "2026-09-29T10:00:02Z",
                       "pid": 5000 + i, "ppid": 1, "process_name": "svchost.exe",
                       "process_path": "C:\\Windows\\System32\\svchost.exe",
                       "command_line": "svchost.exe -k netsvcs"})
    return {"agent_id": AGENT_ID, "events_dropped_total": 0, "events": events}


def _post_batch(monkeypatch, payload, gz=False):
    """Run the real POST /edr/events handler; return the bus it published on."""
    from app.api import edr as edr_api
    from app.services import edr_transport

    bus = _Bus()
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    monkeypatch.setattr(edr_api, "event_bus", bus)

    async def _no_chains(*a, **k):
        return []
    monkeypatch.setattr(edr_api, "evaluate_event", _no_chains)

    auth = SimpleNamespace(client_id=CLIENT_ID)
    out = asyncio.run(edr_api.ingest_events(
        _FakeRequest(payload, gz=gz), db=_FakeDB(_agent()), auth=auth,
    ))
    return bus, out


# ---------------------------------------------------------------------------
# (a) transport: every event of a posted batch reaches _on_edr_event
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("gz", [False, True])
def test_posted_agent_batch_reaches_on_edr_event(engine, monkeypatch, gz):
    payload = _agent_batch(n_noise=20)
    bus, out = _post_batch(monkeypatch, payload, gz=gz)
    assert out.accepted == len(payload["events"])

    batches = [d for t, d in bus.published if t == "edr.event_batch"]
    assert len(batches) == 1, "one bus message per batch, not one per event"

    seen = []
    original = engine._on_edr_event

    async def spy(data):
        seen.append(data)
        await original(data)

    engine._on_edr_event = spy
    run(engine._on_edr_batch(batches[0]), engine)

    assert len(seen) == len(payload["events"])
    assert {e["kind"] for e in seen} == {"process_start", "dns_query"}
    assert all(e["hostname"] == HOST and e["agent_id"] == AGENT_ID for e in seen)
    vss = next(e for e in seen if e["process_name"] == "vssadmin.exe")
    assert vss["command_line"].startswith("vssadmin.exe delete shadows")


def test_engine_subscribes_to_the_batch_topic():
    from app.services import correlation_engine as ce
    from app.services import edr_transport

    assert edr_transport.EDR_BATCH_TOPIC == ce._EDR_BATCH_TOPIC

    class Bus(_Bus):
        topics = []

        def subscribe(self, topic, handler):
            self.topics.append(topic)

    eng = ce.CorrelationEngine()
    if getattr(eng, "_watcher", None) is not None:
        eng._watcher = None
    eng._event_bus = Bus()

    async def go():
        await eng.start()
        await eng.stop()
    asyncio.run(go())
    assert ce._EDR_BATCH_TOPIC in Bus.topics


def test_large_batch_does_not_hold_the_bus(engine, monkeypatch):
    """The bus runs handlers serially; the batch handler must return at once and
    drain in the background, yielding between events."""
    payload = _agent_batch(n_noise=1500)
    bus, _ = _post_batch(monkeypatch, payload)
    batch = next(d for t, d in bus.published if t == "edr.event_batch")

    async def go():
        await engine._on_edr_batch(batch)
        # returned before the drain finished
        assert engine._edr_batch_tasks
        assert engine._stats["events_processed"] < len(payload["events"])
        await asyncio.gather(*list(engine._edr_batch_tasks))
        assert engine._stats["events_processed"] >= 1500
    asyncio.run(go())


# ---------------------------------------------------------------------------
# (b) an endpoint detection becomes an incident attributed to the host
# ---------------------------------------------------------------------------

def _vss_batch_through_engine(engine, monkeypatch):
    bus, _ = _post_batch(monkeypatch, _agent_batch())
    batch = next(d for t, d in bus.published if t == "edr.event_batch")
    run(engine._on_edr_batch(batch), engine)


def test_edr_process_event_opens_incident_about_the_host(engine, monkeypatch):
    _vss_batch_through_engine(engine, monkeypatch)

    fired = [(rid, a) for rid, a in engine.incidents if rid == "ransomware_vss_delete"]
    assert fired, f"no incident for the vss rule; got {[r for r, _ in engine.incidents]}"
    _rid, alert = fired[0]
    assert alert["host"] == HOST
    assert alert["source_ip"] is None
    assert alert["source"] == "correlation_engine"
    assert alert["severity"] == "critical"


def test_host_incidents_for_two_hosts_are_kept_separate(engine):
    async def go():
        for host in ("ws-a.example.test", "ws-b.example.test"):
            await engine._on_edr_event({
                "kind": "process_start", "hostname": host, "agent_id": host,
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
            })
    run(go())
    hosts = {a["host"] for rid, a in engine.incidents if rid == "ransomware_vss_delete"}
    assert hosts == {"ws-a.example.test", "ws-b.example.test"}


def test_host_event_does_not_feed_the_campaign_tracker(engine):
    from app.services import correlation_engine as ce

    before = {k: set(v) for k, v in ce._campaign_tracker._ip_phases.items()}
    run(engine._on_edr_event({
        "kind": "process_start", "hostname": HOST, "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
    }))
    after = {k: set(v) for k, v in ce._campaign_tracker._ip_phases.items()}
    assert after == before


# ---------------------------------------------------------------------------
# (c) that incident yields no block against a local / internal address
# ---------------------------------------------------------------------------

def test_host_alert_gives_ip_actions_nothing_to_target(engine, monkeypatch):
    from app.services.ai_engine import RESPONSE_ACTIONS, resolve_action_target

    _vss_batch_through_engine(engine, monkeypatch)
    _rid, alert = next(x for x in engine.incidents if x[0] == "ransomware_vss_delete")

    for action in ("block_ip", "firewall_rule"):
        target, _why = resolve_action_target(action, alert)
        assert target is None, f"{action} would run against {target!r}"
    # and no action of any kind resolves to a loopback / private address
    import ipaddress
    for actions in RESPONSE_ACTIONS.values():
        for action in actions:
            target, _ = resolve_action_target(action, alert)
            if target is None:
                continue
            try:
                ipaddress.ip_address(target)
            except ValueError:
                continue
            pytest.fail(f"{action} resolved to IP {target}")


def test_process_alert_on_host_alert_never_blocks_an_ip(engine, monkeypatch):
    """Drive the real ai_engine.process_alert with the real host alert, for
    every threat class the triage could choose."""
    import uuid
    from app.services import ai_engine as ae

    _vss_batch_through_engine(engine, monkeypatch)
    _rid, alert = next(x for x in engine.incidents if x[0] == "ransomware_vss_delete")

    class DB:
        def add(self, o):
            if getattr(o, "id", None) is None:
                o.id = str(uuid.uuid4())

        async def commit(self):
            pass

        async def refresh(self, o):
            pass

    calls, unsupported, pending = [], [], []

    async def evaluate_action(*, client, action_type, target, **kw):
        calls.append((action_type, target))
        return SimpleNamespace(id="a", action_type=action_type, status="x",
                               requires_approval=True)

    async def create_unsupported(*, action_type, **kw):
        unsupported.append(action_type)
        return SimpleNamespace(id="u", action_type=action_type,
                               status="skipped_not_applicable", requires_approval=False)

    async def create_pending(*, target, **kw):
        pending.append(target)
        return SimpleNamespace(id="p", action_type="block_ip", status="pending",
                               requires_approval=True)

    async def noop(*a, **k):
        return None

    eng = ae.AIEngine() if hasattr(ae, "AIEngine") else ae.ai_engine
    monkeypatch.setattr(ae.guardrail_engine, "evaluate_action", evaluate_action)
    monkeypatch.setattr(eng, "_create_unsupported_action", create_unsupported)
    monkeypatch.setattr(eng, "_create_pending_block", create_pending)
    monkeypatch.setattr(eng, "_log_audit", noop)
    monkeypatch.setattr(ae.event_bus, "publish", noop)

    client = SimpleNamespace(id=CLIENT_ID)
    for threat in ("unknown", "ransomware", "rce", "malware", "c2_communication",
                   "data_exfiltration", "lateral_movement"):
        calls.clear(), unsupported.clear(), pending.clear()

        async def triage(_alert, _t=threat):
            return {"severity": "critical", "threat_type": _t, "summary": "x",
                    "confidence": 0.9, "mitre_technique": "", "mitre_tactic": ""}
        monkeypatch.setattr(eng, "_triage", triage)
        result = asyncio.run(eng.process_alert(dict(alert), client, DB()))

        assert result["source_ip"] is None
        assert not pending, f"{threat}: pending block against {pending}"
        for action_type, target in calls:
            assert action_type not in ("block_ip", "firewall_rule"), (threat, action_type, target)
            assert target not in ("127.0.0.1", None), (threat, action_type, target)


# ---------------------------------------------------------------------------
# (d) network / log events keep the existing gate
# ---------------------------------------------------------------------------

def test_internal_ip_network_event_is_still_dropped(engine):
    async def go():
        for _ in range(4):
            await engine.evaluate({
                "event_type": "http_request", "source_ip": "10.1.2.3",
                "request_path": "/uploads/sh.php", "path": "/uploads/sh.php",
                "request_method": "POST", "response_status": 200, "source": "sable",
            })
        await engine.evaluate({
            "event_type": "web_request", "source_ip": "192.168.1.9",
            "request_path": "/static/../../../../etc/passwd",
            "path": "/static/../../../../etc/passwd",
            "request_method": "GET", "response_status": 200, "source": "sable",
        })
    run(go())
    assert engine.incidents == []
    assert not [d for t, d in engine._event_bus.published if t == "correlation_triggered"]


def test_loopback_event_without_the_host_flag_is_still_dropped(engine):
    """Same rule, same command line, but not marked host-only: it is a network
    event claiming to be 127.0.0.1 and must hit the IP gate exactly as before."""
    run(engine.evaluate({
        "event_type": "process_creation", "source_ip": "127.0.0.1",
        "hostname": HOST, "process_name": "vssadmin.exe",
        "cmdline": "vssadmin.exe delete shadows /all /quiet", "source": "edr",
    }))
    assert engine.incidents == []


def test_edr_event_carrying_its_own_internal_source_ip_keeps_the_gate(engine):
    run(engine._on_edr_event({
        "kind": "process_start", "hostname": HOST, "source_ip": "10.9.8.7",
        "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
    }))
    assert engine.incidents == []


def test_edr_event_without_any_host_identity_is_dropped(engine, monkeypatch):
    from app.services import correlation_engine as ce
    monkeypatch.setattr(ce, "_LOCAL_HOSTNAME", "")
    run(engine._on_edr_event({
        "kind": "process_start", "process_name": "vssadmin.exe",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
    }))
    assert engine.incidents == []


# ---------------------------------------------------------------------------
# (e) dedup is per host when there is no source IP
# ---------------------------------------------------------------------------

def test_find_recent_incident_is_scoped_to_the_host():
    from app.services.firewall_sync import find_recent_incident

    def inc(host):
        return SimpleNamespace(
            raw_alert={"pattern": "ransomware_vss_delete", "host": host},
            ai_analysis={}, detected_at=datetime.utcnow(),
        )

    a, b = inc("ws-a.example.test"), inc("ws-b.example.test")

    class Res:
        def scalars(self):
            return self

        def all(self):
            return [a, b]

    class DB:
        async def execute(self, _q):
            return Res()

    async def look(host):
        return await find_recent_incident(
            DB(), client_id=CLIENT_ID, source_ip=None, source="correlation_engine",
            kind="ransomware_vss_delete", host=host,
        )

    assert asyncio.run(look("ws-b.example.test")) is b
    assert asyncio.run(look("ws-c.example.test")) is None
