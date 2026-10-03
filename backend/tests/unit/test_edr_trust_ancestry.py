"""Trust by ancestry, cold-start parents, the provisioning window, protected rules,
and attributable failed-logon bursts. Hosts and addresses are placeholders."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from . import edr_payloads as P
from .test_edr_rule_feed import engine, feed, fired  # noqa: F401  (engine is a fixture)

FLEET = "C:\\Program Files\\Example Fleet\\fleet-agent.exe"
INSTALLER = "E:\\Fleet-Setup\\INSTALL.bat"
SYS32 = "C:\\Windows\\System32\\"
RULE = "sigma_c2_encoded_powershell"
CMD = SYS32 + "cmd.exe"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
ENC = ("powershell.exe -NoProfile -WindowStyle Hidden -enc "
       "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("AEGIS_EDR_TRUSTED_PARENTS", "AEGIS_EDR_TRUSTED_INSTALLERS",
                 "AEGIS_EDR_PROVISIONING_GRACE_MIN"):
        monkeypatch.delenv(name, raising=False)


def start(pid, ppid, path, cmd=None, extra=None):
    return P.tauri_event("process_start", pid=pid, ppid=ppid, name=path.split("\\")[-1],
                         path=path, cmd=cmd or path, extra=extra)


def run(engine, *events):
    feed(engine, {"events": [
        {**e, "client_id": P.CLIENT_ID, "agent_id": P.AGENT_ID, "hostname": P.HOST}
        for e in events]})
    return fired(engine)


def judged(engine, pid):
    """The engine's copy of the event for `pid`."""
    return next(ev for _, ev in engine._window if ev.get("pid") == pid)


def test_grandchild_of_trusted_exe_is_trusted(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    alerts = run(engine, start(10, 4, FLEET), start(11, 10, CMD, "cmd /c x"),
                 start(12, 11, PS, ENC))
    assert RULE not in alerts
    ev = judged(engine, 12)
    assert ev["trusted_by"] == FLEET.lower()
    assert ev["trust_reason"] == "ancestor"


def test_direct_child_is_reason_parent(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    run(engine, start(10, 4, FLEET), start(12, 10, PS, ENC))
    assert judged(engine, 12)["trust_reason"] == "parent"


def test_untrusted_chain_still_fires(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    other = "C:\\Users\\public\\other.exe"
    alerts = run(engine, start(10, 4, other), start(11, 10, CMD, "cmd /c x"),
                 start(12, 11, PS, ENC))
    assert RULE in alerts


def test_broken_chain_is_not_trusted(monkeypatch, engine):
    """pid 11's parent (10) was never seen: the walk ends there."""
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    alerts = run(engine, start(11, 10, CMD, "cmd /c x"), start(12, 11, PS, ENC))
    assert RULE in alerts


def test_depth_is_bounded(monkeypatch, engine):
    from app.services.edr_trusted_parents import MAX_DEPTH

    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    chain = [start(10, 4, FLEET)]
    for i in range(1, MAX_DEPTH + 2):
        chain.append(start(10 + i, 9 + i, CMD, f"cmd /c {i}"))
    deepest = start(99, 10 + MAX_DEPTH + 1, PS, ENC)
    assert RULE in run(engine, *chain, deepest)


def test_within_depth_limit_is_trusted(monkeypatch, engine):
    from app.services.edr_trusted_parents import MAX_DEPTH

    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    chain = [start(10, 4, FLEET)]
    for i in range(1, MAX_DEPTH - 1):
        chain.append(start(10 + i, 9 + i, CMD, f"cmd /c {i}"))
    assert RULE not in run(engine, *chain, start(99, 10 + MAX_DEPTH - 2, PS, ENC))


def test_shell_can_never_be_a_trusted_root(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", CMD)
    alerts = run(engine, start(10, 4, CMD, "cmd /c a"), start(11, 10, PS, ENC))
    assert RULE in alerts


def test_exited_ancestor_breaks_the_chain(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    stop = P.tauri_event("process_stop", pid=11, ppid=10, path=CMD)
    alerts = run(engine, start(10, 4, FLEET), start(11, 10, CMD, "cmd /c x"), stop,
                 start(12, 11, PS, ENC))
    assert RULE in alerts


# -- protected rules -----------------------------------------------------------

def _ransom_rules(alerts):
    return {r for r in alerts if "ransom" in r or "shadow" in r or "vss" in r}


def test_ransomware_rules_fire_for_trusted_descendants(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    vss = start(31, 30, SYS32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
    alerts = run(engine, start(30, 4, FLEET), vss)
    assert judged(engine, 31)["trusted_by"] == FLEET.lower()
    assert "ransomware_vss_delete" in alerts


def test_is_protected_rule_classification():
    from app.services.edr_trusted_parents import is_protected_rule as p

    assert p({"id": "ransomware_vss_delete"})
    assert p({"id": "sigma_ransomware_canary_modified"})
    assert p({"id": "x_lsass_dump"})
    assert p({"id": "anything", "mitre": ["T1003.001"]})
    assert not p({"id": RULE, "mitre": ["T1059.001"]})
    assert not p({"id": "sigma_persist_scheduled_task"})
    assert not p({"id": "sigma_evasion_av_tamper"})


# -- cold start ------------------------------------------------------------------

def test_cold_start_parent_path_from_agent(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    alerts = run(engine, start(12, 777, PS, ENC, extra={"parent_path": FLEET}))
    assert RULE not in alerts
    assert judged(engine, 12)["trusted_by"] == FLEET.lower()


def test_cold_start_untrusted_parent_path_fires(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    alerts = run(engine, start(12, 777, PS, ENC, extra={"parent_path": "C:\\Temp\\x.exe"}))
    assert RULE in alerts


def test_server_record_of_parent_beats_the_agents_claim(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    impostor = "C:\\Users\\public\\dropper.exe"
    alerts = run(engine, start(10, 4, impostor),
                 start(12, 10, PS, ENC, extra={"parent_path": FLEET}))
    assert RULE in alerts


def test_agent_claim_is_not_read_from_details(monkeypatch, engine):
    """trusted_by is honoured only at the top level of the ingest-built dict."""
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    ev = start(12, 777, PS, ENC, extra={"trusted_by": FLEET, "trust_reason": "parent"})
    assert RULE in run(engine, ev)


# -- ingest route: stored audit, DB cold start, provisioning ---------------------

def ingest(monkeypatch, events, *, enrolled_at=None, db_parent=None):
    from app.api import edr as edr_api
    from app.services import edr_transport

    bus = P.Bus()
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    monkeypatch.setattr(edr_api, "event_bus", bus)
    monkeypatch.setattr(edr_api, "_ingest_trust", edr_api.TrustResolver())

    async def _no_chains(*a, **k):
        return []
    monkeypatch.setattr(edr_api, "evaluate_event", _no_chains)

    async def _lookup(db, agent_id, ppid, before=None, **k):
        return db_parent.get(ppid) if db_parent else None
    monkeypatch.setattr(edr_api, "resolve_parent_from_db", _lookup)

    agent = P.agent_row()
    agent.created_at = enrolled_at
    db = P.FakeDB(agent)
    payload = {"agent_id": P.AGENT_ID, "events_dropped_total": 0, "events": events}
    asyncio.run(edr_api.ingest_events(
        P._FakeRequest(payload), db=db, auth=SimpleNamespace(client_id=P.CLIENT_ID)))
    return bus.batches()[0]["events"], db.rows


def at(minutes_after, base):
    return (base + timedelta(minutes=minutes_after)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_ingest_stamps_stored_and_published_events(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    sent, rows = ingest(monkeypatch, [start(10, 4, FLEET), start(11, 10, CMD, "cmd /c x"),
                                      start(12, 11, PS, ENC)])
    assert "trusted_by" not in sent[0]
    assert sent[2]["trusted_by"] == FLEET.lower() and sent[2]["trust_reason"] == "ancestor"
    assert rows[2].details["trusted_by"] == FLEET.lower()
    assert "trusted_by" not in rows[0].details


def test_ingest_resolves_unseen_parent_from_stored_history(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    sent, rows = ingest(monkeypatch, [start(12, 500, PS, ENC)], db_parent={500: (FLEET, 4)})
    assert sent[0]["parent_path"] == FLEET
    assert sent[0]["trusted_by"] == FLEET.lower()
    assert rows[0].details["parent_path"] == FLEET


def test_ingest_uses_parent_path_the_agent_sent(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", FLEET)
    sent, _ = ingest(monkeypatch, [start(12, 500, PS, ENC, extra={"parent_path": FLEET})])
    assert sent[0]["trusted_by"] == FLEET.lower()


def test_ingest_without_config_stamps_nothing(monkeypatch):
    sent, rows = ingest(monkeypatch, [start(12, 500, PS, ENC, extra={"parent_path": FLEET})])
    assert "trusted_by" not in sent[0] and "trusted_by" not in rows[0].details


def _install_cmd():
    return start(20, 4, CMD, f"{CMD} /C {INSTALLER}")


def test_provisioning_window_trusts_installer_descendants(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", "15")
    base = datetime(2026, 10, 1, 21, 30)
    evs = [{**_install_cmd(), "at": at(3, base)},
           {**start(21, 20, PS, "powershell -Command Add-MpPreference -ExclusionPath 'C:\\Fleet'"),
            "at": at(3, base)}]
    sent, rows = ingest(monkeypatch, evs, enrolled_at=base)
    assert sent[0]["trusted_by"] == INSTALLER.lower() and sent[0]["trust_reason"] == "installer"
    assert sent[1]["trusted_by"] == INSTALLER.lower() and sent[1]["provisioning"] is True
    assert rows[1].details["provisioning"] is True


def test_provisioning_window_is_off_by_default(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    base = datetime(2026, 10, 1, 21, 30)
    sent, _ = ingest(monkeypatch, [{**_install_cmd(), "at": at(3, base)}], enrolled_at=base)
    assert "trusted_by" not in sent[0]


def test_provisioning_window_expires(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", "15")
    base = datetime(2026, 10, 1, 21, 30)
    sent, _ = ingest(monkeypatch, [{**_install_cmd(), "at": at(40, base)}], enrolled_at=base)
    assert "trusted_by" not in sent[0]


def test_installer_inheritance_ends_with_the_window(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", "15")
    base = datetime(2026, 10, 1, 21, 30)
    evs = [{**_install_cmd(), "at": at(14, base)},
           {**start(21, 20, PS, ENC), "at": at(20, base)}]
    sent, _ = ingest(monkeypatch, evs, enrolled_at=base)
    assert "trusted_by" in sent[0] and "trusted_by" not in sent[1]


def test_installer_path_merely_mentioned_is_not_an_installer(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", "15")
    base = datetime(2026, 10, 1, 21, 30)
    evs = [{**start(20, 4, CMD, f"{CMD} /C echo {INSTALLER}"), "at": at(1, base)},
           {**start(22, 4, CMD, f"{CMD} /C {INSTALLER} & evil.exe"), "at": at(1, base)}]
    sent, _ = ingest(monkeypatch, evs, enrolled_at=base)
    assert "trusted_by" not in sent[0] and "trusted_by" not in sent[1]


def test_provisioning_never_silences_ransomware(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_INSTALLERS", INSTALLER)
    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", "15")
    base = datetime(2026, 10, 1, 21, 30)
    vss = start(31, 20, SYS32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
    sent, _ = ingest(monkeypatch, [{**_install_cmd(), "at": at(1, base)},
                                   {**vss, "at": at(1, base)}], enrolled_at=base)
    assert sent[1]["trusted_by"] == INSTALLER.lower()
    feed(engine, {"events": sent})
    assert _ransom_rules(fired(engine))


def test_installer_entry_validation(caplog):
    import logging
    from app.services.edr_trusted_parents import parse_trusted_installers

    with caplog.at_level(logging.WARNING, logger="aegis.edr"):
        got = parse_trusted_installers(
            f"{INSTALLER}, install.bat, C:\\Windows\\System32\\cmd.exe, E:\\a\\..\\b.bat")
    assert got == frozenset({INSTALLER.lower()})


@pytest.mark.parametrize("raw,expected", [("", 0), ("abc", 0), ("-5", 0), ("15", 15), ("9999", 120)])
def test_grace_minutes_parsing(monkeypatch, raw, expected):
    from app.services.edr_trusted_parents import provisioning_grace_minutes

    monkeypatch.setenv("AEGIS_EDR_PROVISIONING_GRACE_MIN", raw)
    assert provisioning_grace_minutes() == expected


# -- failed-logon bursts ------------------------------------------------------------

def _node_event(details):
    return {"node_id": P.AGENT_ID, "event_type": "brute_force_attempt", "severity": "high",
            "details": details, "timestamp": "2026-10-01T21:34:00+00:00"}


@pytest.fixture(autouse=True)
def _reset_dedup():
    from app.api import nodes
    nodes._node_event_seen.clear()


def post_node(monkeypatch, payload):
    """POST /nodes/events without clearing the replay memory between calls."""
    from app.api import nodes as nodes_api
    from app.services import edr_transport

    monkeypatch.setattr(edr_transport, "event_bus", P.Bus())
    db = P.FakeDB(P.agent_row())
    resp = asyncio.run(nodes_api.receive_node_event(nodes_api.NodeEventRequest(**payload), db=db))
    return resp, db


def test_unattributed_burst_is_low_and_deduped_for_30_minutes(monkeypatch):
    legacy = {"event_id": 4625, "failures": "5+ in 60s", "source": "Security", "source_ip": "unknown"}
    _, db = post_node(monkeypatch, _node_event(legacy))
    assert len(db.rows) == 1
    assert db.rows[0].severity == "low"
    assert "unattributed: old agent, update node-tauri" in db.rows[0].description
    resp, db2 = post_node(monkeypatch, _node_event(legacy))
    assert db2.rows == [] and resp["ignored"] == "duplicate"
    # still deduped 20 minutes later, open again after 30
    from app.api import nodes
    for k in list(nodes._node_event_seen):
        nodes._node_event_seen[k] -= 1200
    assert post_node(monkeypatch, _node_event(legacy))[1].rows == []
    for k in list(nodes._node_event_seen):
        nodes._node_event_seen[k] -= 700
    assert len(post_node(monkeypatch, _node_event(legacy))[1].rows) == 1


def test_burst_with_target_account_opens_one_incident(monkeypatch):
    d = {"event_id": 4625, "source_ip": "local", "target_account": "svc-test",
         "logon_type": "3", "caller_process": "C:\\Windows\\System32\\svchost.exe"}
    _, db = post_node(monkeypatch, _node_event(d))
    assert len(db.rows) == 1
    assert "svc-test" in db.rows[0].description
    resp, db2 = post_node(monkeypatch, _node_event(d))
    assert db2.rows == [] and resp["ignored"] == "duplicate"


def test_burst_from_remote_source_is_kept(monkeypatch):
    d = {"event_id": 4625, "source_ip": "192.0.2.44", "target_account": ""}
    _, db = post_node(monkeypatch, _node_event(d))
    assert len(db.rows) == 1


def test_different_account_is_a_separate_incident(monkeypatch):
    a = {"source_ip": "local", "target_account": "alice"}
    b = {"source_ip": "local", "target_account": "bob"}
    assert len(post_node(monkeypatch, _node_event(a))[1].rows) == 1
    assert len(post_node(monkeypatch, _node_event(b))[1].rows) == 1


# -- stored-history lookup (real SQL, in-memory) --------------------------------------

def test_resolve_parent_from_db_reads_the_latest_start_before_the_event():
    pytest.importorskip("aiosqlite")
    from sqlalchemy import event as sa_event
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from app.models.endpoint_agent import AgentEvent, EventCategory
    from app.services.edr_trusted_parents import resolve_parent_from_db

    async def go():
        eng = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
        async with eng.begin() as conn:
            await conn.run_sync(AgentEvent.__table__.create)
        now = datetime(2026, 10, 1, 22, 0)

        def row(pid, path, ppid, ts, kind="process_start", agent="a1"):
            return AgentEvent(agent_id=agent, client_id="c1", category=EventCategory.process,
                              title="t", timestamp=ts,
                              details={"kind": kind, "pid": pid, "process_path": path, "ppid": ppid})
        async with async_sessionmaker(eng, expire_on_commit=False)() as s:
            s.add_all([
                row(500, "C:\\old\\reused.exe", 1, now - timedelta(hours=11)),
                row(500, FLEET, 4, now - timedelta(minutes=30)),
                row(500, FLEET, 4, now - timedelta(minutes=20), kind="process_stop"),
                row(500, "C:\\other\\agent.exe", 1, now - timedelta(minutes=5), agent="a2"),
                row(500, "C:\\after\\later.exe", 1, now + timedelta(minutes=5)),
            ])
            await s.commit()
            assert await resolve_parent_from_db(s, "a1", 500, before=now) == (FLEET, 4)
            assert await resolve_parent_from_db(s, "a1", 999, before=now) is None
        await eng.dispose()

    asyncio.run(go())
