"""Legacy /nodes/events: attribution to the host, never the agent's LAN address."""
from __future__ import annotations

from . import edr_payloads as P


def _payload(event_type, severity):
    return {"node_id": P.AGENT_ID, "event_type": event_type, "severity": severity,
            "details": {"name": "cmd.exe", "reasons": ["shell"]},
            "timestamp": "2026-09-29T10:00:00+00:00"}


def test_suspicious_process_opens_no_direct_incident(monkeypatch):
    _, db = P.through_nodes_route(monkeypatch, _payload("suspicious_process", "critical"))
    assert db.rows == []


def test_other_high_events_are_host_attributed_without_lan_ip(monkeypatch):
    _, db = P.through_nodes_route(monkeypatch, _payload("fim_tamper", "high"))
    assert len(db.rows) == 1
    inc = db.rows[0]
    assert inc.source_ip is None
    assert P.LOCAL_ADDR not in (inc.description or "")
    assert inc.raw_alert["host"] == P.HOST
    assert inc.title == "EDR: fim_tamper"
    assert P.HOST in inc.description
