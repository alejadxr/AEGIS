"""Who may post as an enrolled node over HTTP (audit A7, M17, B14)."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api import nodes
from app.config import settings
from app.core.auth import hash_node_token


def _agent(agent_id="node-1", token=None):
    return SimpleNamespace(id=agent_id, node_token_hash=hash_node_token(token) if token else None)


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.delenv("AEGIS_NODE_SECRET", raising=False)
    monkeypatch.setattr(settings, "AEGIS_NODE_REQUIRE_TOKEN", False)


def test_nobody_posts_as_the_in_process_host_monitor():
    from app.services.host_monitor import AGENT_ID
    with pytest.raises(HTTPException) as exc:
        nodes._authorize_node_post(_agent(AGENT_ID), None, None)
    assert exc.value.status_code == 403


def test_a_presented_token_must_belong_to_the_named_node():
    agent = _agent("node-1", token="right")
    nodes._authorize_node_post(agent, "right", "node-1")          # ok
    for token, node_id in (("wrong", "node-1"), ("right", "node-2"), ("right", None)):
        with pytest.raises(HTTPException) as exc:
            nodes._authorize_node_post(agent, token, node_id)
        assert exc.value.status_code == 401


def test_a_token_for_a_node_that_has_none_is_rejected_not_ignored():
    with pytest.raises(HTTPException):
        nodes._authorize_node_post(_agent("node-1"), "anything", "node-1")


def test_compat_mode_still_accepts_older_agents():
    nodes._authorize_node_post(_agent("node-1", token="t"), None, None)


def test_strict_mode_requires_the_token_from_a_node_that_holds_one(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_NODE_REQUIRE_TOKEN", True)
    with pytest.raises(HTTPException) as exc:
        nodes._authorize_node_post(_agent("node-1", token="t"), None, None)
    assert exc.value.status_code == 401
    nodes._authorize_node_post(_agent("node-1", token="t"), "t", "node-1")


def test_shared_secret_comparison_rejects_wrong_and_missing(monkeypatch):
    monkeypatch.setenv("AEGIS_NODE_SECRET", "s3cret")
    nodes._verify_node_secret("s3cret")
    for bad in (None, "", "s3cre", "S3CRET"):
        with pytest.raises(HTTPException):
            nodes._verify_node_secret(bad)


@pytest.mark.parametrize("field,value", [
    ("hostname", "pc\n[DETECT] ip=198.51.100.7"),
    ("hostname", "x" * 300),
    ("enroll_code", "A" * 64),
    ("local_ip", "10.0.0.1; rm -rf"),
    ("os_name", "<script>"),
])
def test_announce_rejects_hostile_free_text(field, value):
    base = {"enroll_code": "ABCD-1234", "hostname": "pc-01"}
    with pytest.raises(ValidationError):
        nodes.AnnounceRequest(**{**base, field: value})


def test_announce_accepts_ordinary_values():
    nodes.AnnounceRequest(enroll_code="ABCD-1234", hostname="DESKTOP-AB12CD",
                          os_name="Windows 11", os_version="10.0.26100", local_ip="192.0.2.4")


async def test_pending_announcements_are_capped(monkeypatch):
    monkeypatch.setattr(nodes, "_pending_enrollments", {})
    monkeypatch.setattr(nodes, "_MAX_PENDING_ANNOUNCEMENTS", 3)
    for i in range(3):
        await nodes.announce_node(nodes.AnnounceRequest(enroll_code=f"CODE-{i}", hostname="pc"))
    with pytest.raises(HTTPException) as exc:
        await nodes.announce_node(nodes.AnnounceRequest(enroll_code="CODE-9", hostname="pc"))
    assert exc.value.status_code == 429
    # A code already announced can still poll/re-announce.
    await nodes.announce_node(nodes.AnnounceRequest(enroll_code="CODE-1", hostname="pc"))


def test_node_event_fields_are_bounded():
    nodes.NodeEventRequest(node_id="n", event_type="suspicious_process", severity="high")
    for kwargs in ({"event_type": "x\ny"}, {"event_type": "a" * 100}, {"details": {"k": "v" * 40000}}):
        with pytest.raises(ValidationError):
            nodes.NodeEventRequest(**{"node_id": "n", "event_type": "ok", **kwargs})
