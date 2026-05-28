"""
Tests for the Response module (incident response).

Covers:
- Incident listing and retrieval
- Action listing
- Guardrails retrieval and update
- Tenant scoping
"""

import pytest

from tests.conftest import api_key_headers, jwt_headers


# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_incidents_empty(client, test_client_a):
    """List incidents when none exist returns empty list."""
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/response/incidents", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_incidents_returns_owned(
    client, test_client_a, sample_incident_a
):
    """Listing incidents returns those belonging to the tenant."""
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/response/incidents", headers=headers)
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "SSH Brute Force from 45.33.32.156"
    assert incidents[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_get_incident_by_id(
    client, test_client_a, sample_incident_a
):
    """Retrieve a single incident by ID."""
    headers = api_key_headers(test_client_a)
    resp = await client.get(
        f"/api/v1/response/incidents/{sample_incident_a.id}", headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["source_ip"] == "45.33.32.156"
    assert data["mitre_technique"] == "T1110.001"


@pytest.mark.asyncio
async def test_get_incident_not_found(client, test_client_a):
    """Non-existent incident returns 404."""
    headers = api_key_headers(test_client_a)
    resp = await client.get(
        "/api/v1/response/incidents/nonexistent", headers=headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_incidents_filter_by_severity(
    client, test_client_a, sample_incident_a
):
    """Filter incidents by severity query param."""
    headers = api_key_headers(test_client_a)
    resp = await client.get(
        "/api/v1/response/incidents?severity=high", headers=headers
    )
    assert len(resp.json()) == 1

    resp2 = await client.get(
        "/api/v1/response/incidents?severity=low", headers=headers
    )
    assert len(resp2.json()) == 0


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_actions(
    client, test_client_a, sample_action_a
):
    """List actions returns those belonging to the tenant."""
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/response/actions", headers=headers)
    assert resp.status_code == 200
    actions = resp.json()
    assert len(actions) == 1
    assert actions[0]["action_type"] == "block_ip"
    assert actions[0]["status"] == "pending"
    assert actions[0]["requires_approval"] is True


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_guardrails(client, test_client_a):
    """Get guardrail configuration for the tenant."""
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/response/guardrails", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "guardrails" in data
    assert data["guardrails"]["block_ip"] == "auto_approve"
    assert data["guardrails"]["shutdown_service"] == "never_auto"


@pytest.mark.asyncio
async def test_update_guardrails_admin_only(
    client, test_client_a, admin_user_a
):
    """Admin can update guardrail configuration."""
    headers = jwt_headers(admin_user_a, test_client_a)
    resp = await client.put(
        "/api/v1/response/guardrails",
        json={
            "guardrails": {
                "block_ip": "require_approval",
                "isolate_host": "never_auto",
            }
        },
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["guardrails"]["block_ip"] == "require_approval"


@pytest.mark.asyncio
async def test_update_guardrails_viewer_forbidden(
    client, test_client_a, viewer_user_a
):
    """Viewer cannot update guardrails."""
    headers = jwt_headers(viewer_user_a, test_client_a)
    resp = await client.put(
        "/api/v1/response/guardrails",
        json={"guardrails": {"block_ip": "never_auto"}},
        headers=headers,
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Bug 2: Reject action
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reject_action_returns_200_and_sets_rejected(
    client, test_client_a, sample_action_a, admin_user_a
):
    """POST /response/actions/{id}/reject marks action status='rejected'."""
    headers = jwt_headers(admin_user_a, test_client_a)
    resp = await client.post(
        f"/api/v1/response/actions/{sample_action_a.id}/reject",
        json={"reason": "False positive — internal scanner"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "rejected"
    assert data["action_id"] == sample_action_a.id


@pytest.mark.asyncio
async def test_reject_action_persists_in_db(
    client, test_client_a, sample_action_a, admin_user_a
):
    """After rejection, the API response confirms status='rejected' and the list endpoint agrees."""
    headers = jwt_headers(admin_user_a, test_client_a)
    resp = await client.post(
        f"/api/v1/response/actions/{sample_action_a.id}/reject",
        json={"reason": "test reason"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"

    # Confirm via list endpoint — the action should now appear as rejected
    list_resp = await client.get("/api/v1/response/actions", headers=headers)
    assert list_resp.status_code == 200
    actions = list_resp.json()
    target = next((a for a in actions if a["id"] == sample_action_a.id), None)
    assert target is not None, "Action not found in list"
    assert target["status"] == "rejected"
    assert target["requires_approval"] is False


@pytest.mark.asyncio
async def test_reject_already_rejected_action_returns_400(
    client, test_client_a, sample_action_a, admin_user_a
):
    """Rejecting an already-rejected action returns 400."""
    headers = jwt_headers(admin_user_a, test_client_a)
    # First rejection
    await client.post(
        f"/api/v1/response/actions/{sample_action_a.id}/reject",
        json={},
        headers=headers,
    )
    # Second rejection attempt
    resp = await client.post(
        f"/api/v1/response/actions/{sample_action_a.id}/reject",
        json={},
        headers=headers,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# IP blocking (guardrails enforcement)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_guardrail_auto_approve_creates_approved_action(
    db_session, test_client_a, sample_incident_a
):
    """When guardrail is auto_approve, action status should be 'approved'."""
    from app.core.guardrails import guardrail_engine

    action = await guardrail_engine.evaluate_action(
        client=test_client_a,
        action_type="block_ip",
        target="1.2.3.4",
        ai_reasoning="Brute force detected",
        db=db_session,
        incident_id=sample_incident_a.id,
    )
    assert action.status == "approved"
    assert action.requires_approval is False


@pytest.mark.asyncio
async def test_guardrail_require_approval_creates_pending_action(
    db_session, test_client_a, sample_incident_a
):
    """When guardrail is require_approval, action should be 'pending'."""
    from app.core.guardrails import guardrail_engine

    action = await guardrail_engine.evaluate_action(
        client=test_client_a,
        action_type="isolate_host",
        target="192.168.1.50",
        ai_reasoning="Lateral movement detected",
        db=db_session,
        incident_id=sample_incident_a.id,
    )
    assert action.status == "pending"
    assert action.requires_approval is True


@pytest.mark.asyncio
async def test_guardrail_never_auto_blocks(
    db_session, test_client_a, sample_incident_a
):
    """When guardrail is never_auto, action should be 'pending' and require approval."""
    from app.core.guardrails import guardrail_engine

    action = await guardrail_engine.evaluate_action(
        client=test_client_a,
        action_type="shutdown_service",
        target="nginx",
        ai_reasoning="Compromised service",
        db=db_session,
        incident_id=sample_incident_a.id,
    )
    assert action.status == "pending"
    assert action.requires_approval is True
