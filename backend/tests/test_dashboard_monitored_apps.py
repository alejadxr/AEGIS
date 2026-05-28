"""
Tests for GET /api/v1/dashboard/monitored-apps endpoint.

Covers:
- Returns 200 with correct envelope {apps, count} when apps are configured
- Returns empty apps list when AEGIS_MONITORED_APPS is blank
"""

import pytest
from unittest.mock import patch, MagicMock

from tests.conftest import api_key_headers


# ---------------------------------------------------------------------------
# Test: returns 200 with envelope when apps are configured
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_monitored_apps_returns_200_with_apps(client, test_client_a):
    """GET /dashboard/monitored-apps returns {apps, count} with status 200."""
    mock_settings = MagicMock()
    mock_settings.AEGIS_MONITORED_APPS = "sable,wilabia-frontend,wilabia-backend"

    with patch("app.api.dashboard.settings", mock_settings):
        # Patch pm2 to return empty (no pm2 on test host)
        with patch("app.api.dashboard._get_pm2_statuses", return_value={}):
            headers = api_key_headers(test_client_a)
            resp = await client.get("/api/v1/dashboard/monitored-apps", headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert "apps" in data
    assert "count" in data
    assert data["count"] == 3
    assert len(data["apps"]) == 3
    names = [a["name"] for a in data["apps"]]
    assert "sable" in names
    assert "wilabia-frontend" in names

    # Each app has required fields
    for app in data["apps"]:
        assert "name" in app
        assert "status" in app
        assert "open_incidents" in app
        assert "resolved_count" in app


# ---------------------------------------------------------------------------
# Test: returns empty list when no apps configured
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_monitored_apps_empty_when_not_configured(client, test_client_a):
    """Returns empty apps list when AEGIS_MONITORED_APPS is blank."""
    mock_settings = MagicMock()
    mock_settings.AEGIS_MONITORED_APPS = ""

    with patch("app.api.dashboard.settings", mock_settings):
        with patch("app.api.dashboard._get_pm2_statuses", return_value={}):
            headers = api_key_headers(test_client_a)
            resp = await client.get("/api/v1/dashboard/monitored-apps", headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["apps"] == []
    assert data["count"] == 0
