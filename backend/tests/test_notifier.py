"""Tests for Bug 1 fix: NotificationService.notify_critical_event()."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.notifier import NotificationService


def test_notify_critical_event_method_exists():
    """Bug 1: notify_critical_event must be present on NotificationService."""
    svc = NotificationService()
    assert hasattr(svc, "notify_critical_event"), (
        "NotificationService is missing notify_critical_event — AttributeError in PM2 logs"
    )
    assert callable(svc.notify_critical_event)


@pytest.mark.asyncio
async def test_notify_critical_event_dispatches_to_notify():
    """notify_critical_event should call self.notify() with a well-formed payload."""
    svc = NotificationService()

    # Fake client returned by DB lookup
    fake_client = MagicMock()
    fake_client.settings = {"webhook_url": "https://hooks.example.com/test"}

    # Patch async_session and notify
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = fake_client
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("app.services.notifier.NotificationService.notify", new_callable=AsyncMock) as mock_notify, \
         patch("app.database.async_session", return_value=mock_session):
        await svc.notify_critical_event(
            event_type="path_traversal",
            details={
                "severity": "high",
                "source_ip": "185.220.101.1",
                "message": "Path traversal detected in /etc/passwd",
            },
        )

    mock_notify.assert_awaited_once()
    _, call_kwargs = mock_notify.call_args
    payload = mock_notify.call_args[0][1]  # second positional arg is payload
    assert payload["event_type"] == "path_traversal"
    assert payload["severity"] == "high"
    assert "PATH TRAVERSAL" in payload["title"].upper() or "path_traversal" in payload["title"].lower()


@pytest.mark.asyncio
async def test_notify_critical_event_no_client_does_not_raise():
    """notify_critical_event is graceful when no Client rows exist in DB."""
    svc = NotificationService()

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None  # empty DB
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("app.database.async_session", return_value=mock_session):
        # Must NOT raise — the missing-client case is logged and swallowed
        await svc.notify_critical_event(
            event_type="scanner_detect",
            details={"severity": "high", "source_ip": "1.2.3.4", "message": "scanner"},
        )
