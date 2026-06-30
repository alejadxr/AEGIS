"""
Unit tests for the Pi -> Mac Pro blocklist pull in firewall_sync.

Verifies that:
  * IPs present on the Pi but missing locally get appended.
  * Safe IPs (per AEGIS_SAFE_IPS / CIDR ranges) are skipped.
  * Local-only IPs are NEVER removed (only warned).
  * CIDR entries on Pi (defensive — Pi shouldn't return them) are ignored.
"""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.services import firewall_sync
from app.core import ip_blocker as ip_blocker_mod


@pytest.fixture
def isolated_blocklist(tmp_path, monkeypatch):
    """Point ip_blocker at a tmp file and reset the in-memory set."""
    blocked_file = tmp_path / "blocked_ips.txt"
    blocked_file.write_text("# AEGIS Blocked IPs\n# Managed automatically\n45.155.205.233\n")
    monkeypatch.setattr(ip_blocker_mod, "BLOCKED_IPS_FILE", blocked_file)
    # Reset in-memory state to match the new file
    ip_blocker_mod.ip_blocker_service._blocked = ip_blocker_mod._load_blocked_ips()
    yield blocked_file


@pytest.mark.asyncio
async def test_pull_appends_new_pi_ips(isolated_blocklist):
    pi_response = ["45.155.205.233", "1.2.3.4", "5.6.7.8"]

    with patch.object(
        firewall_sync.firewall_client, "get_blocked", new=AsyncMock(return_value=pi_response)
    ):
        result = await firewall_sync._pull_blocklist_from_pi()

    assert result["added"] == 2
    contents = isolated_blocklist.read_text()
    assert "1.2.3.4" in contents
    assert "5.6.7.8" in contents
    assert "45.155.205.233" in contents  # still there, not duplicated


@pytest.mark.asyncio
async def test_pull_skips_safe_ips(isolated_blocklist):
    """Googlebot IP must not be appended even if Pi has it."""
    # 66.249.0.0/16 should be in AEGIS_SAFE_IPS in prod; force it for the test
    # via the configured _SAFE_NETWORKS list at runtime.
    import ipaddress
    from app.core import attack_detector
    googlebot_net = ipaddress.ip_network("66.249.0.0/16")
    attack_detector._SAFE_NETWORKS.append(googlebot_net)
    try:
        pi_response = ["66.249.75.164", "9.9.9.9"]
        with patch.object(
            firewall_sync.firewall_client, "get_blocked", new=AsyncMock(return_value=pi_response)
        ):
            result = await firewall_sync._pull_blocklist_from_pi()
        assert result["skipped_safe"] == 1
        assert result["added"] == 1
        assert "66.249.75.164" not in isolated_blocklist.read_text()
        assert "9.9.9.9" in isolated_blocklist.read_text()
    finally:
        attack_detector._SAFE_NETWORKS.remove(googlebot_net)


@pytest.mark.asyncio
async def test_pull_does_not_remove_local_only(isolated_blocklist):
    """Local-only IPs must remain even if absent from Pi."""
    pi_response = ["1.2.3.4"]
    with patch.object(
        firewall_sync.firewall_client, "get_blocked", new=AsyncMock(return_value=pi_response)
    ):
        result = await firewall_sync._pull_blocklist_from_pi()
    assert result["local_only"] == 1  # 45.155.205.233 was local-only
    assert "45.155.205.233" in isolated_blocklist.read_text()


@pytest.mark.asyncio
async def test_pull_ignores_cidr_entries(isolated_blocklist):
    """A CIDR returned by Pi (defensive guard) must not be written."""
    pi_response = ["1.2.3.4", "10.0.0.0/8"]
    with patch.object(
        firewall_sync.firewall_client, "get_blocked", new=AsyncMock(return_value=pi_response)
    ):
        result = await firewall_sync._pull_blocklist_from_pi()
    assert result["added"] == 1
    assert "10.0.0.0/8" not in isolated_blocklist.read_text()


@pytest.mark.asyncio
async def test_pull_idempotent(isolated_blocklist):
    """Running twice with same Pi state must not duplicate entries."""
    pi_response = ["1.2.3.4"]
    with patch.object(
        firewall_sync.firewall_client, "get_blocked", new=AsyncMock(return_value=pi_response)
    ):
        await firewall_sync._pull_blocklist_from_pi()
        result2 = await firewall_sync._pull_blocklist_from_pi()
    assert result2["added"] == 0
    assert isolated_blocklist.read_text().count("1.2.3.4") == 1
