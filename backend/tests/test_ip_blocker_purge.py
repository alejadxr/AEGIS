"""Tests for ip_blocker startup safelist purge (v1.6.2)."""
import pytest


@pytest.fixture
def temp_blocklist(tmp_path, monkeypatch):
    """Write a controlled blocked_ips.txt and point the loader at it."""
    f = tmp_path / "blocked_ips.txt"
    f.write_text(
        "# AEGIS Blocked IPs\n"
        "66.249.69.66\n"     # Googlebot — should be purged (66.249.0.0/16 in SAFE_IPS)
        "203.0.113.5\n"      # RFC5737 — should be purged
        "198.51.100.42\n"    # RFC5737 — should be purged
        "192.0.2.99\n"       # RFC5737 — should be purged
        "45.155.205.233\n"   # Real public IP — keep
        "1.2.3.4\n"          # Real public IP — keep
    )
    monkeypatch.setenv("BLOCKED_IPS_FILE", str(f))
    monkeypatch.setenv("AEGIS_SAFE_IPS", "127.0.0.1,::1,66.249.0.0/16,100.64.0.0/10")
    import importlib
    import app.core.attack_detector as ad
    importlib.reload(ad)
    import app.core.ip_blocker as ipb
    importlib.reload(ipb)
    return f, ipb


def test_googlebot_ip_purged_on_load(temp_blocklist):
    """66.249.0.0/16 entries should be purged on startup."""
    _, ipb = temp_blocklist
    loaded = ipb._load_blocked_ips()
    assert "66.249.69.66" not in loaded
    assert "45.155.205.233" in loaded


def test_rfc5737_ips_purged_on_load(temp_blocklist):
    """All three RFC5737 documentation ranges should be purged."""
    _, ipb = temp_blocklist
    loaded = ipb._load_blocked_ips()
    assert "203.0.113.5" not in loaded
    assert "198.51.100.42" not in loaded
    assert "192.0.2.99" not in loaded


def test_real_attacker_ip_preserved(temp_blocklist):
    """Real public IPs not matching any safelist should remain."""
    _, ipb = temp_blocklist
    loaded = ipb._load_blocked_ips()
    assert "1.2.3.4" in loaded


def test_blocklist_file_rewritten_without_purged_entries(temp_blocklist):
    """After load, the file on disk no longer contains purged IPs."""
    f, ipb = temp_blocklist
    ipb._load_blocked_ips()
    content = f.read_text()
    assert "66.249.69.66" not in content
    assert "203.0.113.5" not in content
    assert "45.155.205.233" in content
