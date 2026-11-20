"""The agent must work as root in a container (no sudo) and on a gateway (sudo)."""
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402
import dos_netshield  # noqa: E402


@pytest.mark.parametrize("mod", [main, dos_netshield])
def test_root_runs_iptables_directly(monkeypatch, mod):
    monkeypatch.delenv("AEGIS_FW_SUDO", raising=False)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    assert mod._privileged(["/usr/sbin/iptables", "-S"]) == ["/usr/sbin/iptables", "-S"]


@pytest.mark.parametrize("mod", [main, dos_netshield])
def test_unprivileged_user_goes_through_sudo(monkeypatch, mod):
    monkeypatch.delenv("AEGIS_FW_SUDO", raising=False)
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1000)
    assert mod._privileged(["/usr/sbin/iptables", "-S"]) == ["sudo", "/usr/sbin/iptables", "-S"]


@pytest.mark.parametrize("mod", [main, dos_netshield])
def test_operator_can_force_either_way(monkeypatch, mod):
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setenv("AEGIS_FW_SUDO", "1")
    assert mod._privileged(["x"]) == ["sudo", "x"]
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("AEGIS_FW_SUDO", "0")
    assert mod._privileged(["x"]) == ["x"]


def test_iptables_binary_follows_the_detected_backend(monkeypatch):
    monkeypatch.setenv("AEGIS_IPTABLES", "/usr/sbin/iptables-legacy")
    try:
        reloaded = importlib.reload(main)
        assert reloaded.IPTABLES == "/usr/sbin/iptables-legacy"
        calls = []
        monkeypatch.setattr(reloaded.subprocess, "run", lambda cmd, **k: calls.append(cmd))
        monkeypatch.setattr(reloaded.os, "geteuid", lambda: 0)
        reloaded._run_iptables("-C", "INPUT", "-s", "203.0.113.9", "-j", "DROP", check=False)
        assert calls == [["/usr/sbin/iptables-legacy", "-C", "INPUT", "-s", "203.0.113.9", "-j", "DROP"]]
    finally:
        monkeypatch.delenv("AEGIS_IPTABLES", raising=False)
        importlib.reload(main)
