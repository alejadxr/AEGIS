"""A permission-denied firewall backend disables itself once and reports it."""
import logging
import subprocess
from unittest.mock import MagicMock, patch

from app.services import firewall_local as fl


def _denied():
    p = MagicMock(spec=subprocess.CompletedProcess)
    p.returncode = 1
    p.stdout = b""
    p.stderr = b"pfctl: /dev/pf: Permission denied"
    return p


def test_block_disables_layer_and_warns_once(caplog):
    fw = fl.MacOSFirewall()
    with patch.object(fl, "_run", return_value=_denied()) as run, caplog.at_level(logging.WARNING):
        assert fw.block("203.0.113.5") is False
        assert fw.block("203.0.113.6") is False
        assert fw.unblock("203.0.113.5") is False
    assert run.call_count == 1  # later calls short-circuit
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert fw.status() == "unavailable: permission denied"


def test_setup_probe_disables_layer():
    fw = fl.MacOSFirewall()
    with patch.object(fl, "_run", return_value=_denied()):
        fw.setup()
    assert not fw.available


def test_non_permission_failure_keeps_layer_enabled():
    fw = fl.MacOSFirewall()
    bad = _denied()
    bad.stderr = b"some other error"
    with patch.object(fl, "_run", return_value=bad):
        assert fw.block("203.0.113.5") is False
    assert fw.available and fw.status() == "active"


def test_linux_permission_denied_disables():
    fw = fl.LinuxFirewall()
    p = _denied()
    p.stderr = b"iptables: Permission denied (you must be root)"
    with patch.object(fl, "_run", return_value=p):
        fw.block("203.0.113.5")
    assert fw.status().startswith("unavailable")
