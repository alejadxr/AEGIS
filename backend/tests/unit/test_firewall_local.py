"""Unit tests for app.services.firewall_local.

All subprocess calls are mocked — no actual pfctl/iptables execution.
"""
import importlib
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import subprocess

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_module():
    """Reload firewall_local to bust the lru_cache singleton between tests."""
    mod_name = "app.services.firewall_local"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import app.services.firewall_local as m
    m.get_firewall.cache_clear()
    return m


def _make_proc(returncode=0, stdout=b"", stderr=b""):
    p = MagicMock(spec=subprocess.CompletedProcess)
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


# ---------------------------------------------------------------------------
# NoopFirewall
# ---------------------------------------------------------------------------

class TestNoopFirewall:
    def setup_method(self):
        m = _reload_module()
        self.fw = m.NoopFirewall()

    def test_block_and_is_blocked(self):
        assert self.fw.block("1.2.3.4") is True
        assert self.fw.is_blocked("1.2.3.4") is True

    def test_unblock(self):
        self.fw.block("1.2.3.4")
        assert self.fw.unblock("1.2.3.4") is True
        assert self.fw.is_blocked("1.2.3.4") is False

    def test_unblock_not_present(self):
        assert self.fw.unblock("9.9.9.9") is True  # discard is idempotent

    def test_list_blocked(self):
        self.fw.block("1.1.1.1")
        self.fw.block("2.2.2.2")
        assert self.fw.list_blocked() == {"1.1.1.1", "2.2.2.2"}

    def test_list_returns_copy(self):
        self.fw.block("1.1.1.1")
        lst = self.fw.list_blocked()
        lst.add("9.9.9.9")
        assert "9.9.9.9" not in self.fw.list_blocked()

    def test_block_twice_idempotent(self):
        assert self.fw.block("3.3.3.3") is True
        assert self.fw.block("3.3.3.3") is True
        assert self.fw.list_blocked() == {"3.3.3.3"}

    def test_invalid_ip_rejected(self):
        assert self.fw.block("not-an-ip") is False
        assert self.fw.unblock("not-an-ip") is False
        assert self.fw.is_blocked("not-an-ip") is False

    def test_setup_teardown_noop(self):
        self.fw.setup()
        self.fw.block("4.4.4.4")
        self.fw.teardown()
        assert self.fw.list_blocked() == set()


# ---------------------------------------------------------------------------
# Persistence: setup() reloads IPs from BLOCKED_IPS_FILE
# ---------------------------------------------------------------------------

class TestPersistenceReload:
    def test_setup_reloads_file(self, tmp_path):
        blocked_file = tmp_path / "blocked_ips.txt"
        blocked_file.write_text("# comment\n10.0.0.1\n10.0.0.2\n")

        m = _reload_module()
        m._BLOCKED_IPS_FILE = blocked_file  # patch module-level path
        fw = m.NoopFirewall()
        fw.setup()

        assert fw.is_blocked("10.0.0.1")
        assert fw.is_blocked("10.0.0.2")

    def test_setup_skips_bad_ips_in_file(self, tmp_path):
        blocked_file = tmp_path / "blocked_ips.txt"
        blocked_file.write_text("10.0.0.1\nbad-entry\n10.0.0.2\n")

        m = _reload_module()
        m._BLOCKED_IPS_FILE = blocked_file
        fw = m.NoopFirewall()
        fw.setup()

        assert fw.is_blocked("10.0.0.1")
        assert fw.is_blocked("10.0.0.2")
        assert not fw.is_blocked("bad-entry")

    def test_setup_handles_missing_file(self, tmp_path):
        m = _reload_module()
        m._BLOCKED_IPS_FILE = tmp_path / "nonexistent.txt"
        fw = m.NoopFirewall()
        fw.setup()  # must not raise
        assert fw.list_blocked() == set()


# ---------------------------------------------------------------------------
# MacOSFirewall (subprocess mocked)
# ---------------------------------------------------------------------------

class TestMacOSFirewall:
    def setup_method(self):
        self.m = _reload_module()
        self.fw = self.m.MacOSFirewall()

    @patch("app.services.firewall_local._run")
    def test_block_calls_pfctl_add(self, mock_run):
        mock_run.return_value = _make_proc(0)
        result = self.fw.block("5.5.5.5")
        assert result is True
        mock_run.assert_called_once_with(["pfctl", "-t", "aegis_block", "-T", "add", "5.5.5.5"])

    @patch("app.services.firewall_local._run")
    def test_block_nonzero_returns_false(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1, stderr=b"permission denied")
        result = self.fw.block("5.5.5.5")
        assert result is False

    @patch("app.services.firewall_local._run")
    def test_block_twice_no_error(self, mock_run):
        mock_run.return_value = _make_proc(0)
        assert self.fw.block("6.6.6.6") is True
        assert self.fw.block("6.6.6.6") is True
        assert mock_run.call_count == 2

    @patch("app.services.firewall_local._run")
    def test_unblock_calls_pfctl_delete(self, mock_run):
        mock_run.return_value = _make_proc(0)
        result = self.fw.unblock("7.7.7.7")
        assert result is True
        mock_run.assert_called_once_with(["pfctl", "-t", "aegis_block", "-T", "delete", "7.7.7.7"])

    @patch("app.services.firewall_local._run")
    def test_unblock_nonzero_returns_false(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1, stderr=b"no such table")
        assert self.fw.unblock("7.7.7.7") is False

    @patch("app.services.firewall_local._run")
    def test_list_blocked_parses_output(self, mock_run):
        mock_run.return_value = _make_proc(0, stdout=b"  8.8.8.8\n  1.1.1.1\n")
        result = self.fw.list_blocked()
        assert result == {"8.8.8.8", "1.1.1.1"}

    @patch("app.services.firewall_local._run")
    def test_list_blocked_empty_on_error(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1)
        assert self.fw.list_blocked() == set()

    @patch("app.services.firewall_local._run")
    def test_is_blocked_true(self, mock_run):
        mock_run.return_value = _make_proc(0, stdout=b"9.9.9.9\n")
        assert self.fw.is_blocked("9.9.9.9") is True

    @patch("app.services.firewall_local._run")
    def test_is_blocked_false(self, mock_run):
        mock_run.return_value = _make_proc(0, stdout=b"8.8.8.8\n")
        assert self.fw.is_blocked("9.9.9.9") is False

    def test_block_invalid_ip(self):
        assert self.fw.block("not-valid") is False

    @patch("app.services.firewall_local._run")
    @patch("pathlib.Path.write_text")
    @patch("pathlib.Path.mkdir")
    def test_setup_loads_anchor_and_reloads_file(self, mock_mkdir, mock_write, mock_run, tmp_path):
        mock_run.return_value = _make_proc(0)
        self.m._BLOCKED_IPS_FILE = tmp_path / "blocked_ips.txt"
        (tmp_path / "blocked_ips.txt").write_text("10.10.10.10\n")

        with patch("app.services.firewall_local._run", return_value=_make_proc(0)) as mr:
            self.fw.setup()
            # Should have called pfctl -a aegis -f ... and pfctl add for reloaded IP
            argv_list = [c.args[0] for c in mr.call_args_list]
            assert any("aegis" in str(a) for a in argv_list), "pfctl anchor load not called"


# ---------------------------------------------------------------------------
# LinuxFirewall (subprocess mocked)
# ---------------------------------------------------------------------------

class TestLinuxFirewall:
    def setup_method(self):
        self.m = _reload_module()
        self.fw = self.m.LinuxFirewall()

    @patch("app.services.firewall_local._run")
    def test_block_calls_iptables_append(self, mock_run):
        mock_run.return_value = _make_proc(0)
        result = self.fw.block("11.11.11.11")
        assert result is True
        mock_run.assert_called_once_with(["iptables", "-A", "AEGIS_BLOCK", "-s", "11.11.11.11", "-j", "DROP"])

    @patch("app.services.firewall_local._run")
    def test_block_nonzero_returns_false(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1, stderr=b"iptables error")
        assert self.fw.block("11.11.11.11") is False

    @patch("app.services.firewall_local._run")
    def test_block_twice_no_error(self, mock_run):
        mock_run.return_value = _make_proc(0)
        assert self.fw.block("12.12.12.12") is True
        assert self.fw.block("12.12.12.12") is True
        assert mock_run.call_count == 2

    @patch("app.services.firewall_local._run")
    def test_unblock_calls_iptables_delete(self, mock_run):
        mock_run.return_value = _make_proc(0)
        result = self.fw.unblock("13.13.13.13")
        assert result is True
        mock_run.assert_called_once_with(["iptables", "-D", "AEGIS_BLOCK", "-s", "13.13.13.13", "-j", "DROP"])

    @patch("app.services.firewall_local._run")
    def test_unblock_nonzero_returns_false(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1, stderr=b"bad rule")
        assert self.fw.unblock("13.13.13.13") is False

    @patch("app.services.firewall_local._run")
    def test_list_blocked_parses_drop_lines(self, mock_run):
        output = (
            b"Chain AEGIS_BLOCK (1 references)\n"
            b"target     prot opt source               destination\n"
            b"DROP       all  --  14.14.14.14          0.0.0.0/0\n"
            b"DROP       all  --  15.15.15.15          0.0.0.0/0\n"
        )
        mock_run.return_value = _make_proc(0, stdout=output)
        result = self.fw.list_blocked()
        assert result == {"14.14.14.14", "15.15.15.15"}

    @patch("app.services.firewall_local._run")
    def test_list_blocked_empty_on_error(self, mock_run):
        mock_run.return_value = _make_proc(returncode=1)
        assert self.fw.list_blocked() == set()

    def test_block_invalid_ip(self):
        assert self.fw.block("bad-ip") is False

    @patch("app.services.firewall_local._run")
    def test_setup_creates_chain_and_inserts_jump(self, mock_run):
        # First call: -N chain (idempotent), second: -C check (fails → not present),
        # third: -I INPUT insert
        mock_run.side_effect = [
            _make_proc(0),        # iptables -N AEGIS_BLOCK
            _make_proc(1),        # iptables -C INPUT -j AEGIS_BLOCK (not found)
            _make_proc(0),        # iptables -I INPUT -j AEGIS_BLOCK
        ]
        self.fw.setup()
        calls = mock_run.call_args_list
        assert calls[0].args[0] == ["iptables", "-N", "AEGIS_BLOCK"]
        assert calls[1].args[0] == ["iptables", "-C", "INPUT", "-j", "AEGIS_BLOCK"]
        assert calls[2].args[0] == ["iptables", "-I", "INPUT", "-j", "AEGIS_BLOCK"]

    @patch("app.services.firewall_local._run")
    def test_setup_skips_insert_if_jump_already_present(self, mock_run):
        mock_run.side_effect = [
            _make_proc(0),   # -N (idempotent)
            _make_proc(0),   # -C (already exists)
        ]
        self.fw.setup()
        assert mock_run.call_count == 2  # no -I call


# ---------------------------------------------------------------------------
# Factory / get_firewall()
# ---------------------------------------------------------------------------

class TestGetFirewall:
    def test_default_is_noop(self):
        m = _reload_module()
        os.environ.pop("AEGIS_REAL_FW", None)
        fw = m.get_firewall()
        assert isinstance(fw, m.NoopFirewall)

    def test_macos_when_real_fw_and_darwin(self):
        m = _reload_module()
        os.environ["AEGIS_REAL_FW"] = "1"
        try:
            with patch.object(sys, "platform", "darwin"):
                fw = m.get_firewall()
            assert isinstance(fw, m.MacOSFirewall)
        finally:
            os.environ.pop("AEGIS_REAL_FW", None)
            m.get_firewall.cache_clear()

    def test_linux_when_real_fw_and_linux(self):
        m = _reload_module()
        os.environ["AEGIS_REAL_FW"] = "1"
        try:
            with patch.object(sys, "platform", "linux"):
                fw = m.get_firewall()
            assert isinstance(fw, m.LinuxFirewall)
        finally:
            os.environ.pop("AEGIS_REAL_FW", None)
            m.get_firewall.cache_clear()

    def test_singleton_returns_same_instance(self):
        m = _reload_module()
        fw1 = m.get_firewall()
        fw2 = m.get_firewall()
        assert fw1 is fw2
