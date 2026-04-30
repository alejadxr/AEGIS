"""
Local firewall abstraction for AEGIS.

Gated by AEGIS_REAL_FW=1. Without the flag (or when run as non-root / in CI),
falls back to NoopFirewall which tracks blocks in-memory only.
"""
import functools
import ipaddress
import logging
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger("aegis.firewall_local")

_BLOCKED_IPS_FILE = Path(os.environ.get("BLOCKED_IPS_FILE", str(Path.home() / "AEGIS" / "blocked_ips.txt")))
_PF_ANCHOR_PATH = "/etc/pf.anchors/aegis"
_PF_TABLE = "aegis_block"
_IPT_CHAIN = "AEGIS_BLOCK"


def _validate_ip(ip: str) -> str:
    """Validate and return normalized IP. Raises ValueError on bad input."""
    return str(ipaddress.ip_address(ip))


def _run(argv: list[str], timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, capture_output=True, timeout=timeout)


class LocalFirewall(ABC):
    @abstractmethod
    def block(self, ip: str) -> bool: ...

    @abstractmethod
    def unblock(self, ip: str) -> bool: ...

    @abstractmethod
    def is_blocked(self, ip: str) -> bool: ...

    @abstractmethod
    def list_blocked(self) -> set[str]: ...

    @abstractmethod
    def setup(self) -> None: ...

    @abstractmethod
    def teardown(self) -> None: ...

    def _reload_from_file(self) -> None:
        """Re-block every IP persisted in BLOCKED_IPS_FILE."""
        if not _BLOCKED_IPS_FILE.exists():
            return
        try:
            lines = _BLOCKED_IPS_FILE.read_text().splitlines()
            for line in lines:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    try:
                        self.block(_validate_ip(ip))
                    except Exception as e:
                        logger.warning(f"firewall_local: skipping bad IP '{ip}' from file: {e}")
        except Exception as e:
            logger.error(f"firewall_local: failed to reload from file: {e}")


class NoopFirewall(LocalFirewall):
    """In-memory only — used in sandboxed/CI/non-root contexts."""

    def __init__(self) -> None:
        self._blocked: set[str] = set()

    def block(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return False
        self._blocked.add(ip)
        return True

    def unblock(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return False
        self._blocked.discard(ip)
        return True

    def is_blocked(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return False
        return ip in self._blocked

    def list_blocked(self) -> set[str]:
        return set(self._blocked)

    def setup(self) -> None:
        self._reload_from_file()

    def teardown(self) -> None:
        self._blocked.clear()


class MacOSFirewall(LocalFirewall):
    """pfctl-backed firewall using an `aegis_block` table."""

    def block(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            logger.error(f"firewall_local(macos): invalid IP '{ip}'")
            return False
        result = _run(["pfctl", "-t", _PF_TABLE, "-T", "add", ip])
        if result.returncode != 0:
            logger.warning(
                f"firewall_local(macos): pfctl add failed for {ip}: {result.stderr.decode(errors='replace').strip()}"
            )
            return False
        return True

    def unblock(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            logger.error(f"firewall_local(macos): invalid IP '{ip}'")
            return False
        result = _run(["pfctl", "-t", _PF_TABLE, "-T", "delete", ip])
        if result.returncode != 0:
            logger.warning(
                f"firewall_local(macos): pfctl delete failed for {ip}: {result.stderr.decode(errors='replace').strip()}"
            )
            return False
        return True

    def is_blocked(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return False
        return ip in self.list_blocked()

    def list_blocked(self) -> set[str]:
        result = _run(["pfctl", "-t", _PF_TABLE, "-T", "show"])
        if result.returncode != 0:
            return set()
        lines = result.stdout.decode(errors="replace").splitlines()
        ips: set[str] = set()
        for line in lines:
            candidate = line.strip()
            if candidate:
                try:
                    ips.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    pass
        return ips

    def setup(self) -> None:
        try:
            anchor_dir = Path(_PF_ANCHOR_PATH).parent
            anchor_dir.mkdir(parents=True, exist_ok=True)
            Path(_PF_ANCHOR_PATH).write_text(f"table <{_PF_TABLE}> persist\nblock drop from <{_PF_TABLE}> to any\n")
            load_result = _run(["pfctl", "-a", "aegis", "-f", _PF_ANCHOR_PATH])
            if load_result.returncode != 0:
                err = load_result.stderr.decode(errors="replace").strip()
                logger.warning(f"firewall_local(macos): pfctl anchor load failed (need sudo?): {err}")
        except PermissionError as e:
            logger.warning(f"firewall_local(macos): setup requires root — {e}. Continuing without system firewall.")
            return
        except Exception as e:
            logger.error(f"firewall_local(macos): setup error: {e}")
            return
        self._reload_from_file()

    def teardown(self) -> None:
        _run(["pfctl", "-t", _PF_TABLE, "-T", "flush"])


class LinuxFirewall(LocalFirewall):
    """iptables-backed firewall using an AEGIS_BLOCK chain."""

    def block(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            logger.error(f"firewall_local(linux): invalid IP '{ip}'")
            return False
        result = _run(["iptables", "-A", _IPT_CHAIN, "-s", ip, "-j", "DROP"])
        if result.returncode != 0:
            logger.warning(
                f"firewall_local(linux): iptables block failed for {ip}: {result.stderr.decode(errors='replace').strip()}"
            )
            return False
        return True

    def unblock(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            logger.error(f"firewall_local(linux): invalid IP '{ip}'")
            return False
        result = _run(["iptables", "-D", _IPT_CHAIN, "-s", ip, "-j", "DROP"])
        if result.returncode != 0:
            logger.warning(
                f"firewall_local(linux): iptables unblock failed for {ip}: {result.stderr.decode(errors='replace').strip()}"
            )
            return False
        return True

    def is_blocked(self, ip: str) -> bool:
        try:
            ip = _validate_ip(ip)
        except ValueError:
            return False
        return ip in self.list_blocked()

    def list_blocked(self) -> set[str]:
        result = _run(["iptables", "-L", _IPT_CHAIN, "-n"])
        if result.returncode != 0:
            return set()
        ips: set[str] = set()
        for line in result.stdout.decode(errors="replace").splitlines():
            parts = line.split()
            # iptables -L -n output: target prot opt source destination
            # source is index 3 when chain list header is skipped
            if len(parts) >= 4 and parts[0] == "DROP":
                candidate = parts[3]
                try:
                    ips.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    pass
        return ips

    def setup(self) -> None:
        # Create chain (idempotent — ignore error if exists)
        _run(["iptables", "-N", _IPT_CHAIN])
        # Insert jump rule if not already present
        check = _run(["iptables", "-C", "INPUT", "-j", _IPT_CHAIN])
        if check.returncode != 0:
            insert = _run(["iptables", "-I", "INPUT", "-j", _IPT_CHAIN])
            if insert.returncode != 0:
                logger.warning(
                    f"firewall_local(linux): failed to insert INPUT jump rule: "
                    f"{insert.stderr.decode(errors='replace').strip()}"
                )
        self._reload_from_file()

    def teardown(self) -> None:
        _run(["iptables", "-D", "INPUT", "-j", _IPT_CHAIN])
        _run(["iptables", "-F", _IPT_CHAIN])
        _run(["iptables", "-X", _IPT_CHAIN])


@functools.lru_cache(maxsize=1)
def get_firewall() -> LocalFirewall:
    """Return the appropriate LocalFirewall singleton based on env and platform."""
    if os.environ.get("AEGIS_REAL_FW") == "1":
        if sys.platform == "darwin":
            logger.info("firewall_local: using MacOSFirewall (pfctl)")
            return MacOSFirewall()
        if sys.platform.startswith("linux"):
            logger.info("firewall_local: using LinuxFirewall (iptables)")
            return LinuxFirewall()
    logger.info("firewall_local: using NoopFirewall (in-memory only; set AEGIS_REAL_FW=1 to enable system firewall)")
    return NoopFirewall()
