import ipaddress as _ipaddress
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aegis.ip_blocker")

# v1.6.2: env override for BLOCKED_IPS_FILE (must agree with firewall_local)
BLOCKED_IPS_FILE = Path(os.environ.get(
    "BLOCKED_IPS_FILE",
    str(Path.home() / "AEGIS" / "blocked_ips.txt"),
))

# v1.6.2: RFC5737 documentation prefixes — IPs that should NEVER appear in any
# production blocklist (reserved for examples and test injection).
_RFC5737_NETS = [
    _ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    _ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    _ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]


def _should_purge_ip(ip: str) -> tuple[bool, str]:
    """v1.6.2: Return (purge, reason). Purge if IP matches AEGIS_SAFE_IPS or RFC5737."""
    try:
        from app.core.attack_detector import _is_safe_ip
        if _is_safe_ip(ip):
            return (True, "AEGIS_SAFE_IPS")
    except Exception:
        pass
    try:
        addr = _ipaddress.ip_address(ip)
        if any(addr in net for net in _RFC5737_NETS):
            return (True, "RFC5737")
    except (ValueError, TypeError):
        return (False, "")
    return (False, "")


def atomic_write_text(path: Path, content: str) -> None:
    """Replace `path` with `content` so a concurrent reader sees the old file
    or the new one, never a truncated mix.

    `write_text` truncates in place before writing, and the apps that poll the
    blocklist (and AEGIS itself at startup) can read in that window and come
    away with an empty or half-written set, silently dropping blocks. The temp
    file lives in the same directory so `os.replace` is a same-filesystem
    rename, which is atomic on POSIX.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, path.stat().st_mode & 0o777)
        except FileNotFoundError:
            os.chmod(tmp, 0o644)  # mkstemp creates 0600; readers are other users/apps
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# A reload that parses fewer than this share of the entries already in memory
# is treated as a damaged read, not as a mass unblock.
_RELOAD_MIN_KEEP_RATIO = 0.5
_RELOAD_GUARD_MIN_PREVIOUS = 10


def _load_blocked_ips(previous: Optional[set] = None) -> set:
    """Load blocked IPs from disk with safelist purge.

    `previous` is the set currently in memory on a reload. If the file now
    parses to under half of it (and `previous` is big enough for that to mean
    something), the read is assumed damaged and `previous` is kept.

    v1.6.2: Any IP matching AEGIS_SAFE_IPS (including CIDR ranges like
    66.249.0.0/16 for Googlebot) or RFC5737 documentation prefixes is dropped
    on load AND the file is rewritten without it. This prevents safelist
    entries from persisting across restarts when an operator changes the
    safelist or when test-injection IPs get committed by mistake.
    """
    if not BLOCKED_IPS_FILE.exists():
        return set()
    try:
        lines = BLOCKED_IPS_FILE.read_text().splitlines()
        raw = {line.strip() for line in lines if line.strip() and not line.startswith("#")}
    except Exception as e:
        logger.error(f"Failed to load blocked IPs: {e}")
        return set()

    if (
        previous
        and len(previous) >= _RELOAD_GUARD_MIN_PREVIOUS
        and len(raw) < len(previous) * _RELOAD_MIN_KEEP_RATIO
    ):
        logger.error(
            f"ip_blocker: blocklist file parsed to {len(raw)} entries against "
            f"{len(previous)} in memory; treating it as a damaged read and keeping the previous set"
        )
        return set(previous)

    purged: dict[str, str] = {}
    kept: set[str] = set()
    for ip in raw:
        do_purge, reason = _should_purge_ip(ip)
        if do_purge:
            purged[ip] = reason
        else:
            kept.add(ip)

    if purged:
        logger.warning(
            f"ip_blocker: purged {len(purged)} safelisted IP(s) from blocklist "
            f"on startup: {dict(list(purged.items())[:10])}"
            + (" ..." if len(purged) > 10 else "")
        )
        try:
            _save_blocked_ips(kept)
        except Exception as e:
            logger.error(f"ip_blocker: failed to persist post-purge blocklist: {e}")

    return kept


def _save_blocked_ips(ips: set) -> None:
    try:
        content = "# AEGIS Blocked IPs\n# Managed automatically\n"
        content += "\n".join(sorted(ips))
        if ips:
            content += "\n"
        atomic_write_text(BLOCKED_IPS_FILE, content)
    except Exception as e:
        logger.error(f"Failed to save blocked IPs: {e}")


class IPBlockerService:
    """Service to manage blocked IPs with file persistence."""

    def __init__(self):
        self._blocked: set = _load_blocked_ips()
        logger.info(f"IP Blocker initialized with {len(self._blocked)} blocked IPs")

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def block_ip(self, ip: str, force: bool = False) -> dict:
        """Add `ip` to the blocklist.

        Shared consumer egress (WARP / Private Relay) is refused unless
        `force=True`, which only an operator-approved action passes: this is the
        single chokepoint every automated blocker funnels through, so the guard
        holds for callers that never heard of the shared-egress category.
        """
        if not ip or not isinstance(ip, str):
            logger.warning(f"block_ip called with invalid IP: {ip!r}, skipping")
            return {"success": False, "ip": ip, "error": "Invalid IP"}
        if not force:
            try:
                from app.core.attack_detector import is_shared_egress
                if is_shared_egress(ip):
                    logger.warning(f"BLOCK_IP: refusing shared-egress IP {ip} (needs operator approval)")
                    return {"success": False, "ip": ip, "skipped": "shared_egress"}
            except Exception as exc:
                logger.debug(f"shared-egress check failed for {ip}: {exc}")
        already_blocked = ip in self._blocked
        self._blocked.add(ip)
        _save_blocked_ips(self._blocked)
        try:
            from app.core import attack_detector as _ad
            if hasattr(_ad, "_blocked_ips"):
                _ad._blocked_ips.add(ip)
        except Exception as exc:
            logger.debug(f"attack_detector blocklist mirror failed for {ip}: {exc}")
        pf_cmd = f'echo "block drop from {ip} to any" | sudo pfctl -ef -'
        logger.warning(f"BLOCK_IP: {ip} added to block list. pf equivalent: {pf_cmd}")
        return {
            "success": True,
            "ip": ip,
            "already_blocked": already_blocked,
            "total_blocked": len(self._blocked),
            "file": str(BLOCKED_IPS_FILE),
            "pf_command": pf_cmd,
        }

    def unblock_ip(self, ip: str) -> dict:
        was_blocked = ip in self._blocked
        self._blocked.discard(ip)
        if was_blocked:
            _save_blocked_ips(self._blocked)
        try:
            from app.core import attack_detector as _ad
            if hasattr(_ad, "_blocked_ips"):
                _ad._blocked_ips.discard(ip)
        except Exception:
            pass
        logger.info(f"UNBLOCK_IP: {ip} removed from block list")
        return {
            "success": True,
            "ip": ip,
            "was_blocked": was_blocked,
            "total_blocked": len(self._blocked),
        }

    def list_blocked(self) -> list:
        return sorted(self._blocked)

    def reload(self) -> int:
        self._blocked = _load_blocked_ips(previous=self._blocked)
        return len(self._blocked)


ip_blocker_service = IPBlockerService()


class IPBlockerMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that blocks requests from known-bad IPs."""

    async def dispatch(self, request: Request, call_next):
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if not client_ip:
            client_ip = request.client.host if request.client else "unknown"

        if ip_blocker_service.is_blocked(client_ip):
            logger.warning(f"Blocked request from {client_ip} to {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied", "ip": client_ip},
            )

        return await call_next(request)
