import logging
from pathlib import Path
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aegis.ip_blocker")

BLOCKED_IPS_FILE = Path.home() / "AEGIS" / "blocked_ips.txt"


def _load_blocked_ips() -> set:
    try:
        if BLOCKED_IPS_FILE.exists():
            lines = BLOCKED_IPS_FILE.read_text().splitlines()
            return {line.strip() for line in lines if line.strip() and not line.startswith("#")}
    except Exception as e:
        logger.error(f"Failed to load blocked IPs: {e}")
    return set()


def _save_blocked_ips(ips: set) -> None:
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        content = "# AEGIS Blocked IPs\n# Managed automatically\n"
        content += "\n".join(sorted(ips))
        if ips:
            content += "\n"
        BLOCKED_IPS_FILE.write_text(content)
    except Exception as e:
        logger.error(f"Failed to save blocked IPs: {e}")


class IPBlockerService:
    """Service to manage blocked IPs with file persistence."""

    def __init__(self):
        self._blocked: set = _load_blocked_ips()
        logger.info(f"IP Blocker initialized with {len(self._blocked)} blocked IPs")

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def block_ip(self, ip: str) -> dict:
        if not ip or not isinstance(ip, str):
            logger.warning(f"block_ip called with invalid IP: {ip!r}, skipping")
            return {"success": False, "ip": ip, "error": "Invalid IP"}
        already_blocked = ip in self._blocked
        self._blocked.add(ip)
        _save_blocked_ips(self._blocked)
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
        self._blocked = _load_blocked_ips()
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
