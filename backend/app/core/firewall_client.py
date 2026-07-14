import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("aegis.firewall_client")

FIREWALL_API = (settings.AEGIS_FIREWALL_URL or "").rstrip("/")
TIMEOUT = 30.0


class FirewallClient:
    """Async HTTP client for an external firewall API.

    Set AEGIS_FIREWALL_URL to the full base URL of your firewall's API
    (e.g., http://firewall.local:8000/api). The firewall must expose:
    /status, /block, /blocked, /attackers, /analyze, /events, etc.

    If AEGIS_FIREWALL_URL is not set, all methods return graceful errors
    and local middleware blocking is used instead.
    """

    async def get_status(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/status")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall get_status failed: {e}")
            return {"error": str(e), "firewall_online": False}

    async def get_attackers(self) -> list:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/attackers")
                resp.raise_for_status()
                data = resp.json()
                return data.get("attackers", data) if isinstance(data, dict) else data
        except Exception as e:
            logger.warning(f"Firewall get_attackers failed: {e}")
            return []

    async def get_attacker(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/attacker/{ip}")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall get_attacker({ip}) failed: {e}")
            return {"error": str(e)}

    async def get_blocked(self) -> list:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/blocked")
                resp.raise_for_status()
                data = resp.json()
                return data.get("blocked", [])
        except Exception as e:
            logger.warning(f"Firewall get_blocked failed: {e}")
            return []

    async def block_ip(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(f"{FIREWALL_API}/block", json={"ip": ip})
                resp.raise_for_status()
                return {"success": True, "response": resp.json()}
        except Exception as e:
            logger.error(f"Firewall block_ip({ip}) failed: {e}")
            return {"success": False, "error": str(e)}

    async def unblock_ip(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.delete(f"{FIREWALL_API}/block/{ip}")
                resp.raise_for_status()
                return {"success": True, "response": resp.json()}
        except Exception as e:
            logger.error(f"Firewall unblock_ip({ip}) failed: {e}")
            return {"success": False, "error": str(e)}

    async def analyze_ip(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(f"{FIREWALL_API}/analyze", json={"ip": ip})
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall analyze_ip({ip}) failed: {e}")
            return {"error": str(e)}

    async def investigate_ip(self, ip: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(f"{FIREWALL_API}/ai/investigate", json={"ip": ip})
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall investigate_ip({ip}) failed: {e}")
            return {"error": str(e)}

    async def get_threat_summary(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/threat-summary")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall get_threat_summary failed: {e}")
            return {"error": str(e)}

    async def get_visitors(self, minutes: int = 60) -> list:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/visitors/recent", params={"minutes": minutes})
                resp.raise_for_status()
                data = resp.json()
                return data.get("accesses", data) if isinstance(data, dict) else data
        except Exception as e:
            logger.warning(f"Firewall get_visitors failed: {e}")
            return []

    async def get_iptables_rules(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/iptables/rules")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall get_iptables_rules failed: {e}")
            return {"error": str(e)}

    async def get_events(self) -> list:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/events")
                resp.raise_for_status()
                data = resp.json()
                return data.get("events", []) if isinstance(data, dict) else data
        except Exception as e:
            logger.warning(f"Firewall get_events failed: {e}")
            return []

    async def get_auto_response_blocked(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/auto-response/blocked")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall get_auto_response_blocked failed: {e}")
            return {"blocked": [], "permanent": [], "temp": []}

    async def chat(self, message: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(f"{FIREWALL_API}/ai/chat", json={"message": message})
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall chat failed: {e}")
            return {"error": str(e)}

    # -----------------------------------------------------------------------
    # DoS Netshield (network tier) — DEFAULT OFF, gated by AEGIS_DOS_NETSHIELD
    # -----------------------------------------------------------------------
    #
    # These call the Pi firewall-agent /dos/* endpoints (dedicated AEGIS_DOS
    # iptables chain + sysctl SYN hardening). Every method early-returns a no-op
    # unless settings.AEGIS_DOS_NETSHIELD is truthy — so nothing touches the Pi
    # gateway unless an operator has explicitly enabled the network tier. The Pi
    # endpoints additionally require the X-AEGIS-Netshield: enable header (sent
    # here) AND their own env gate, and ALWAYS prepend host-safety ACCEPT rules
    # for the Mac Pro + Tailscale CGNAT before any limit/DROP.

    @staticmethod
    def _netshield_enabled() -> bool:
        # getattr keeps this safe even if AEGIS_DOS_NETSHIELD is not yet in
        # Settings (owner B adds it). Accepts bool True or truthy string.
        val = getattr(settings, "AEGIS_DOS_NETSHIELD", False)
        if isinstance(val, str):
            return val.strip().lower() in ("1", "true", "yes", "on")
        return bool(val)

    _NETSHIELD_HEADERS = {"X-AEGIS-Netshield": "enable"}

    async def apply_dos_ratelimit(
        self,
        ip: str | None = None,
        rate: int = 50,
        burst: int = 100,
        connlimit: int = 100,
        port: int = 8000,
    ) -> dict:
        """Apply per-source SYN hashlimit + connlimit on the Pi (network tier).

        No-op unless AEGIS_DOS_NETSHIELD is truthy. `ip` is accepted for API
        symmetry/logging; the Pi applies a per-source hashlimit across all
        sources (the host-safety ACCEPT rules exempt Mac Pro/Tailscale).
        """
        if not self._netshield_enabled():
            return {"success": False, "error": "netshield disabled"}
        if not FIREWALL_API:
            return {"success": False, "error": "AEGIS_FIREWALL_URL not set"}
        payload = {"rate": rate, "burst": burst, "connlimit": connlimit, "port": port}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(
                    f"{FIREWALL_API}/dos/ratelimit",
                    json=payload,
                    headers=self._NETSHIELD_HEADERS,
                )
                resp.raise_for_status()
                return {"success": True, "response": resp.json()}
        except Exception as e:
            logger.error(f"Firewall apply_dos_ratelimit failed: {e}")
            return {"success": False, "error": str(e)}

    async def harden_synflood(self) -> dict:
        """Enable SYN cookies + backlog tuning on the Pi (network tier).

        No-op unless AEGIS_DOS_NETSHIELD is truthy. Reversible via revert_dos().
        """
        if not self._netshield_enabled():
            return {"success": False, "error": "netshield disabled"}
        if not FIREWALL_API:
            return {"success": False, "error": "AEGIS_FIREWALL_URL not set"}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(
                    f"{FIREWALL_API}/dos/harden",
                    headers=self._NETSHIELD_HEADERS,
                )
                resp.raise_for_status()
                return {"success": True, "response": resp.json()}
        except Exception as e:
            logger.error(f"Firewall harden_synflood failed: {e}")
            return {"success": False, "error": str(e)}

    async def revert_dos(self) -> dict:
        """FULL rollback of the Pi network tier: remove AEGIS_DOS chain + restore sysctl.

        No-op unless AEGIS_DOS_NETSHIELD is truthy.
        """
        if not self._netshield_enabled():
            return {"success": False, "error": "netshield disabled"}
        if not FIREWALL_API:
            return {"success": False, "error": "AEGIS_FIREWALL_URL not set"}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.post(
                    f"{FIREWALL_API}/dos/revert",
                    headers=self._NETSHIELD_HEADERS,
                )
                resp.raise_for_status()
                return {"success": True, "response": resp.json()}
        except Exception as e:
            logger.error(f"Firewall revert_dos failed: {e}")
            return {"success": False, "error": str(e)}

    async def dos_status(self) -> dict:
        """Read-only Pi netshield state. Safe to call regardless of gate."""
        if not FIREWALL_API:
            return {"error": "AEGIS_FIREWALL_URL not set", "available": False}
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                resp = await client.get(f"{FIREWALL_API}/dos/status")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning(f"Firewall dos_status failed: {e}")
            return {"error": str(e), "available": False}


firewall_client = FirewallClient()
