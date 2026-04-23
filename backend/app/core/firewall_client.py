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


firewall_client = FirewallClient()
