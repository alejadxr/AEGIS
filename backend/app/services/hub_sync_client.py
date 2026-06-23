"""
Hub Sync Client — connects an AEGIS node to the threat sharing hub.

Lifecycle:
  1. On startup, registers with hub (POST /threats/nodes/register)
  2. Every 60s, pulls new IOCs (GET /threats/feed?since=<last_pull>)
  3. High-confidence IPs (>=0.8) are auto-blocked locally
  4. Local detections are pushed via auto_sharer (separate module)
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

logger = logging.getLogger("aegis.hub_sync")


class HubSyncClient:
    def __init__(self):
        self.hub_url: str = ""
        self.node_id: str = ""
        self.last_pull: Optional[str] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._stats = {
            "iocs_pulled": 0,
            "iocs_pushed": 0,
            "auto_blocks": 0,
            "last_sync": None,
            "errors": 0,
            "connected": False,
        }

    async def start(self, hub_url: str, node_id: str, node_name: str = ""):
        """Start the sync client. Called during app lifespan if AEGIS_HUB_URL is set."""
        if not hub_url:
            logger.info("Hub sync disabled — no AEGIS_HUB_URL configured")
            return

        self.hub_url = hub_url.rstrip("/")
        self.node_id = node_id
        self._running = True
        self._client = httpx.AsyncClient(timeout=15.0)

        # Register with hub
        try:
            resp = await self._client.post(
                f"{self.hub_url}/api/v1/threats/nodes/register",
                json={
                    "node_id": node_id,
                    "node_name": node_name or node_id,
                    "node_url": "",
                    "version": "1.4.0",
                },
            )
            if resp.status_code == 200:
                logger.info(f"Registered with hub: {self.hub_url}")
                self._stats["connected"] = True
            else:
                logger.warning(f"Hub registration failed: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Cannot reach hub at {self.hub_url}: {e}")
            self._stats["errors"] += 1

        # Start pull loop
        self._task = asyncio.create_task(self._sync_loop())
        logger.info(f"Hub sync client started — pulling from {self.hub_url}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        if self._client:
            await self._client.aclose()
        self._stats["connected"] = False
        logger.info("Hub sync client stopped")

    async def push_ioc(self, ioc_data: dict) -> bool:
        """Push a locally-detected IOC to the hub."""
        if not self._client or not self.hub_url:
            return False
        try:
            ioc_data["node_id"] = self.node_id
            resp = await self._client.post(
                f"{self.hub_url}/api/v1/threats/intel/share",
                json=ioc_data,
            )
            if resp.status_code == 200:
                result = resp.json()
                if result.get("status") == "accepted":
                    self._stats["iocs_pushed"] += 1
                    return True
                else:
                    logger.debug(f"IOC rejected by hub: {result.get('reason')}")
            return False
        except Exception as e:
            logger.debug(f"Failed to push IOC to hub: {e}")
            self._stats["errors"] += 1
            return False

    async def _sync_loop(self):
        """Pull IOCs from hub every 60 seconds."""
        await asyncio.sleep(5)  # Initial delay
        while self._running:
            try:
                await self._pull_iocs()
                self._stats["last_sync"] = datetime.now(timezone.utc).isoformat()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Hub sync error: {e}")
                self._stats["errors"] += 1
            await asyncio.sleep(60)

    async def _pull_iocs(self):
        """Pull new IOCs from hub and auto-block high-confidence IPs."""
        if not self._client:
            return

        params = {}
        if self.last_pull:
            params["since"] = self.last_pull

        try:
            resp = await self._client.get(
                f"{self.hub_url}/api/v1/threats/feed",
                params=params,
            )
            if resp.status_code != 200:
                return

            data = resp.json()
            iocs = data.get("iocs", [])
            if not iocs:
                return

            self._stats["iocs_pulled"] += len(iocs)
            self.last_pull = datetime.now(timezone.utc).isoformat()
            self._stats["connected"] = True

            # Auto-block high-confidence IPs
            for ioc in iocs:
                if (
                    ioc.get("ioc_type") == "ip"
                    and float(ioc.get("confidence", 0)) >= 0.8
                    and ioc.get("source_instance") != self.node_id
                ):
                    await self._auto_block_ip(ioc["ioc_value"], ioc.get("threat_type", "shared_threat"))

        except Exception as e:
            logger.debug(f"Pull IOCs failed: {e}")
            self._stats["errors"] += 1

    async def _auto_block_ip(self, ip: str, reason: str):
        """Auto-block a high-confidence shared IP locally."""
        try:
            from app.core.ip_blocker import ip_blocker_service
            result = ip_blocker_service.block_ip(ip)
            if result.get("success"):
                self._stats["auto_blocks"] += 1
                logger.info(f"Auto-blocked shared threat: {ip} ({reason})")
        except Exception as e:
            logger.debug(f"Auto-block failed for {ip}: {e}")

    @property
    def stats(self) -> dict:
        return dict(self._stats)


hub_sync_client = HubSyncClient()
