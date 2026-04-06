import asyncio
import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import event_bus
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("aegis.scanner")


class ScanOrchestrator:
    """Orchestrates discovery and vulnerability scans."""

    def __init__(self):
        self._active_scans: dict[str, dict] = {}

    async def launch_scan(
        self,
        target: str,
        scan_type: str,
        client: Client,
        db: AsyncSession,
    ) -> dict:
        """Launch a scan against a target."""
        from app.modules.surface.discovery import discovery_engine
        from app.modules.surface.nuclei import nuclei_scanner

        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{target.replace('.', '_')}"
        self._active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "client_id": client.id,
            "results": {},
        }

        try:
            # Stage 1: Discovery
            logger.info(f"Starting discovery for {target}")
            discovery_results = await discovery_engine.discover(target)
            self._active_scans[scan_id]["results"]["discovery"] = discovery_results

            # Create assets from discovery
            assets_created = []
            for found in discovery_results.get("hosts", []):
                asset = Asset(
                    client_id=client.id,
                    hostname=found.get("hostname", target),
                    ip_address=found.get("ip", ""),
                    asset_type=found.get("type", "web"),
                    ports=found.get("ports", []),
                    technologies=found.get("technologies", []),
                    status="active",
                    risk_score=0.0,
                    last_scan_at=datetime.utcnow(),
                )
                db.add(asset)
                await db.flush()
                assets_created.append(asset)

            # If no hosts discovered, create one for the target itself
            if not assets_created:
                asset = Asset(
                    client_id=client.id,
                    hostname=target,
                    ip_address="",
                    asset_type="web",
                    ports=[],
                    technologies=[],
                    status="active",
                    risk_score=0.0,
                    last_scan_at=datetime.utcnow(),
                )
                db.add(asset)
                await db.flush()
                assets_created.append(asset)

            # Stage 2: Vulnerability scan
            if scan_type in ("full", "vuln"):
                logger.info(f"Starting vulnerability scan for {target}")
                vuln_results = await nuclei_scanner.scan(target)
                self._active_scans[scan_id]["results"]["vulnerabilities"] = vuln_results

                for vuln_data in vuln_results.get("vulnerabilities", []):
                    vuln = Vulnerability(
                        client_id=client.id,
                        asset_id=assets_created[0].id,
                        title=vuln_data.get("title", "Unknown Vulnerability"),
                        description=vuln_data.get("description", ""),
                        severity=vuln_data.get("severity", "info"),
                        cvss_score=vuln_data.get("cvss_score"),
                        cve_id=vuln_data.get("cve_id"),
                        template_id=vuln_data.get("template_id"),
                        evidence=vuln_data.get("evidence", ""),
                        status="open",
                    )
                    db.add(vuln)

            await db.commit()

            self._active_scans[scan_id]["status"] = "completed"
            self._active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
            self._active_scans[scan_id]["assets_found"] = len(assets_created)

            await event_bus.publish("scan_completed", {
                "scan_id": scan_id,
                "target": target,
                "assets_found": len(assets_created),
            })

            return self._active_scans[scan_id]

        except Exception as e:
            logger.error(f"Scan failed for {target}: {e}")
            self._active_scans[scan_id]["status"] = "failed"
            self._active_scans[scan_id]["error"] = str(e)
            return self._active_scans[scan_id]

    def get_scan(self, scan_id: str, client_id: Optional[str] = None) -> Optional[dict]:
        scan = self._active_scans.get(scan_id)
        if scan and client_id and scan.get("client_id") != client_id:
            return None
        return scan

    def list_scans(self, client_id: Optional[str] = None) -> list[dict]:
        if client_id:
            return [s for s in self._active_scans.values() if s.get("client_id") == client_id]
        return list(self._active_scans.values())


scan_orchestrator = ScanOrchestrator()
