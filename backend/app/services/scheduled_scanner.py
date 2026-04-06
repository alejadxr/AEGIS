import asyncio
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.audit_log import AuditLog
from app.models.client import Client
from app.core.events import event_bus

logger = logging.getLogger("aegis.scheduled_scanner")

# Default scan intervals (can be overridden per client via client.settings)
DEFAULT_FULL_SCAN_HOURS = 2
DEFAULT_QUICK_SCAN_MINUTES = 30
DEFAULT_DISCOVERY_HOURS = 1
ALERT_MODE_SCAN_MINUTES = 30      # interval during alert mode
ALERT_MODE_DURATION_HOURS = 2     # how long alert mode lasts

NMAP_PATH = "/usr/local/bin/nmap"
NUCLEI_PATH = "nuclei"
AUTO_DISCOVER_TARGET = "127.0.0.1"


class ScheduledScanner:
    """
    Background scheduler with adaptive scan frequency.

    Normal mode:
      - Full nmap+nuclei scan every 2h (configurable per client)
      - Quick nmap top-100 scan every 30min
      - Auto-discovery every 1h

    Alert mode (triggered by incident or honeypot hit):
      - Immediate re-scan of affected assets
      - Full scans every 30min for the next 2h, then reverts to normal
    """

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._running = False
        # client_id -> datetime when alert mode expires
        self._alert_mode_until: dict[str, datetime] = {}

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def start(self):
        if self._running:
            return

        # Full scan job
        self.scheduler.add_job(
            self._run_all_assets_scan,
            trigger=IntervalTrigger(minutes=DEFAULT_FULL_SCAN_HOURS * 60),
            id="full_asset_scan",
            name="Full nmap+nuclei scan of all assets",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=300,
        )

        # Quick scan job (top-100 ports only, no nuclei)
        self.scheduler.add_job(
            self._run_quick_scan_all,
            trigger=IntervalTrigger(minutes=DEFAULT_QUICK_SCAN_MINUTES),
            id="quick_asset_scan",
            name="Quick nmap top-100 scan of all assets",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=120,
        )

        # Auto-discovery job
        self.scheduler.add_job(
            self._run_auto_discovery,
            trigger=IntervalTrigger(hours=DEFAULT_DISCOVERY_HOURS),
            id="auto_discovery",
            name="Auto-discover new services on localhost",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=300,
        )

        self.scheduler.start()
        self._running = True

        # Subscribe to threat events for adaptive mode
        event_bus.subscribe("alert_processed", self._on_alert_processed)
        event_bus.subscribe("honeypot_interaction", self._on_honeypot_interaction)

        logger.info(
            f"Scheduled scanner started — full scan every {DEFAULT_FULL_SCAN_HOURS}h, "
            f"quick scan every {DEFAULT_QUICK_SCAN_MINUTES}min, "
            f"discovery every {DEFAULT_DISCOVERY_HOURS}h"
        )

    def stop(self):
        if self._running:
            event_bus.unsubscribe("alert_processed", self._on_alert_processed)
            event_bus.unsubscribe("honeypot_interaction", self._on_honeypot_interaction)
            self.scheduler.shutdown(wait=False)
            self._running = False
            logger.info("Scheduled scanner stopped")

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    async def trigger_immediate_scan(self, client_id: Optional[str] = None):
        """Trigger an immediate full scan (called from API endpoint)."""
        logger.info(f"Immediate full scan triggered via API (client_id={client_id})")
        await self._run_all_assets_scan(client_id=client_id)

    def enter_alert_mode(self, client_id: str):
        """
        Switch a client into alert mode: accelerate full scans to every 30min
        for the next ALERT_MODE_DURATION_HOURS hours.
        """
        expires_at = datetime.utcnow() + timedelta(hours=ALERT_MODE_DURATION_HOURS)
        prev = self._alert_mode_until.get(client_id)
        # Extend if already in alert mode
        if prev is None or expires_at > prev:
            self._alert_mode_until[client_id] = expires_at
            logger.warning(
                f"Alert mode ACTIVE for client {client_id} until {expires_at.isoformat()}. "
                f"Full scans accelerated to every {ALERT_MODE_SCAN_MINUTES}min."
            )

    def is_alert_mode(self, client_id: str) -> bool:
        until = self._alert_mode_until.get(client_id)
        if until and datetime.utcnow() < until:
            return True
        # Clean up expired entry
        if client_id in self._alert_mode_until:
            del self._alert_mode_until[client_id]
            logger.info(f"Alert mode expired for client {client_id}, reverting to normal schedule.")
        return False

    def get_scan_interval(self, client: Client, scan_type: str = "full") -> int:
        """
        Return effective scan interval in minutes for a client.
        Reads from client.settings; falls back to defaults.
        Alert mode overrides the full scan interval.
        """
        settings = client.settings or {}
        scan_cfg = settings.get("scan_intervals", {})

        if scan_type == "full":
            base_minutes = scan_cfg.get("full_scan_hours", DEFAULT_FULL_SCAN_HOURS) * 60
            if self.is_alert_mode(client.id):
                return min(base_minutes, ALERT_MODE_SCAN_MINUTES)
            return base_minutes
        elif scan_type == "quick":
            return scan_cfg.get("quick_scan_minutes", DEFAULT_QUICK_SCAN_MINUTES)
        elif scan_type == "discovery":
            return scan_cfg.get("discovery_hours", DEFAULT_DISCOVERY_HOURS) * 60
        return DEFAULT_FULL_SCAN_HOURS * 60

    # ------------------------------------------------------------------ #
    #  Event handlers (adaptive triggers)                                  #
    # ------------------------------------------------------------------ #

    async def _on_alert_processed(self, data: dict):
        """When an incident is created, enter alert mode and immediately re-scan affected assets."""
        client_id = data.get("client_id")
        severity = data.get("severity", "low")
        asset_id = data.get("asset_id")

        if not client_id:
            return

        if severity in ("critical", "high", "medium"):
            self.enter_alert_mode(client_id)
            logger.info(f"Alert mode triggered by incident (severity={severity}, client={client_id})")

            # Trigger immediate re-scan of the affected asset if known
            if asset_id:
                asyncio.create_task(self._rescan_asset_by_id(asset_id, client_id))
            else:
                asyncio.create_task(self._run_all_assets_scan(client_id=client_id))

    async def _on_honeypot_interaction(self, data: dict):
        """When a honeypot is hit, enter alert mode and trigger immediate scan."""
        client_id = data.get("client_id")
        attacker_ip = data.get("attacker_ip", "unknown")

        if not client_id:
            return

        self.enter_alert_mode(client_id)
        logger.warning(
            f"Honeypot hit from {attacker_ip} — alert mode activated for client {client_id}, "
            f"triggering immediate scan."
        )
        asyncio.create_task(self._run_all_assets_scan(client_id=client_id))

    # ------------------------------------------------------------------ #
    #  Core scan pipeline                                                  #
    # ------------------------------------------------------------------ #

    async def _run_all_assets_scan(self, client_id: Optional[str] = None):
        """Fetch all assets and run full nmap+nuclei scan on each."""
        logger.info(f"Starting full scan of all assets (client_id={client_id or 'all'})")
        async with async_session() as db:
            query = select(Asset)
            if client_id:
                query = query.where(Asset.client_id == client_id)
            result = await db.execute(query)
            assets = result.scalars().all()

            if not assets:
                logger.info("No assets registered — skipping full scan")
                return

            logger.info(f"Full-scanning {len(assets)} assets")
            for asset in assets:
                try:
                    await self._scan_single_asset(asset, db, quick=False)
                    await db.commit()
                except Exception as e:
                    logger.error(f"Error scanning asset {asset.hostname}: {e}")
                    await db.rollback()

        logger.info("Full scan complete")

    async def _run_quick_scan_all(self):
        """Run quick nmap top-100 port scan on all assets. No nuclei."""
        logger.info("Starting quick scan of all assets (top-100 ports)")
        async with async_session() as db:
            result = await db.execute(select(Asset))
            assets = result.scalars().all()

            if not assets:
                return

            loop = asyncio.get_event_loop()
            for asset in assets:
                target = asset.ip_address or asset.hostname
                if not target:
                    continue
                try:
                    nmap_results = await loop.run_in_executor(
                        None, self._run_nmap_quick, target
                    )
                    if nmap_results.get("ports"):
                        # Merge new ports into existing (keep ports not seen in quick scan)
                        existing_ports = {p["port"]: p for p in (asset.ports or []) if isinstance(p, dict)}
                        for p in nmap_results["ports"]:
                            existing_ports[p["port"]] = p
                        asset.ports = list(existing_ports.values())
                        asset.last_scan_at = datetime.utcnow()
                        await db.commit()
                        logger.info(f"Quick scan {target}: {len(nmap_results['ports'])} open ports")
                except Exception as e:
                    logger.error(f"Quick scan error for {asset.hostname}: {e}")
                    await db.rollback()

        logger.info("Quick scan complete")

    async def _rescan_asset_by_id(self, asset_id: str, client_id: str):
        """Immediately re-scan a single asset by ID."""
        logger.info(f"Immediate re-scan of asset {asset_id}")
        async with async_session() as db:
            result = await db.execute(
                select(Asset).where(Asset.id == asset_id, Asset.client_id == client_id)
            )
            asset = result.scalar_one_or_none()
            if not asset:
                logger.warning(f"Asset {asset_id} not found for re-scan")
                return
            try:
                await self._scan_single_asset(asset, db, quick=False)
                await db.commit()
            except Exception as e:
                logger.error(f"Re-scan error for asset {asset_id}: {e}")
                await db.rollback()

    async def _scan_single_asset(self, asset: Asset, db: AsyncSession, quick: bool = False):
        """Run nmap (+ optional nuclei) + AI risk score for one asset."""
        target = asset.ip_address or asset.hostname
        if not target:
            return

        logger.info(f"Scanning asset: {target} (id={asset.id}, quick={quick})")
        loop = asyncio.get_event_loop()

        # Stage 1: nmap
        nmap_fn = self._run_nmap_quick if quick else self._run_nmap
        nmap_results = await loop.run_in_executor(None, nmap_fn, target)

        if nmap_results.get("ports"):
            asset.ports = nmap_results["ports"]

        # Stage 2: nuclei on web services (full scan only)
        nuclei_vulns = []
        if not quick:
            web_ports = [
                p for p in (nmap_results.get("ports") or [])
                if p.get("service") in ("http", "https", "ssl/http")
                or p.get("port") in (80, 443, 8080, 8443, 3000, 3001, 3006, 8000)
            ]

            if web_ports:
                port_num = web_ports[0]["port"]
                scheme = "https" if port_num in (443, 8443) else "http"
                url = (
                    f"{scheme}://{target}:{port_num}"
                    if port_num not in (80, 443)
                    else f"{scheme}://{target}"
                )
                nuclei_vulns = await loop.run_in_executor(None, self._run_nuclei, url)
            elif asset.asset_type in ("web", "api", "web_application", "api_server"):
                url = f"https://{target}"
                nuclei_vulns = await loop.run_in_executor(None, self._run_nuclei, url)

        # Stage 3: Store vulnerabilities
        for vuln_data in nuclei_vulns:
            existing = await db.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.template_id == vuln_data.get("template_id"),
                    Vulnerability.status == "open",
                )
            )
            if existing.scalar_one_or_none():
                continue

            vuln = Vulnerability(
                client_id=asset.client_id,
                asset_id=asset.id,
                title=vuln_data.get("title", "Unknown"),
                description=vuln_data.get("description", ""),
                severity=vuln_data.get("severity", "info"),
                cvss_score=vuln_data.get("cvss_score"),
                cve_id=vuln_data.get("cve_id"),
                template_id=vuln_data.get("template_id"),
                evidence=vuln_data.get("evidence", ""),
                status="open",
            )
            db.add(vuln)

        # Stage 4: AI risk scoring
        await db.flush()
        vuln_count_result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset.id,
                Vulnerability.status == "open",
            )
        )
        all_vulns = vuln_count_result.scalars().all()
        critical_count = sum(1 for v in all_vulns if v.severity == "critical")
        high_count = sum(1 for v in all_vulns if v.severity == "high")

        ai_result = await self._score_risk_with_ai(
            asset=asset,
            ports=nmap_results.get("ports", []),
            vuln_count=len(all_vulns),
            critical_vulns=critical_count,
            high_vulns=high_count,
        )
        asset.risk_score = ai_result["risk_score"]
        asset.last_scan_at = datetime.utcnow()

        # Stage 5: Audit log
        db.add(AuditLog(
            client_id=asset.client_id,
            action="scheduled_scan" if not quick else "quick_scan",
            model_used=ai_result.get("model_used", "none"),
            input_summary=(
                f"{'Quick' if quick else 'Full'} scan {target}: "
                f"{len(nmap_results.get('ports', []))} ports, "
                f"{len(nuclei_vulns)} new vulns"
            ),
            ai_reasoning=ai_result.get("justification", ""),
            decision=f"risk_score={ai_result['risk_score']}",
            confidence=ai_result.get("confidence", 0.0),
        ))

        await event_bus.publish("scan_completed", {
            "asset_id": asset.id,
            "target": target,
            "scan_type": "quick" if quick else "full",
            "ports_found": len(nmap_results.get("ports", [])),
            "vulns_found": len(nuclei_vulns),
            "risk_score": ai_result["risk_score"],
        })

        logger.info(
            f"{'Quick' if quick else 'Full'} scan {target}: "
            f"{len(nmap_results.get('ports', []))} ports, "
            f"{len(nuclei_vulns)} new vulns, risk={ai_result['risk_score']:.1f}"
        )

    # ------------------------------------------------------------------ #
    #  nmap                                                                #
    # ------------------------------------------------------------------ #

    def _run_nmap(self, target: str) -> dict:
        """Full nmap -sV -sC -T4 top-1000 ports."""
        nmap_bin = NMAP_PATH if os.path.isfile(NMAP_PATH) else (shutil.which("nmap") or "nmap")
        cmd = [
            nmap_bin, "-sV", "-sC", "-T4",
            "--top-ports", "1000",
            "--open",
            "-oG", "-",
            target,
        ]
        logger.info(f"Running nmap (full): {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            ports = self._parse_nmap_greppable(result.stdout)
            logger.info(f"nmap found {len(ports)} open ports on {target}")
            return {"target": target, "ports": ports, "raw": result.stdout[:2000]}
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap timed out for {target}")
            return {"target": target, "ports": [], "error": "timeout"}
        except Exception as e:
            logger.error(f"nmap error for {target}: {e}")
            return {"target": target, "ports": [], "error": str(e)}

    def _run_nmap_quick(self, target: str) -> dict:
        """Quick nmap top-100 port scan, no service detection."""
        nmap_bin = NMAP_PATH if os.path.isfile(NMAP_PATH) else (shutil.which("nmap") or "nmap")
        cmd = [
            nmap_bin, "-T4",
            "--top-ports", "100",
            "--open",
            "-oG", "-",
            target,
        ]
        logger.info(f"Running nmap (quick): {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            ports = self._parse_nmap_greppable(result.stdout)
            logger.info(f"nmap quick found {len(ports)} open ports on {target}")
            return {"target": target, "ports": ports}
        except subprocess.TimeoutExpired:
            logger.warning(f"nmap quick timed out for {target}")
            return {"target": target, "ports": [], "error": "timeout"}
        except Exception as e:
            logger.error(f"nmap quick error for {target}: {e}")
            return {"target": target, "ports": [], "error": str(e)}

    def _parse_nmap_greppable(self, output: str) -> list:
        """Parse nmap -oG output into list of port dicts."""
        ports = []
        for line in output.split("\n"):
            if "Ports:" not in line:
                continue
            port_section = line.split("Ports:")[1].strip()
            for entry in port_section.split(","):
                parts = entry.strip().split("/")
                if len(parts) >= 5:
                    try:
                        port_num = int(parts[0].strip())
                        state = parts[1].strip()
                        protocol = parts[2].strip()
                        service = parts[4].strip()
                        version = parts[6].strip() if len(parts) > 6 else ""
                        if state == "open":
                            ports.append({
                                "port": port_num,
                                "protocol": protocol,
                                "service": service,
                                "version": version,
                                "state": state,
                            })
                    except (ValueError, IndexError):
                        pass
        return ports

    # ------------------------------------------------------------------ #
    #  nuclei                                                              #
    # ------------------------------------------------------------------ #

    def _run_nuclei(self, url: str) -> list:
        """Run nuclei against a URL synchronously, return list of vuln dicts."""
        nuclei_bin = NUCLEI_PATH
        if not (os.path.isfile(nuclei_bin) and os.access(nuclei_bin, os.X_OK)):
            nuclei_bin = shutil.which("nuclei") or "nuclei"

        cmd = [
            nuclei_bin,
            "-u", url,
            "-json",
            "-silent",
            "-severity", "critical,high,medium",
            "-timeout", "10",
            "-retries", "1",
        ]
        logger.info(f"Running nuclei: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            vulns = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    finding = json.loads(line)
                    severity = finding.get("info", {}).get("severity", "info")
                    vulns.append({
                        "title": finding.get("info", {}).get("name", "Unknown"),
                        "description": finding.get("info", {}).get("description", ""),
                        "severity": severity,
                        "cvss_score": self._severity_to_cvss(severity),
                        "cve_id": self._extract_cve(finding),
                        "template_id": finding.get("template-id", ""),
                        "evidence": finding.get("matched-at", ""),
                        "matcher_name": finding.get("matcher-name", ""),
                    })
                except json.JSONDecodeError:
                    pass
            logger.info(f"nuclei found {len(vulns)} findings on {url}")
            return vulns
        except subprocess.TimeoutExpired:
            logger.warning(f"nuclei timed out for {url}")
            return []
        except Exception as e:
            logger.error(f"nuclei error for {url}: {e}")
            return []

    def _severity_to_cvss(self, severity: str) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(severity, 0.0)

    def _extract_cve(self, finding: dict) -> Optional[str]:
        refs = finding.get("info", {}).get("reference", [])
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, str) and ref.startswith("CVE-"):
                    return ref
        cve_ids = finding.get("info", {}).get("classification", {}).get("cve-id", [])
        if isinstance(cve_ids, list) and cve_ids:
            return cve_ids[0]
        return None

    # ------------------------------------------------------------------ #
    #  AI risk scoring                                                     #
    # ------------------------------------------------------------------ #

    async def _score_risk_with_ai(
        self,
        asset: Asset,
        ports: list,
        vuln_count: int,
        critical_vulns: int,
        high_vulns: int,
    ) -> dict:
        """Send scan results to OpenRouter and get AI risk score 0-100."""
        from app.core.openrouter import openrouter_client
        import re

        port_summary = ", ".join(
            f"{p['port']}/{p.get('protocol', 'tcp')} ({p.get('service', '?')})"
            for p in ports[:20]
        ) or "none detected"

        prompt = (
            f"Asset: {asset.hostname or asset.ip_address}\n"
            f"Type: {asset.asset_type}\n"
            f"Open ports: {port_summary}\n"
            f"Total open vulnerabilities: {vuln_count}\n"
            f"Critical: {critical_vulns}, High: {high_vulns}\n\n"
            f"Given this information for a {asset.asset_type or 'server'}, "
            f"rate the overall risk from 0 to 100 and explain why briefly."
        )

        try:
            result = await openrouter_client.query(
                messages=[{"role": "user", "content": prompt}],
                task_type="risk_scoring",
                temperature=0.2,
                max_tokens=512,
            )
            content = result.get("content", "")

            try:
                clean = content.strip()
                if clean.startswith("```"):
                    clean = "\n".join(clean.split("\n")[1:-1])
                data = json.loads(clean)
                risk_score = float(data.get("risk_score", 0))
                justification = data.get("justification", data.get("factors", ""))
                if isinstance(justification, list):
                    justification = "; ".join(justification)
            except (json.JSONDecodeError, TypeError, ValueError):
                numbers = re.findall(r'\b(\d{1,3})\b', content)
                risk_score = (
                    float(numbers[0])
                    if numbers
                    else self._heuristic_risk(critical_vulns, high_vulns, vuln_count, ports)
                )
                justification = content[:500]

            risk_score = max(0.0, min(100.0, risk_score))
            return {
                "risk_score": risk_score,
                "justification": str(justification)[:1000],
                "model_used": result.get("model_used", ""),
                "confidence": 0.85,
            }
        except Exception as e:
            logger.error(f"AI risk scoring failed: {e}")
            return {
                "risk_score": self._heuristic_risk(critical_vulns, high_vulns, vuln_count, ports),
                "justification": f"Heuristic fallback (AI error: {e})",
                "model_used": "heuristic",
                "confidence": 0.5,
            }

    def _heuristic_risk(self, critical: int, high: int, total: int, ports: list) -> float:
        score = min(100.0, critical * 20.0 + high * 10.0 + total * 2.0 + len(ports) * 0.5)
        return round(score, 1)

    # ------------------------------------------------------------------ #
    #  Auto-discovery                                                      #
    # ------------------------------------------------------------------ #

    async def _run_auto_discovery(self):
        """Scan localhost, compare against registered assets, alert on unknowns."""
        logger.info("Starting auto-discovery scan of localhost")
        loop = asyncio.get_event_loop()
        nmap_results = await loop.run_in_executor(
            None, self._run_nmap_discovery, AUTO_DISCOVER_TARGET
        )

        discovered_ports = set(p["port"] for p in nmap_results.get("ports", []))
        if not discovered_ports:
            logger.info("Auto-discovery: no open ports found")
            return

        async with async_session() as db:
            result = await db.execute(select(Client).where(Client.slug == "demo"))
            client = result.scalar_one_or_none()
            if not client:
                logger.info("Auto-discovery: no demo client found")
                return

            assets_result = await db.execute(
                select(Asset).where(Asset.client_id == client.id)
            )
            registered_assets = assets_result.scalars().all()
            registered_ports = set()
            for a in registered_assets:
                for p in (a.ports or []):
                    if isinstance(p, dict):
                        registered_ports.add(p.get("port"))

            new_ports = discovered_ports - registered_ports
            if new_ports:
                logger.warning(
                    f"Auto-discovery: found {len(new_ports)} unknown ports: {new_ports}"
                )
                port_list = [p for p in nmap_results["ports"] if p["port"] in new_ports]
                new_asset = Asset(
                    client_id=client.id,
                    hostname=AUTO_DISCOVER_TARGET,
                    ip_address=AUTO_DISCOVER_TARGET,
                    asset_type="server",
                    ports=port_list,
                    technologies=[],
                    status="active",
                    risk_score=0.0,
                    last_scan_at=datetime.utcnow(),
                )
                db.add(new_asset)
                db.add(AuditLog(
                    client_id=client.id,
                    action="auto_discovery_alert",
                    input_summary=(
                        f"Unknown services on {AUTO_DISCOVER_TARGET}: "
                        f"ports {sorted(new_ports)}"
                    ),
                    decision="auto_registered",
                ))
                await db.commit()

                await event_bus.publish("scan_completed", {
                    "type": "auto_discovery",
                    "target": AUTO_DISCOVER_TARGET,
                    "new_ports": sorted(new_ports),
                    "message": f"Unknown services detected: {sorted(new_ports)}",
                })
            else:
                logger.info("Auto-discovery: no new unknown services found")

    def _run_nmap_discovery(self, target: str) -> dict:
        """Quick nmap discovery scan for auto-discovery."""
        nmap_bin = NMAP_PATH if os.path.isfile(NMAP_PATH) else (shutil.which("nmap") or "nmap")
        cmd = [nmap_bin, "-sT", "--top-ports", "2000", "--open", "-oG", "-", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"ports": self._parse_nmap_greppable(result.stdout)}
        except Exception as e:
            logger.error(f"nmap discovery error: {e}")
            return {"ports": []}


# Singleton
scheduled_scanner = ScheduledScanner()
