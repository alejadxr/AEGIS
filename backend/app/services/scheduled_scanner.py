import asyncio
import json
import logging
import os
import shutil
import socket
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
from app.services.scanner import scan_orchestrator
from app.services import asset_risk

logger = logging.getLogger("aegis.scheduled_scanner")

# Default scan intervals (can be overridden per client via client.settings)
DEFAULT_FULL_SCAN_HOURS = 2
DEFAULT_QUICK_SCAN_MINUTES = 30
DEFAULT_DISCOVERY_HOURS = 1
ALERT_MODE_SCAN_MINUTES = 30      # interval during alert mode
ALERT_MODE_DURATION_HOURS = 2     # how long alert mode lasts

DEFAULT_UPTIME_CHECK_MINUTES = 5

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

        # Uptime monitoring job (TCP port check)
        self.scheduler.add_job(
            self._run_uptime_check,
            trigger=IntervalTrigger(minutes=DEFAULT_UPTIME_CHECK_MINUTES),
            id="uptime_check",
            name="TCP port uptime check for all assets",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=60,
        )

        self.scheduler.start()
        self._running = True

        # Subscribe to threat events for adaptive mode
        event_bus.subscribe("alert_processed", self._on_alert_processed)
        event_bus.subscribe("honeypot_interaction", self._on_honeypot_interaction)

        logger.info(
            f"Scheduled scanner started — full scan every {DEFAULT_FULL_SCAN_HOURS}h, "
            f"quick scan every {DEFAULT_QUICK_SCAN_MINUTES}min, "
            f"discovery every {DEFAULT_DISCOVERY_HOURS}h, "
            f"uptime check every {DEFAULT_UPTIME_CHECK_MINUTES}min"
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

            # Group by client so each tenant gets its own `scans` row.
            by_client: dict[str, list[Asset]] = {}
            for asset in assets:
                by_client.setdefault(asset.client_id, []).append(asset)

            logger.info(f"Full-scanning {len(assets)} assets across {len(by_client)} client(s)")

            for group_client_id, group in by_client.items():
                started_at = datetime.utcnow()
                state = {
                    "id": f"sched_full_{started_at.strftime('%Y%m%d_%H%M%S')}_{group_client_id}",
                    "type": "scheduled_full",
                    "target": f"{len(group)} assets",
                    "status": "running",
                    "started_at": started_at.isoformat(),
                    "client_id": group_client_id,
                    "results": {},
                    "assets_found": 0,
                }
                await scan_orchestrator.persist_scan(db, state)

                ok_count = 0
                vuln_count_total = 0
                failures: list[tuple[str, str]] = []
                for asset in group:
                    try:
                        new_vulns = await self._scan_single_asset(asset, db, quick=False)
                        await db.commit()
                        ok_count += 1
                        vuln_count_total += new_vulns
                    except Exception as e:
                        logger.error(f"Error scanning asset {asset.hostname}: {e}")
                        await db.rollback()
                        failures.append((asset.hostname, str(e)))

                state["status"] = "completed"
                state["completed_at"] = datetime.utcnow().isoformat()
                state["assets_found"] = ok_count
                state["results"] = {
                    "assets_total": len(group),
                    "assets_scanned_ok": ok_count,
                    "vulns_found": vuln_count_total,
                    "failures": failures,
                }
                await scan_orchestrator.persist_scan(db, state)

        logger.info("Full scan complete")

    async def _run_quick_scan_all(self):
        """Run quick nmap top-100 port scan on all assets. No nuclei."""
        logger.info("Starting quick scan of all assets (top-100 ports)")
        async with async_session() as db:
            result = await db.execute(select(Asset))
            assets = result.scalars().all()

            if not assets:
                return

            # Group by client so each tenant gets its own `scans` row.
            by_client: dict[str, list[Asset]] = {}
            for asset in assets:
                by_client.setdefault(asset.client_id, []).append(asset)

            loop = asyncio.get_event_loop()
            for group_client_id, group in by_client.items():
                started_at = datetime.utcnow()
                state = {
                    "id": f"sched_quick_{started_at.strftime('%Y%m%d_%H%M%S')}_{group_client_id}",
                    "type": "scheduled_quick",
                    "target": f"{len(group)} assets",
                    "status": "running",
                    "started_at": started_at.isoformat(),
                    "client_id": group_client_id,
                    "results": {},
                    "assets_found": 0,
                }
                await scan_orchestrator.persist_scan(db, state)

                ok_count = 0
                failures: list[tuple[str, str]] = []
                for asset in group:
                    target = asset.ip_address or asset.hostname
                    if not target:
                        continue
                    try:
                        nmap_results = await loop.run_in_executor(
                            None, self._run_nmap_quick, target
                        )
                        if nmap_results.get("ports"):
                            # Merge new ports into existing (keep ports not seen in quick scan).
                            # v1.7.2: only REFRESH ports already registered on this asset
                            # (state/version/service update) — never ADD a newly-seen port
                            # discovered on a shared IP. New-port discovery is scoped work
                            # for the discovery/full scan; this loop was the source of the
                            # host-wide port pollution that made every asset on 127.0.0.1
                            # converge on one shared port set.
                            existing_ports = {p["port"]: p for p in (asset.ports or []) if isinstance(p, dict)}
                            for p in nmap_results["ports"]:
                                if p["port"] not in existing_ports:
                                    continue
                                existing_ports[p["port"]] = p
                            asset.ports = list(existing_ports.values())
                            asset.last_scan_at = datetime.utcnow()
                            await db.commit()
                            logger.info(f"Quick scan {target}: {len(nmap_results['ports'])} open ports")
                        ok_count += 1
                    except Exception as e:
                        logger.error(f"Quick scan error for {asset.hostname}: {e}")
                        await db.rollback()
                        failures.append((asset.hostname, str(e)))

                state["status"] = "completed"
                state["completed_at"] = datetime.utcnow().isoformat()
                state["assets_found"] = ok_count
                state["results"] = {
                    "assets_total": len(group),
                    "assets_scanned_ok": ok_count,
                    "vulns_found": 0,
                    "failures": failures,
                }
                await scan_orchestrator.persist_scan(db, state)

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

            started_at = datetime.utcnow()
            state = {
                "id": f"sched_rescan_{started_at.strftime('%Y%m%d_%H%M%S')}_{asset_id}",
                "type": "scheduled_rescan",
                "target": asset.ip_address or asset.hostname,
                "status": "running",
                "started_at": started_at.isoformat(),
                "client_id": client_id,
                "results": {},
                "assets_found": 1,
            }
            await scan_orchestrator.persist_scan(db, state)

            failures: list[tuple[str, str]] = []
            vuln_count_total = 0
            try:
                new_vulns = await self._scan_single_asset(asset, db, quick=False)
                await db.commit()
                vuln_count_total = new_vulns
            except Exception as e:
                logger.error(f"Re-scan error for asset {asset_id}: {e}")
                await db.rollback()
                failures.append((asset.hostname, str(e)))

            state["status"] = "completed"
            state["completed_at"] = datetime.utcnow().isoformat()
            state["assets_found"] = 1
            state["results"] = {
                "assets_total": 1,
                "assets_scanned_ok": 0 if failures else 1,
                "vulns_found": vuln_count_total,
                "failures": failures,
            }
            await scan_orchestrator.persist_scan(db, state)

    async def _scan_single_asset(self, asset: Asset, db: AsyncSession, quick: bool = False) -> int:
        """Run nmap (+ optional nuclei) + AI risk score for one asset.

        Returns the number of new vulnerabilities persisted for this asset
        (0 for quick scans, which skip the nuclei stage entirely).
        """
        target = asset.ip_address or asset.hostname
        if not target:
            return 0

        logger.info(f"Scanning asset: {target} (id={asset.id}, quick={quick})")
        loop = asyncio.get_event_loop()

        # Stage 1: nmap
        nmap_fn = self._run_nmap_quick if quick else self._run_nmap
        nmap_results = await loop.run_in_executor(None, nmap_fn, target)

        # NOTE: Do NOT overwrite asset.ports with full nmap results.
        # Each asset owns its specific port(s) — the scan confirms they're open
        # but shouldn't dump all server ports into every asset.

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
        new_vuln_count = 0
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
            new_vuln_count += 1

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

        # service_weighted_v1 — deterministic, no AI in the number. Score
        # against a merged view of the asset's already-known ports plus
        # whatever this scan just found, WITHOUT persisting that merge into
        # asset.ports (see comment above Stage 1 — an asset only owns the
        # port(s) it's registered with; this merge is scoring input only).
        existing_ports = {
            p.get("port"): p for p in (asset.ports or []) if isinstance(p, dict)
        }
        for p in nmap_results.get("ports", []):
            existing_ports[p.get("port")] = p
        merged_ports = list(existing_ports.values())

        res = asset_risk.score_asset(
            ports=merged_ports,
            ip_address=asset.ip_address,
            hostname=asset.hostname,
            critical_vulns=critical_count,
            high_vulns=high_count,
            total_vulns=len(all_vulns),
            # No fleet context available in a single-asset scan, so no
            # host-wide damping is applied here — this persisted value is a
            # coarser floor kept only for history. The API (surface.py)
            # recomputes with a fresh, client-scoped host_index on every
            # read, which is what makes it the authoritative number.
            host_index=None,
        )
        asset.risk_score = res["risk_score"]  # already 0-10 scale, no /10 division
        asset.last_scan_at = datetime.utcnow()

        # AI is commentary only from here on — it can explain the score in
        # prose for the audit trail, but it is never consulted for the
        # number itself, and its absence changes nothing about the score.
        justification = await self._ai_risk_justification(
            asset=asset,
            ports=merged_ports,
            vuln_count=len(all_vulns),
            critical_vulns=critical_count,
            high_vulns=high_count,
        )

        # Stage 5: Audit log
        db.add(AuditLog(
            client_id=asset.client_id,
            action="scheduled_scan" if not quick else "quick_scan",
            model_used=asset_risk.MODEL_VERSION,
            input_summary=(
                f"{'Quick' if quick else 'Full'} scan {target}: "
                f"{len(nmap_results.get('ports', []))} ports, "
                f"{len(nuclei_vulns)} new vulns"
            ),
            ai_reasoning=justification or "",
            decision=f"risk_score={res['risk_score']}",
            confidence=1.0,  # deterministic method — no probabilistic uncertainty
        ))

        await event_bus.publish("scan_completed", {
            "asset_id": asset.id,
            "target": target,
            "scan_type": "quick" if quick else "full",
            "ports_found": len(nmap_results.get("ports", [])),
            "vulns_found": len(nuclei_vulns),
            "risk_score": res["risk_score"],
        })

        logger.info(
            f"{'Quick' if quick else 'Full'} scan {target}: "
            f"{len(nmap_results.get('ports', []))} ports, "
            f"{len(nuclei_vulns)} new vulns, risk={res['risk_score']:.1f} ({res['risk_band']})"
        )

        return new_vuln_count

    # ------------------------------------------------------------------ #
    #  nmap                                                                #
    # ------------------------------------------------------------------ #

    def _run_nmap(self, target: str) -> dict:
        """Full nmap -sV -sC -T4 top-1000 ports."""
        nmap_bin = NMAP_PATH if os.path.isfile(NMAP_PATH) else (shutil.which("nmap") or "nmap")
        cmd = [
            nmap_bin, "-sV", "-sC", "-T4",
            "--top-ports", "1000",
            "--exclude-ports", "2222,8888",
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
            "--exclude-ports", "2222,8888",
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
            "-jsonl",
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
    #  AI risk justification (commentary only — NEVER the score)           #
    # ------------------------------------------------------------------ #

    async def _ai_risk_justification(
        self,
        asset: Asset,
        ports: list,
        vuln_count: int,
        critical_vulns: int,
        high_vulns: int,
    ) -> Optional[str]:
        """Ask the AI for a short prose explanation of the asset's risk posture.

        This is commentary ONLY, stored in ``AuditLog.ai_reasoning`` — the risk
        SCORE itself always comes from ``asset_risk.score_asset``
        (``service_weighted_v1``, fully deterministic). This function must
        never be consulted for the number and its return value is never
        parsed for one. Returns ``None`` when AI is disabled or the call
        fails; nothing else in the scan pipeline depends on this succeeding.
        """
        from app.core.openrouter import openrouter_client
        from app.core.ai_mode import ai_available

        if not ai_available():
            return None

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
            f"briefly explain the security posture in 1-2 sentences. "
            f"Do not invent a numeric risk score — one is already computed "
            f"deterministically elsewhere and yours would be ignored."
        )

        try:
            result = await openrouter_client.query(
                messages=[{"role": "user", "content": prompt}],
                task_type="risk_scoring",
                temperature=0.2,
                max_tokens=256,
            )
            content = (result.get("content") or "").strip()
            return content[:1000] or None
        except Exception as e:
            logger.debug(f"AI risk justification failed (non-fatal, score unaffected): {e}")
            return None

    # ------------------------------------------------------------------ #
    #  Uptime monitoring                                                   #
    # ------------------------------------------------------------------ #

    async def _run_uptime_check(self):
        """Check if each asset's primary port is reachable via TCP connect."""
        logger.info("Starting uptime check for all assets")
        async with async_session() as db:
            result = await db.execute(select(Asset).where(Asset.status == "active"))
            assets = result.scalars().all()

            if not assets:
                return

            loop = asyncio.get_event_loop()
            for asset in assets:
                ip = asset.ip_address or asset.hostname
                if not ip:
                    continue
                ports = asset.ports or []
                if not ports:
                    continue
                # Check the first (primary) port
                primary = ports[0] if isinstance(ports[0], dict) else {}
                port_num = primary.get("port")
                if not port_num:
                    continue

                reachable = await loop.run_in_executor(
                    None, self._tcp_check, ip, port_num
                )
                if not reachable and asset.status == "active":
                    asset.status = "inactive"
                    db.add(AuditLog(
                        client_id=asset.client_id,
                        action="uptime_alert",
                        input_summary=f"Service down: {asset.hostname} ({ip}:{port_num})",
                        decision="status_set_inactive",
                    ))
                    await event_bus.publish("node_status", {
                        "_event_type": "node_status",
                        "id": asset.id,
                        "hostname": asset.hostname,
                        "status": "offline",
                        "last_heartbeat": None,
                        "message": f"TCP connect to {ip}:{port_num} failed",
                    })
                    logger.warning(f"Uptime check FAILED: {asset.hostname} ({ip}:{port_num}) — marked inactive")
                elif reachable and asset.status == "inactive":
                    asset.status = "active"
                    logger.info(f"Uptime check RECOVERED: {asset.hostname} ({ip}:{port_num}) — marked active")

            await db.commit()
        logger.info("Uptime check complete")

    @staticmethod
    def _tcp_check(host: str, port: int, timeout: float = 5.0) -> bool:
        """Try a TCP connect; return True if the port is open."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

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
            # Get ALL clients (each gets their own assets)
            all_result = await db.execute(select(Client))
            all_clients = list(all_result.scalars().all())
            # Skip demo if real clients exist
            real_clients = [c for c in all_clients if c.slug != "demo"]
            clients = real_clients if real_clients else all_clients
            if not clients:
                logger.info("Auto-discovery: no clients found")
                return

            # Run discovery for each client
            for client in clients:
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
                        f"Auto-discovery [{client.slug}]: found {len(new_ports)} unknown ports: {new_ports}"
                    )
                    port_list = [p for p in nmap_results["ports"] if p["port"] in new_ports]
                    # Generate descriptive hostname from the first new port
                    first_port = port_list[0] if port_list else {}
                    svc_name = first_port.get("service", "service").lower().replace(" ", "-")
                    port_num = first_port.get("port", 0)
                    new_hostname = f"{svc_name}-{port_num}" if port_num else "unknown-service"

                    new_asset = Asset(
                        client_id=client.id,
                        hostname=new_hostname,
                        ip_address=AUTO_DISCOVER_TARGET,
                        asset_type="server",
                        ports=port_list,
                        technologies=[],
                        status="active",
                        risk_score=0.0,
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
                        "client_id": client.id,
                        "target": AUTO_DISCOVER_TARGET,
                        "new_ports": sorted(new_ports),
                        "message": f"Unknown services detected: {sorted(new_ports)}",
                    })
                else:
                    logger.info(f"Auto-discovery [{client.slug}]: no new unknown services")

    def _run_nmap_discovery(self, target: str) -> dict:
        """Quick nmap discovery scan for auto-discovery."""
        nmap_bin = NMAP_PATH if os.path.isfile(NMAP_PATH) else (shutil.which("nmap") or "nmap")
        cmd = [nmap_bin, "-sT", "--top-ports", "2000", "--exclude-ports", "2222,8888", "--open", "-oG", "-", target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"ports": self._parse_nmap_greppable(result.stdout)}
        except Exception as e:
            logger.error(f"nmap discovery error: {e}")
            return {"ports": []}


# Singleton
scheduled_scanner = ScheduledScanner()
