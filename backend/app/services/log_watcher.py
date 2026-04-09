import asyncio
import ipaddress as _ipaddress
import logging
import os
import re
import shutil
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("aegis.log_watcher")

# Private/internal IP ranges that should NEVER trigger alerts
# Includes RFC1918 + CGNAT/Tailscale (100.64.0.0/10)
_SAFE_NETWORKS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / Tailscale
]


# Well-known IPs that appear in logs but are NOT attackers
_KNOWN_SAFE_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "9.9.9.9",                       # Quad9 DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
})


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is internal, private, Tailscale, or a known safe IP."""
    if ip in _KNOWN_SAFE_IPS:
        return True
    try:
        addr = _ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private or any(addr in net for net in _SAFE_NETWORKS)
    except (ValueError, TypeError):
        return False

PATTERNS = [
    {
        "name": "sql_injection", "severity": "high", "threat_type": "sql_injection",
        "regex": re.compile(r"(?i)(union\s+select|or\s+1\s*=\s*1|;\s*select|drop\s+table|information_schema|%27|--\s*$|'\s*OR\s*'|UNION\s+SELECT|OR\s+1=1)"),
    },
    {
        "name": "xss_attempt", "severity": "medium", "threat_type": "xss",
        "regex": re.compile(r"(?i)(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript:|<img\s+src\s*=\s*x|<svg\s+onload|document\.cookie)"),
    },
    {
        "name": "path_traversal", "severity": "high", "threat_type": "path_traversal",
        "regex": re.compile(r"(\.\./|\.\.%2[fF]|%2[eE]%2[eE]|%252e%252e|\.\.[\\/]|/etc/passwd|/etc/shadow|/proc/self|/windows/system32|/var/log)"),
    },
    {
        "name": "scanner_detect", "severity": "low", "threat_type": "reconnaissance",
        "regex": re.compile(r"(?i)(nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz|nuclei|zgrab|hydra|burpsuite|nmaplowercheck|/sdk|/evox|/HNAP1)"),
    },
    {
        "name": "auth_failure", "severity": "medium", "threat_type": "brute_force",
        # Only match 401 Unauthorized — NOT 403 (which is normal for tier-gated features)
        "regex": re.compile(r'"(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/[\d.]+"\s+401\b'),
    },
    {
        "name": "server_error", "severity": "low", "threat_type": "error_spike",
        "regex": re.compile(r'"(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/[\d.]+"\s+500'),
    },
    {
        "name": "cmd_injection", "severity": "critical", "threat_type": "rce",
        "regex": re.compile(r"(?i)(;\s*cat\s+/etc|\|\s*whoami|&&\s*id\b|`id`|\$\(id\)|;\s*ls\s|\|\s*cat\s|\bexec\s*\()"),
    },
]

IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# IPs that belong to AEGIS itself - never create incidents for these
# Extend via AEGIS_INTERNAL_IPS env var (comma-separated)
import os as _os
_internal_default = {"127.0.0.1", "::1", "localhost"}
_internal_extra = _os.environ.get("AEGIS_INTERNAL_IPS", "")
if _internal_extra:
    _internal_default.update(ip.strip() for ip in _internal_extra.split(",") if ip.strip())
INTERNAL_IPS = frozenset(_internal_default)

# Log source prefixes that indicate our own scheduled scanner
INTERNAL_SOURCE_MARKERS = (
    "aegis.scheduled_scanner",
    "aegis.scanner",
)

# Tool names used only by the internal scanner - skip lines containing these
# when they come from our own logger (not from external log lines)
INTERNAL_TOOL_PATTERNS = re.compile(r"(?i)(nmap|nuclei)\b")


def _extract_ip(line: str) -> Optional[str]:
    match = IP_PATTERN.search(line)
    return match.group(1) if match else None


def _is_internal_line(line: str) -> bool:
    """Return True if the log line is from AEGIS's own infrastructure."""
    # Lines emitted by our scheduled scanner logger
    for marker in INTERNAL_SOURCE_MARKERS:
        if marker in line:
            return True
    # Lines that carry only an internal/private/Tailscale IP (no external actor)
    ip = _extract_ip(line)
    if ip and (ip in INTERNAL_IPS or _is_private_ip(ip)):
        return True
    # Empty / placeholder lines (dashes only after stripping log metadata)
    stripped = re.sub(r'^\S+\s+\S+\s+', '', line).strip()
    if not stripped or stripped in ("-", "--", "---"):
        return True
    return False


class PortScanTracker:
    """Track unique ports accessed per IP to detect port scanning."""

    def __init__(self, window_seconds: int = 60, threshold: int = 10):
        self.window = window_seconds
        self.threshold = threshold
        self._port_hits: dict = defaultdict(deque)  # ip -> deque of (timestamp, port)

    def record(self, ip: str, port: int) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        q = self._port_hits[ip]
        while q and q[0][0] < cutoff:
            q.popleft()
        q.append((now, port))
        unique_ports = len(set(p for _, p in q))
        return unique_ports >= self.threshold


class RateTracker:
    def __init__(self, window_seconds: int = 60, threshold: int = 100):
        self.window = window_seconds
        self.threshold = threshold
        self._requests: dict = defaultdict(deque)

    def record(self, ip: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        q = self._requests[ip]
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        return len(q) >= self.threshold


PORT_PATTERN = re.compile(r':(\d{2,5})\b')


class LogWatcher:
    """Watches PM2 logs and detects security events."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._rate_tracker = RateTracker(window_seconds=60, threshold=500)
        self._brute_force_tracker: dict = defaultdict(deque)
        self._port_scan_tracker = PortScanTracker(window_seconds=60, threshold=10)
        self._recent_alerts: deque = deque(maxlen=500)
        # Incident deduplication: track (ip, threat_type) → last_created timestamp
        # Don't create another incident for the same IP+type within 5 minutes
        self._incident_cooldown: dict[str, datetime] = {}
        self._COOLDOWN_SECONDS = 300  # 5 minutes between incidents for same IP+type

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._watch_loop(), name="log_watcher")
        logger.info("Log watcher started")

    async def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Log watcher stopped")

    async def _watch_loop(self):
        while self._running:
            try:
                await self._tail_pm2_logs()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Log watcher error: {e}. Restarting in 10s...")
                await asyncio.sleep(10)

    async def _tail_pm2_logs(self):
        # Resolve PM2 with correct PATH (macOS node env)
        extra_paths = [
            "/usr/local/bin",
            "/usr/local/bin",
            "/usr/local/bin",
            "/usr/local/bin",
        ]
        env = os.environ.copy()
        env["PATH"] = ":".join(extra_paths) + ":" + env.get("PATH", "")

        pm2_path = shutil.which("pm2", path=env["PATH"]) or "/usr/local/bin/pm2"
        cmd = [pm2_path, "logs", "--raw", "--lines", "0"]
        logger.info(f"Starting PM2 log tail: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError:
            logger.error(f"PM2 not found at {pm2_path}. Log watcher disabled.")
            self._running = False
            return

        try:
            while self._running:
                try:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    continue

                if not line_bytes:
                    logger.warning("PM2 log stream ended")
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if line:
                    await self._process_line(line)
        finally:
            try:
                proc.terminate()
                await proc.wait()
            except Exception:
                pass

    async def _process_line(self, line: str):
        # Publish every log line to event_bus for the Raw Log Stream widget
        try:
            from app.core.events import event_bus
            await event_bus.publish("log_line", {
                "_event_type": "log_line",
                "line": line[:1000],
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass  # Never let stream publishing break log processing

        # Skip lines from our own internal scanner / infrastructure
        if _is_internal_line(line):
            return

        ip = _extract_ip(line)

        # Never flag internal/private/Tailscale IPs
        if ip and (ip in INTERNAL_IPS or _is_private_ip(ip)):
            return

        # Honey-AI breadcrumb scan — if this log line contains a UUID that
        # was planted in a deception campaign we raise a CRITICAL incident.
        try:
            await self._scan_breadcrumbs(line)
        except Exception:  # pragma: no cover - defensive, never fail the log loop
            pass

        # Port scan detection: track unique ports per IP
        if ip:
            port_match = PORT_PATTERN.search(line)
            if port_match:
                port = int(port_match.group(1))
                if self._port_scan_tracker.record(ip, port):
                    alert_key = f"port_scan:{ip}"
                    if alert_key not in self._recent_alerts:
                        self._recent_alerts.append(alert_key)
                        await self._create_incident_from_log(
                            line=line,
                            pattern_name="port_scan",
                            threat_type="port_scan",
                            severity="medium",
                            source_ip=ip,
                            description=f"Port scan detected: >10 unique ports probed by {ip} in 60s",
                        )

        # Skip rate/brute-force tracking for normal dashboard API paths
        _SAFE_PATHS = ("/dashboard/", "/api/v1/health", "/api/v1/dashboard/", "/ws", "/api/v1/nodes/heartbeat")
        is_dashboard_request = any(p in line for p in _SAFE_PATHS)

        # Brute force detection: track 401 responses per IP (not 403 tier-gating)
        if ip and " 401 " in line and not is_dashboard_request:
            now = datetime.utcnow()
            cutoff = now - timedelta(seconds=60)
            q = self._brute_force_tracker[ip]
            while q and q[0] < cutoff:
                q.popleft()
            q.append(now)
            if len(q) >= 5:
                alert_key = f"brute_force:{ip}"
                if alert_key not in self._recent_alerts:
                    self._recent_alerts.append(alert_key)
                    await self._create_incident_from_log(
                        line=line,
                        pattern_name="brute_force_401",
                        threat_type="brute_force",
                        severity="high",
                        source_ip=ip,
                        description=f"Brute force detected: {len(q)} failed auth attempts from {ip} in 60s",
                    )

        if ip and not is_dashboard_request and self._rate_tracker.record(ip):
            alert_key = f"rate:{ip}"
            if alert_key not in self._recent_alerts:
                self._recent_alerts.append(alert_key)
                await self._create_incident_from_log(
                    line=line,
                    pattern_name="high_request_rate",
                    threat_type="brute_force",
                    severity="high",
                    source_ip=ip,
                    description=f"High request rate detected from {ip} (>100 req/min)",
                )

        for pattern in PATTERNS:
            if pattern["regex"].search(line):
                # Extra guard: skip auth_failure from internal/private IPs
                if pattern["name"] == "auth_failure" and ip and (ip in INTERNAL_IPS or _is_private_ip(ip)):
                    return
                alert_key = f"{pattern['name']}:{line[:80]}"
                if alert_key not in self._recent_alerts:
                    self._recent_alerts.append(alert_key)
                    await self._create_incident_from_log(
                        line=line,
                        pattern_name=pattern["name"],
                        threat_type=pattern["threat_type"],
                        severity=pattern["severity"],
                        source_ip=ip,
                        description=f"Pattern '{pattern['name']}' detected in log: {line[:200]}",
                    )
                break

    async def _scan_breadcrumbs(self, line: str) -> None:
        """Scan a log line for Honey-AI breadcrumb UUIDs.

        A match proves an attacker consumed bait from a deception campaign
        and is now reusing the stolen value against a real service.  The
        tracker raises a CRITICAL incident via incident_cb.
        """
        # Fast-path: only bother with DB if the line might contain a UUID
        if "hb" not in line and "-" not in line:
            return
        try:
            from app.services.honey_ai import breadcrumb_tracker
            from app.database import async_session
        except Exception:  # pragma: no cover
            return
        async with async_session() as db:
            await breadcrumb_tracker.scan_text(
                db,
                text=line,
                source=f"log_watcher:{line[:200]}",
                incident_cb=breadcrumb_tracker.raise_breadcrumb_incident,
            )

    async def _create_incident_from_log(
        self,
        line: str,
        pattern_name: str,
        threat_type: str,
        severity: str,
        source_ip: Optional[str],
        description: str,
    ):
        # Skip incidents without a real source IP
        if not source_ip or source_ip in ('None', 'null', 'unknown', ''):
            logger.debug(f'Skipping incident without source IP: {pattern_name}')
            return

        # Skip private/Tailscale/internal IPs — these are NEVER attackers
        if _is_private_ip(source_ip) or source_ip in INTERNAL_IPS:
            logger.debug(f'Skipping incident for internal IP {source_ip}: {pattern_name}')
            return

        # Incident deduplication: don't spam incidents for the same IP + threat type
        cooldown_key = f"{source_ip}:{threat_type}"
        now = datetime.utcnow()
        last_created = self._incident_cooldown.get(cooldown_key)
        if last_created and (now - last_created).total_seconds() < self._COOLDOWN_SECONDS:
            logger.debug(f'Incident cooldown active for {cooldown_key}, skipping')
            return
        self._incident_cooldown[cooldown_key] = now
        try:
            from app.database import async_session
            from app.models.client import Client
            from app.services.ai_engine import ai_engine
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(select(Client).limit(1))
                client = result.scalar_one_or_none()
                if not client:
                    logger.warning("No client found - cannot create incident")
                    return

                alert_data = {
                    "source": "log_watcher",
                    "source_ip": source_ip,
                    "threat_type": threat_type,
                    "severity": severity,
                    "pattern": pattern_name,
                    "log_line": line[:500],
                    "description": description,
                    "title": f"{severity.upper()}: {pattern_name.replace('_', ' ').title()} detected",
                }

                logger.warning(
                    f"Security pattern detected [{pattern_name}] from {source_ip}: {description[:100]}"
                )
                await ai_engine.process_alert(alert_data, client, db)

                # Send webhook notification for high/critical
                if severity in ("critical", "high"):
                    try:
                        from app.services.notifier import notifier
                        await notifier.notify_critical_event(
                            event_type=pattern_name,
                            details={
                                "severity": severity,
                                "source_ip": source_ip or "unknown",
                                "message": description[:300],
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send webhook for log event: {e}")

        except Exception as e:
            logger.error(f"Failed to create incident from log: {e}")


log_watcher = LogWatcher()
