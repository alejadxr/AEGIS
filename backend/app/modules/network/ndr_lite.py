"""
Lightweight Network Detection & Response (NDR) for AEGIS.

Monitors network connections via psutil to detect:
  - New listening ports (unexpected services)
  - Outbound connections to known-bad IPs
  - Connection volume anomalies (spikes)
  - Connections to unusual ports
  - Internal lateral movement patterns

NOT a full packet capture system. Designed to be low-overhead
and run continuously alongside the AEGIS platform.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

import psutil

logger = logging.getLogger("aegis.ndr_lite")

# Well-known ports that are expected for outbound connections
COMMON_OUTBOUND_PORTS = frozenset({
    20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 5432, 6379, 8080, 8443, 9090, 27017,
})

# Private IP ranges (for lateral movement detection)
PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "169.254.",
)

# Tailscale CGNAT range
TAILSCALE_PREFIX = "100."

# How long the baseline learning period lasts (seconds)
BASELINE_LEARNING_PERIOD = 86400  # 24 hours

# Anomaly thresholds
CONNECTION_SPIKE_MULTIPLIER = 3.0  # 3x normal = anomaly
LATERAL_MOVEMENT_THRESHOLD = 5  # connections to 5+ internal IPs from one process


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is in a private/reserved range."""
    if not ip:
        return False
    for prefix in PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _is_tailscale_ip(ip: str) -> bool:
    """Check if an IP is in the Tailscale CGNAT range (100.x.x.x)."""
    if not ip:
        return False
    return ip.startswith(TAILSCALE_PREFIX)


def _is_external_ip(ip: str) -> bool:
    """Check if an IP is external (not private, not localhost, not tailscale)."""
    if not ip or ip == "" or ip == "::":
        return False
    return not _is_private_ip(ip) and not _is_tailscale_ip(ip)


class NetworkAnomaly:
    """Represents a detected network anomaly."""

    def __init__(
        self,
        anomaly_type: str,
        severity: str,
        details: dict,
        process_name: Optional[str] = None,
        process_pid: Optional[int] = None,
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.details = details
        self.process_name = process_name
        self.process_pid = process_pid
        self.timestamp = datetime.utcnow()
        self.id = f"ndr-{int(time.time() * 1000)}-{hash(anomaly_type) % 10000:04d}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "details": self.details,
            "process_name": self.process_name,
            "process_pid": self.process_pid,
            "timestamp": self.timestamp.isoformat(),
        }


class NDRLite:
    """Lightweight Network Detection & Response engine.

    Monitors system network connections via psutil and detects anomalies
    against a learned baseline.
    """

    def __init__(self, event_bus=None):
        self._event_bus = event_bus
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Baseline state
        self._baseline_started_at: Optional[float] = None
        self._baseline_complete = False
        self._baseline = {
            "listening_ports": set(),          # set of (port, protocol)
            "common_remote_ips": set(),        # IPs seen during baseline
            "process_connection_counts": {},   # process_name -> avg connections
            "sample_count": 0,
        }

        # Tracking for anomaly detection
        self._process_conn_history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=60)  # 5s intervals * 60 = 5 minutes
        )

        # Known-bad IPs (loaded from threat_intel)
        self._bad_ips: set = set()

        # Statistics
        self._stats = {
            "snapshots_taken": 0,
            "anomalies_detected": 0,
            "new_ports_detected": 0,
            "bad_ip_connections": 0,
            "volume_anomalies": 0,
            "unusual_port_connections": 0,
            "lateral_movement_alerts": 0,
            "started_at": None,
            "last_snapshot_at": None,
            "baseline_complete": False,
            "baseline_progress_pct": 0,
        }

        # Recent anomalies ring buffer
        self._recent_anomalies: deque = deque(maxlen=500)

        # Current connections snapshot (for API)
        self._current_connections: list = []

        # Suppression: avoid duplicate alerts for same anomaly
        # key -> last_alert_timestamp
        self._alert_cooldown: dict[str, float] = {}
        self._cooldown_seconds = 300  # 5 min cooldown per anomaly key

    async def start(self):
        """Begin NDR monitoring."""
        if self._running:
            logger.warning("NDR already running")
            return

        self._running = True
        self._baseline_started_at = time.time()
        self._stats["started_at"] = datetime.utcnow().isoformat()

        # Load bad IPs from threat_intel
        await self._load_bad_ips()

        # Take initial snapshot for baseline
        await self._snapshot_connections()

        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("NDR Lite started (baseline learning for 24h)")

    async def stop(self):
        """Stop NDR monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("NDR Lite stopped")

    async def _load_bad_ips(self):
        """Load known-bad IPs from threat_intel table."""
        try:
            from app.database import async_session
            from app.models.threat_intel import ThreatIntel
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(
                    select(ThreatIntel).where(ThreatIntel.ioc_type == "ip")
                )
                iocs = result.scalars().all()
                for ioc in iocs:
                    self._bad_ips.add(ioc.ioc_value)
            logger.info(f"NDR loaded {len(self._bad_ips)} bad IPs from threat_intel")
        except Exception as e:
            logger.warning(f"Could not load bad IPs: {e}")

    async def _monitor_loop(self):
        """Main monitoring loop — runs every 5 seconds."""
        try:
            while self._running:
                await self._snapshot_connections()
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"NDR monitor loop error: {e}", exc_info=True)

    async def _snapshot_connections(self):
        """Take a snapshot of all active connections and run detection."""
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Fallback: try TCP only (less permissions needed)
            try:
                connections = psutil.net_connections(kind="tcp")
            except Exception:
                logger.debug("Cannot access network connections (permission denied)")
                return
        except Exception as e:
            logger.error(f"Failed to get connections: {e}")
            return

        self._stats["snapshots_taken"] += 1
        self._stats["last_snapshot_at"] = datetime.utcnow().isoformat()

        # Build structured snapshot
        snapshot = []
        listening_ports = set()
        process_connections: dict[str, list] = defaultdict(list)
        remote_ips = set()
        internal_targets_by_process: dict[str, set] = defaultdict(set)

        for conn in connections:
            entry = self._conn_to_dict(conn)
            if entry:
                snapshot.append(entry)

            # Track listening ports
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                proto = "tcp" if conn.type == 1 else "udp"  # SOCK_STREAM=1
                listening_ports.add((port, proto))

            # Track per-process connections and remote IPs
            if conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                proc_name = self._get_process_name(conn.pid)

                if proc_name:
                    process_connections[proc_name].append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                    })

                    # Track internal targets for lateral movement
                    if _is_private_ip(remote_ip):
                        internal_targets_by_process[proc_name].add(remote_ip)

                remote_ips.add(remote_ip)

        self._current_connections = snapshot

        # Update baseline or detect anomalies
        elapsed = time.time() - (self._baseline_started_at or time.time())
        if not self._baseline_complete and elapsed < BASELINE_LEARNING_PERIOD:
            # Still learning
            self._update_baseline(listening_ports, remote_ips, process_connections)
            self._stats["baseline_progress_pct"] = round(
                min(elapsed / BASELINE_LEARNING_PERIOD * 100, 100), 1
            )
        else:
            if not self._baseline_complete:
                self._baseline_complete = True
                self._stats["baseline_complete"] = True
                self._stats["baseline_progress_pct"] = 100
                logger.info(
                    f"NDR baseline learning complete. "
                    f"Listening ports: {len(self._baseline['listening_ports'])}, "
                    f"Known IPs: {len(self._baseline['common_remote_ips'])}"
                )

            # Run detections
            await self._detect_new_ports(listening_ports)
            await self._detect_bad_ip_connections(remote_ips)
            await self._detect_volume_anomalies(process_connections)
            await self._detect_unusual_ports(snapshot)
            await self._detect_lateral_movement(internal_targets_by_process)

    def _conn_to_dict(self, conn) -> Optional[dict]:
        """Convert a psutil connection to a serializable dict."""
        try:
            proc_name = self._get_process_name(conn.pid)
            entry = {
                "pid": conn.pid,
                "process": proc_name,
                "status": conn.status,
                "type": "tcp" if conn.type == 1 else "udp",
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            }
            return entry
        except Exception:
            return None

    def _get_process_name(self, pid: Optional[int]) -> Optional[str]:
        """Get process name from PID, with caching."""
        if not pid:
            return None
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _update_baseline(
        self,
        listening_ports: set,
        remote_ips: set,
        process_connections: dict,
    ):
        """Update the baseline during the learning period."""
        self._baseline["listening_ports"].update(listening_ports)
        self._baseline["common_remote_ips"].update(remote_ips)
        self._baseline["sample_count"] += 1

        # Update average connection counts per process
        for proc_name, conns in process_connections.items():
            count = len(conns)
            self._process_conn_history[proc_name].append(count)
            if len(self._process_conn_history[proc_name]) >= 5:
                avg = sum(self._process_conn_history[proc_name]) / len(
                    self._process_conn_history[proc_name]
                )
                self._baseline["process_connection_counts"][proc_name] = avg

    def _should_alert(self, key: str) -> bool:
        """Check if we should fire an alert (respects cooldown)."""
        now = time.time()
        last = self._alert_cooldown.get(key, 0)
        if now - last < self._cooldown_seconds:
            return False
        self._alert_cooldown[key] = now
        return True

    async def _detect_new_ports(self, current_ports: set):
        """Detect new listening ports that weren't in the baseline."""
        new_ports = current_ports - self._baseline["listening_ports"]
        for port, proto in new_ports:
            key = f"new_port:{port}:{proto}"
            if not self._should_alert(key):
                continue

            self._stats["new_ports_detected"] += 1
            anomaly = NetworkAnomaly(
                anomaly_type="new_listening_port",
                severity="high",
                details={
                    "port": port,
                    "protocol": proto,
                    "message": f"New {proto} listening port {port} detected",
                },
            )
            await self._emit_anomaly(anomaly)

    async def _detect_bad_ip_connections(self, remote_ips: set):
        """Detect connections to known-bad IPs."""
        for ip in remote_ips:
            if ip in self._bad_ips:
                key = f"bad_ip:{ip}"
                if not self._should_alert(key):
                    continue

                self._stats["bad_ip_connections"] += 1
                anomaly = NetworkAnomaly(
                    anomaly_type="known_bad_ip",
                    severity="critical",
                    details={
                        "remote_ip": ip,
                        "source": "threat_intel",
                        "message": f"Connection to known malicious IP: {ip}",
                    },
                )
                await self._emit_anomaly(anomaly)

    async def _detect_volume_anomalies(self, process_connections: dict):
        """Detect sudden spikes in connections from a process."""
        for proc_name, conns in process_connections.items():
            current_count = len(conns)
            baseline_avg = self._baseline["process_connection_counts"].get(proc_name)

            # Track history regardless
            self._process_conn_history[proc_name].append(current_count)

            if baseline_avg and baseline_avg > 0:
                ratio = current_count / baseline_avg
                if ratio >= CONNECTION_SPIKE_MULTIPLIER and current_count > 10:
                    key = f"volume_spike:{proc_name}"
                    if not self._should_alert(key):
                        continue

                    self._stats["volume_anomalies"] += 1
                    anomaly = NetworkAnomaly(
                        anomaly_type="connection_spike",
                        severity="medium",
                        details={
                            "current_connections": current_count,
                            "baseline_average": round(baseline_avg, 1),
                            "ratio": round(ratio, 2),
                            "message": (
                                f"Process '{proc_name}' has {current_count} connections "
                                f"({ratio:.1f}x baseline average of {baseline_avg:.0f})"
                            ),
                        },
                        process_name=proc_name,
                    )
                    await self._emit_anomaly(anomaly)

    async def _detect_unusual_ports(self, snapshot: list):
        """Detect outbound connections to unusual ports on external IPs."""
        for conn in snapshot:
            if not conn.get("remote_addr"):
                continue
            if conn.get("status") not in ("ESTABLISHED", "SYN_SENT"):
                continue

            parts = conn["remote_addr"].rsplit(":", 1)
            if len(parts) != 2:
                continue
            remote_ip, remote_port_str = parts
            try:
                remote_port = int(remote_port_str)
            except ValueError:
                continue

            if not _is_external_ip(remote_ip):
                continue

            if remote_port not in COMMON_OUTBOUND_PORTS and remote_port > 1024:
                key = f"unusual_port:{remote_ip}:{remote_port}"
                if not self._should_alert(key):
                    continue

                # Only alert if not in baseline
                if remote_ip not in self._baseline["common_remote_ips"]:
                    self._stats["unusual_port_connections"] += 1
                    anomaly = NetworkAnomaly(
                        anomaly_type="unusual_port",
                        severity="low",
                        details={
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "process": conn.get("process"),
                            "message": (
                                f"Outbound connection to unusual port {remote_port} "
                                f"on external IP {remote_ip}"
                            ),
                        },
                        process_name=conn.get("process"),
                        process_pid=conn.get("pid"),
                    )
                    await self._emit_anomaly(anomaly)

    async def _detect_lateral_movement(
        self, internal_targets_by_process: dict[str, set]
    ):
        """Detect potential lateral movement (one process connecting to many internal IPs)."""
        for proc_name, targets in internal_targets_by_process.items():
            if len(targets) >= LATERAL_MOVEMENT_THRESHOLD:
                key = f"lateral:{proc_name}"
                if not self._should_alert(key):
                    continue

                self._stats["lateral_movement_alerts"] += 1
                anomaly = NetworkAnomaly(
                    anomaly_type="lateral_movement",
                    severity="high",
                    details={
                        "process": proc_name,
                        "internal_targets": list(targets)[:20],
                        "target_count": len(targets),
                        "message": (
                            f"Process '{proc_name}' connecting to {len(targets)} "
                            f"internal IPs (possible lateral movement)"
                        ),
                    },
                    process_name=proc_name,
                )
                await self._emit_anomaly(anomaly)

    async def _emit_anomaly(self, anomaly: NetworkAnomaly):
        """Record anomaly and publish to event bus."""
        self._stats["anomalies_detected"] += 1
        self._recent_anomalies.append(anomaly)

        if self._event_bus:
            try:
                priority_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                priority = priority_map.get(anomaly.severity, 2)
                await self._event_bus.publish(
                    "network_anomaly",
                    anomaly.to_dict(),
                    priority=priority,
                )
            except Exception as e:
                logger.error(f"Failed to publish network anomaly: {e}")

        logger.warning(
            f"Network anomaly: type={anomaly.anomaly_type} "
            f"severity={anomaly.severity} "
            f"details={anomaly.details.get('message', '')}"
        )

    def get_stats(self) -> dict:
        """Return current NDR statistics."""
        return {
            **self._stats,
            "is_running": self._running,
            "current_connections_count": len(self._current_connections),
        }

    def get_current_connections(self, limit: int = 100) -> list[dict]:
        """Return current connection snapshot."""
        return self._current_connections[:limit]

    def get_recent_anomalies(self, limit: int = 50) -> list[dict]:
        """Return recent network anomalies."""
        anomalies = list(self._recent_anomalies)
        anomalies.reverse()
        return [a.to_dict() for a in anomalies[:limit]]

    def get_baseline(self) -> dict:
        """Return the current baseline state."""
        return {
            "complete": self._baseline_complete,
            "sample_count": self._baseline["sample_count"],
            "listening_ports": [
                {"port": p, "protocol": proto}
                for p, proto in sorted(self._baseline["listening_ports"])
            ],
            "known_remote_ips_count": len(self._baseline["common_remote_ips"]),
            "process_baselines": {
                proc: round(avg, 1)
                for proc, avg in self._baseline["process_connection_counts"].items()
            },
            "learning_period_hours": BASELINE_LEARNING_PERIOD / 3600,
            "progress_pct": self._stats["baseline_progress_pct"],
        }

    def reset_baseline(self):
        """Reset the baseline and restart learning."""
        self._baseline = {
            "listening_ports": set(),
            "common_remote_ips": set(),
            "process_connection_counts": {},
            "sample_count": 0,
        }
        self._baseline_complete = False
        self._baseline_started_at = time.time()
        self._stats["baseline_complete"] = False
        self._stats["baseline_progress_pct"] = 0
        self._process_conn_history.clear()
        self._alert_cooldown.clear()
        logger.info("NDR baseline reset — re-learning started")


# Singleton instance
ndr_lite = NDRLite()
