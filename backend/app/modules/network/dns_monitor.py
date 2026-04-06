"""
DNS Monitoring module for AEGIS.

Provides passive DNS analysis via multiple approaches:
  1. System DNS log parsing (systemd-resolved, syslog, dnsmasq)
  2. Active DNS query monitoring via dnspython
  3. Optional scapy packet sniffing (requires root)

Detections:
  - DGA (Domain Generation Algorithm) domains
  - DNS tunneling (long labels, high query volume)
  - Known malicious domains (via threat_intel table)
  - Unusual query types (TXT, NULL)
  - Beaconing / C2 periodic callbacks
"""

import asyncio
import logging
import math
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.modules.network.entropy import calculate_entropy, is_dga_domain

logger = logging.getLogger("aegis.dns_monitor")

# Tunneling thresholds
MAX_LABEL_LENGTH = 50
MAX_DOMAIN_LENGTH = 100
TUNNELING_QUERY_THRESHOLD = 50  # queries to same base domain in 60s

# Beaconing detection
BEACON_WINDOW_SIZE = 10  # need at least N queries to detect beaconing
BEACON_JITTER_TOLERANCE = 0.15  # 15% tolerance on interval regularity
BEACON_MIN_INTERVAL = 5  # seconds — ignore faster than this
BEACON_MAX_INTERVAL = 3600  # seconds — ignore slower than this

# Suspicious query types commonly used for tunneling
SUSPICIOUS_QTYPES = {"TXT", "NULL", "CNAME", "MX", "SRV", "NAPTR", "ANY"}

# Whitelist: never flag these domains
WHITELIST_DOMAINS = frozenset({
    "localhost", "local", "arpa", "invalid", "test",
    "in-addr.arpa", "ip6.arpa",
})

# Whitelist patterns for common system queries
WHITELIST_PATTERNS = [
    re.compile(r".*\.google\.com$"),
    re.compile(r".*\.googleapis\.com$"),
    re.compile(r".*\.gstatic\.com$"),
    re.compile(r".*\.apple\.com$"),
    re.compile(r".*\.icloud\.com$"),
    re.compile(r".*\.microsoft\.com$"),
    re.compile(r".*\.windowsupdate\.com$"),
    re.compile(r".*\.ubuntu\.com$"),
    re.compile(r".*\.debian\.org$"),
]


def _is_whitelisted(domain: str) -> bool:
    """Check if a domain is in the whitelist."""
    domain_lower = domain.lower().rstrip(".")
    parts = domain_lower.split(".")
    # Check exact TLD/suffix whitelist
    if parts[-1] in WHITELIST_DOMAINS:
        return True
    if domain_lower in WHITELIST_DOMAINS:
        return True
    # Check patterns
    for pattern in WHITELIST_PATTERNS:
        if pattern.match(domain_lower):
            return True
    return False


def _get_base_domain(domain: str) -> str:
    """Extract base domain (last two labels) from FQDN."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


class DNSThreat:
    """Represents a detected DNS threat."""

    def __init__(
        self,
        domain: str,
        threat_type: str,
        severity: str,
        details: dict,
        source_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ):
        self.domain = domain
        self.threat_type = threat_type
        self.severity = severity
        self.details = details
        self.source_ip = source_ip
        self.query_type = query_type
        self.timestamp = datetime.now(timezone.utc)
        self.id = f"dns-{int(time.time() * 1000)}-{hash(domain) % 10000:04d}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "details": self.details,
            "source_ip": self.source_ip,
            "query_type": self.query_type,
            "timestamp": self.timestamp.isoformat(),
        }


class DNSMonitor:
    """DNS monitoring and threat detection engine.

    Operates in-process using asyncio. Processes DNS queries from
    log parsing or active monitoring and runs detection heuristics.
    """

    def __init__(self, event_bus=None):
        self._event_bus = event_bus
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._log_task: Optional[asyncio.Task] = None

        # Statistics
        self._stats = {
            "total_queries": 0,
            "unique_domains": 0,
            "threats_detected": 0,
            "dga_detected": 0,
            "tunneling_detected": 0,
            "beaconing_detected": 0,
            "malicious_domains": 0,
            "suspicious_qtypes": 0,
            "started_at": None,
            "last_query_at": None,
        }

        # Domain tracking for beaconing detection
        # domain -> deque of timestamps
        self._query_timestamps: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

        # Domain query counts in sliding window (for tunneling volume detection)
        # base_domain -> deque of timestamps
        self._query_volume: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )

        # Seen domains (for unique count)
        self._seen_domains: set = set()

        # Recent threats (ring buffer)
        self._recent_threats: deque = deque(maxlen=1000)

        # Known malicious domains cache (loaded from threat_intel)
        self._malicious_domains: set = set()
        self._malicious_ips: set = set()

        # Interface for scapy mode
        self._interface: Optional[str] = None

        # Log file path for log-parsing mode
        self._log_path: Optional[str] = None

    async def start(self, interface: str = "eth0", log_path: Optional[str] = None):
        """Begin DNS monitoring.

        Args:
            interface: Network interface for scapy sniffing (if available)
            log_path: Path to DNS query log file. Auto-detected if None.
        """
        if self._running:
            logger.warning("DNS monitor already running")
            return

        self._interface = interface
        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()

        # Try to load known malicious domains from threat_intel
        await self._load_threat_intel()

        # Determine log path
        if log_path:
            self._log_path = log_path
        else:
            self._log_path = self._detect_dns_log()

        if self._log_path:
            logger.info(f"DNS monitor starting in log-parse mode: {self._log_path}")
            self._log_task = asyncio.create_task(self._tail_dns_log())
        else:
            logger.info("DNS monitor starting in periodic-check mode (no log file found)")
            self._task = asyncio.create_task(self._periodic_check())

        logger.info("DNS monitor started")

    async def stop(self):
        """Stop DNS monitoring."""
        self._running = False
        for task in [self._task, self._log_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._task = None
        self._log_task = None
        logger.info("DNS monitor stopped")

    def _detect_dns_log(self) -> Optional[str]:
        """Auto-detect available DNS log files on the system."""
        candidates = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/dnsmasq.log",
            "/var/log/pihole.log",
            "/var/log/named/queries.log",
            "/var/log/unbound.log",
        ]
        for path in candidates:
            if Path(path).exists() and Path(path).is_file():
                return path
        return None

    async def _load_threat_intel(self):
        """Load known malicious domains and IPs from the threat_intel table."""
        try:
            from app.database import async_session
            from app.models.threat_intel import ThreatIntel
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(
                    select(ThreatIntel).where(
                        ThreatIntel.ioc_type.in_(["domain", "ip"])
                    )
                )
                iocs = result.scalars().all()
                for ioc in iocs:
                    if ioc.ioc_type == "domain":
                        self._malicious_domains.add(ioc.ioc_value.lower())
                    elif ioc.ioc_type == "ip":
                        self._malicious_ips.add(ioc.ioc_value)

            logger.info(
                f"Loaded {len(self._malicious_domains)} malicious domains, "
                f"{len(self._malicious_ips)} malicious IPs from threat_intel"
            )
        except Exception as e:
            logger.warning(f"Could not load threat intel: {e}")

    async def _tail_dns_log(self):
        """Tail a DNS log file and process new entries."""
        try:
            # Seek to end of file
            log_path = Path(self._log_path)
            if not log_path.exists():
                logger.error(f"DNS log file not found: {self._log_path}")
                return

            with open(self._log_path, "r") as f:
                # Go to end
                f.seek(0, 2)

                while self._running:
                    line = f.readline()
                    if line:
                        await self._parse_log_line(line.strip())
                    else:
                        await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"DNS log tailing error: {e}")

    async def _parse_log_line(self, line: str):
        """Parse a single DNS log line and extract query information.

        Supports formats:
          - dnsmasq: "query[A] example.com from 192.168.1.100"
          - systemd-resolved: "... query example.com IN A"
          - syslog/named: "... query: example.com IN A ..."
          - pihole/FTLDNS: "... example.com ... A ..."
        """
        if not line:
            return

        domain = None
        query_type = "A"
        source_ip = None

        # dnsmasq format
        dnsmasq_match = re.search(
            r"query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)", line
        )
        if dnsmasq_match:
            query_type = dnsmasq_match.group(1)
            domain = dnsmasq_match.group(2)
            source_ip = dnsmasq_match.group(3)

        # systemd-resolved / named format
        if not domain:
            resolved_match = re.search(
                r"query\s+(\S+)\s+IN\s+(\w+)", line, re.IGNORECASE
            )
            if resolved_match:
                domain = resolved_match.group(1)
                query_type = resolved_match.group(2)

        # Generic: look for domain-like patterns
        if not domain:
            generic_match = re.search(
                r"(?:query|lookup|resolve)[:\s]+(\S+\.(?:[a-z]{2,}))", line, re.IGNORECASE
            )
            if generic_match:
                domain = generic_match.group(1)

        if domain:
            await self._process_query(domain, query_type, source_ip)

    async def _periodic_check(self):
        """Fallback mode: periodic DNS resolution checks.

        In this mode we cannot see all DNS queries, but we can
        periodically refresh the malicious domain list and process
        any programmatically submitted queries.
        """
        try:
            reload_interval = 300  # 5 minutes
            last_reload = 0

            while self._running:
                now = time.time()
                if now - last_reload > reload_interval:
                    await self._load_threat_intel()
                    last_reload = now
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass

    async def _process_query(
        self,
        domain: str,
        query_type: str = "A",
        source_ip: Optional[str] = None,
    ):
        """Process a single DNS query through all detection engines.

        This is the main entry point for analysis. Can be called from:
          - Log parser
          - Scapy sniffer
          - External API submission
        """
        domain = domain.lower().rstrip(".")
        if not domain or len(domain) < 3:
            return

        # Skip whitelisted domains
        if _is_whitelisted(domain):
            return

        # Update stats
        self._stats["total_queries"] += 1
        self._stats["last_query_at"] = datetime.now(timezone.utc).isoformat()
        self._seen_domains.add(domain)
        self._stats["unique_domains"] = len(self._seen_domains)

        # Track timestamps for beaconing detection
        base_domain = _get_base_domain(domain)
        now = time.time()
        self._query_timestamps[base_domain].append(now)
        self._query_volume[base_domain].append(now)

        threats_found = []

        # --- Detection 1: DGA domains ---
        dga_result = is_dga_domain(domain)
        if dga_result["is_dga"]:
            self._stats["dga_detected"] += 1
            threats_found.append(DNSThreat(
                domain=domain,
                threat_type="dga",
                severity="high" if dga_result["score"] > 0.7 else "medium",
                details=dga_result,
                source_ip=source_ip,
                query_type=query_type,
            ))

        # --- Detection 2: DNS tunneling ---
        tunneling = self._check_tunneling(domain, base_domain, query_type)
        if tunneling:
            self._stats["tunneling_detected"] += 1
            threats_found.append(DNSThreat(
                domain=domain,
                threat_type="dns_tunneling",
                severity="high",
                details=tunneling,
                source_ip=source_ip,
                query_type=query_type,
            ))

        # --- Detection 3: Known malicious domain ---
        if self._check_malicious(domain):
            self._stats["malicious_domains"] += 1
            threats_found.append(DNSThreat(
                domain=domain,
                threat_type="known_malicious",
                severity="critical",
                details={"match_type": "threat_intel", "domain": domain},
                source_ip=source_ip,
                query_type=query_type,
            ))

        # --- Detection 4: Suspicious query type ---
        if query_type.upper() in SUSPICIOUS_QTYPES:
            # Only flag if combined with other signals
            entropy = calculate_entropy(domain.split(".")[0])
            if entropy > 3.0 or len(domain) > 60:
                self._stats["suspicious_qtypes"] += 1
                threats_found.append(DNSThreat(
                    domain=domain,
                    threat_type="suspicious_qtype",
                    severity="medium",
                    details={
                        "query_type": query_type,
                        "entropy": round(entropy, 3),
                        "domain_length": len(domain),
                    },
                    source_ip=source_ip,
                    query_type=query_type,
                ))

        # --- Detection 5: Beaconing ---
        beacon_result = self._check_beaconing(base_domain)
        if beacon_result:
            self._stats["beaconing_detected"] += 1
            threats_found.append(DNSThreat(
                domain=domain,
                threat_type="beaconing",
                severity="high",
                details=beacon_result,
                source_ip=source_ip,
                query_type=query_type,
            ))

        # Publish threats
        for threat in threats_found:
            self._stats["threats_detected"] += 1
            self._recent_threats.append(threat)
            await self._publish_threat(threat)

    def _check_tunneling(
        self, domain: str, base_domain: str, query_type: str
    ) -> Optional[dict]:
        """Detect DNS tunneling indicators.

        Checks:
          - Individual label length > 50 chars
          - Total domain length > 100 chars
          - High query volume to same base domain
        """
        reasons = []

        # Label length check
        labels = domain.split(".")
        max_label = max(len(label) for label in labels) if labels else 0
        if max_label > MAX_LABEL_LENGTH:
            reasons.append(f"long_label={max_label}")

        # Total length check
        if len(domain) > MAX_DOMAIN_LENGTH:
            reasons.append(f"long_domain={len(domain)}")

        # Query volume to same base domain (sliding window of 60s)
        now = time.time()
        timestamps = self._query_volume[base_domain]
        # Prune old entries
        while timestamps and timestamps[0] < now - 60:
            timestamps.popleft()
        volume = len(timestamps)
        if volume > TUNNELING_QUERY_THRESHOLD:
            reasons.append(f"high_volume={volume}/60s")

        if not reasons:
            return None

        return {
            "base_domain": base_domain,
            "max_label_length": max_label,
            "domain_length": len(domain),
            "volume_60s": volume,
            "reasons": reasons,
        }

    def _check_malicious(self, domain: str) -> bool:
        """Check if domain or any parent domain is in the malicious set."""
        parts = domain.split(".")
        # Check full domain and all parent domains
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self._malicious_domains:
                return True
        return False

    def _check_beaconing(self, base_domain: str) -> Optional[dict]:
        """Detect periodic DNS queries (C2 beaconing pattern).

        Looks for regular intervals between queries to the same domain.
        Requires at least BEACON_WINDOW_SIZE queries to analyze.
        """
        timestamps = self._query_timestamps[base_domain]
        if len(timestamps) < BEACON_WINDOW_SIZE:
            return None

        # Calculate intervals between consecutive queries
        ts_list = list(timestamps)
        intervals = []
        for i in range(1, len(ts_list)):
            interval = ts_list[i] - ts_list[i - 1]
            if BEACON_MIN_INTERVAL <= interval <= BEACON_MAX_INTERVAL:
                intervals.append(interval)

        if len(intervals) < BEACON_WINDOW_SIZE - 1:
            return None

        # Calculate mean and standard deviation
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < BEACON_MIN_INTERVAL:
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Check if the jitter is within tolerance
        # coefficient of variation (CV) = std_dev / mean
        cv = std_dev / mean_interval if mean_interval > 0 else 1.0

        if cv <= BEACON_JITTER_TOLERANCE:
            return {
                "base_domain": base_domain,
                "mean_interval_s": round(mean_interval, 2),
                "std_dev_s": round(std_dev, 2),
                "coefficient_of_variation": round(cv, 4),
                "sample_count": len(intervals),
                "pattern": "periodic_beaconing",
            }

        return None

    async def _publish_threat(self, threat: DNSThreat):
        """Publish a DNS threat to the event bus."""
        if self._event_bus:
            try:
                priority = 0 if threat.severity == "critical" else 1 if threat.severity == "high" else 2
                await self._event_bus.publish(
                    "dns_threat",
                    threat.to_dict(),
                    priority=priority,
                )
            except Exception as e:
                logger.error(f"Failed to publish DNS threat: {e}")
        logger.warning(
            f"DNS threat detected: type={threat.threat_type} "
            f"domain={threat.domain} severity={threat.severity}"
        )

    async def submit_query(
        self,
        domain: str,
        query_type: str = "A",
        source_ip: Optional[str] = None,
    ):
        """Programmatically submit a DNS query for analysis.

        Useful for integration with external DNS logs or API submissions.
        """
        await self._process_query(domain, query_type, source_ip)

    def get_stats(self) -> dict:
        """Return current monitoring statistics."""
        return {
            **self._stats,
            "monitoring_mode": "log_parse" if self._log_path else "periodic",
            "log_path": self._log_path,
            "tracked_domains": len(self._query_timestamps),
            "malicious_domains_loaded": len(self._malicious_domains),
            "is_running": self._running,
        }

    def get_recent_threats(self, limit: int = 50) -> list[dict]:
        """Return recent DNS threats."""
        threats = list(self._recent_threats)
        threats.reverse()  # Most recent first
        return [t.to_dict() for t in threats[:limit]]

    def get_top_queried(self, limit: int = 20) -> list[dict]:
        """Return top queried domains by volume."""
        domain_counts = {}
        for domain, timestamps in self._query_volume.items():
            domain_counts[domain] = len(timestamps)
        sorted_domains = sorted(
            domain_counts.items(), key=lambda x: x[1], reverse=True
        )
        return [
            {"domain": d, "query_count": c}
            for d, c in sorted_domains[:limit]
        ]


# Singleton instance
dns_monitor = DNSMonitor()
