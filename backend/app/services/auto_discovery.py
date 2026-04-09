"""Auto-discovery engine for AEGIS setup wizard.

Wraps nmap to discover hosts and services on a target IP or CIDR range,
identifies service types from port/banner data, estimates risk, and
suggests hostnames.
"""

import asyncio
import json
import logging
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings

logger = logging.getLogger("aegis.auto_discovery")


# ---------------------------------------------------------------------------
# Service-identification tables
# ---------------------------------------------------------------------------

PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
    # port -> (asset_type, friendly_name)
    21: ("server", "FTP"),
    22: ("server", "SSH"),
    23: ("server", "Telnet"),
    25: ("server", "SMTP"),
    53: ("server", "DNS"),
    80: ("web_application", "HTTP"),
    110: ("server", "POP3"),
    143: ("server", "IMAP"),
    443: ("web_application", "HTTPS"),
    445: ("server", "SMB"),
    993: ("server", "IMAPS"),
    995: ("server", "POP3S"),
    1433: ("database", "MSSQL"),
    1521: ("database", "Oracle DB"),
    2375: ("server", "Docker API"),
    2376: ("server", "Docker API (TLS)"),
    3000: ("web_application", "Web App"),
    3001: ("web_application", "Web App"),
    3006: ("web_application", "Web App"),
    3306: ("database", "MySQL"),
    3389: ("server", "RDP"),
    5432: ("database", "PostgreSQL"),
    5672: ("server", "RabbitMQ"),
    5900: ("server", "VNC"),
    6379: ("cache", "Redis"),
    8000: ("api_server", "API Server"),
    8080: ("api_server", "API Server"),
    8443: ("web_application", "HTTPS Alt"),
    8888: ("web_application", "Web App"),
    9090: ("web_application", "Web Admin"),
    9200: ("database", "Elasticsearch"),
    9300: ("database", "Elasticsearch Transport"),
    11211: ("cache", "Memcached"),
    11434: ("ai_service", "Ollama"),
    15672: ("server", "RabbitMQ Management"),
    27017: ("database", "MongoDB"),
}

# Ports in these ranges default to web_application
WEB_PORT_RANGES = [(3000, 3999), (8000, 8999)]

# Services considered high-risk when exposed
HIGH_RISK_SERVICES = {
    "database", "cache", "ai_service",
}

# Specific high-risk ports (common attack targets)
HIGH_RISK_PORTS = {21, 23, 445, 2375, 3389, 5900}

# Banner substrings -> technology name
BANNER_TECH_MAP: list[tuple[str, str]] = [
    ("next.js", "Next.js"),
    ("nextjs", "Next.js"),
    ("express", "Express"),
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("node", "Node.js"),
    ("python", "Python"),
    ("uvicorn", "Uvicorn"),
    ("fastapi", "FastAPI"),
    ("gunicorn", "Gunicorn"),
    ("openresty", "OpenResty"),
    ("caddy", "Caddy"),
    ("traefik", "Traefik"),
    ("postgresql", "PostgreSQL"),
    ("mysql", "MySQL"),
    ("mariadb", "MariaDB"),
    ("mongodb", "MongoDB"),
    ("redis", "Redis"),
    ("openssh", "OpenSSH"),
    ("dropbear", "Dropbear SSH"),
    ("ollama", "Ollama"),
    ("docker", "Docker"),
    ("microsoft", "Microsoft"),
]


@dataclass
class DiscoveredService:
    port: int
    protocol: str  # tcp / udp
    state: str  # open / filtered / closed
    service: str  # nmap service name
    version: str  # nmap version string
    hostname: str
    asset_type: str
    risk_estimate: int  # 0-100
    technologies: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: str
    os_guess: str
    services: list[DiscoveredService] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    scan_time_ms: int
    hosts: list[HostResult] = field(default_factory=list)
    error: Optional[str] = None


class AutoDiscovery:
    """Discovers hosts and services using nmap."""

    def __init__(self):
        self._nmap_path: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_nmap(self) -> Optional[str]:
        """Locate the nmap binary.  Checks config, common paths, then PATH."""
        if self._nmap_path:
            return self._nmap_path

        candidates = [
            settings.NMAP_PATH,
            "/usr/local/bin/nmap",
            "/usr/bin/nmap",
            "/opt/homebrew/bin/nmap",
        ]
        for path in candidates:
            if shutil.which(path):
                self._nmap_path = path
                return path

        # Fallback: search PATH
        found = shutil.which("nmap")
        if found:
            self._nmap_path = found
        return found

    async def discover_host(self, ip: str) -> ScanResult:
        """Run nmap + AI analysis against a single host."""
        result = await self._run_nmap(ip)
        # Enrich with AI if available
        result = await self._ai_enrich(result)
        return result

    async def discover_network(self, cidr: str) -> ScanResult:
        """Run nmap + AI analysis against a CIDR range."""
        result = await self._run_nmap(cidr)
        result = await self._ai_enrich(result)
        return result

    async def _ai_enrich(self, result: ScanResult) -> ScanResult:
        """Use AI to analyze nmap results and improve service identification."""
        if not result.hosts:
            return result

        try:
            from app.core.openrouter import openrouter_client

            # Build a summary of what nmap found
            scan_summary = []
            for host in result.hosts:
                host_info = f"Host: {host.ip}"
                if host.hostname:
                    host_info += f" ({host.hostname})"
                if host.os_guess:
                    host_info += f" OS: {host.os_guess}"
                for svc in host.services:
                    host_info += f"\n  Port {svc.port}/{svc.protocol}: {svc.service} {svc.version}"
                scan_summary.append(host_info)

            prompt = f"""Analyze these nmap scan results from a security platform setup. For each discovered service, provide:
1. A clear, human-readable service name (e.g., "Sable Website" not "http")
2. The likely technology (Next.js, FastAPI, PostgreSQL, etc.)
3. Risk level (0-100) with brief justification
4. A suggested hostname (short, descriptive)

Scan results:
{chr(10).join(scan_summary)}

Respond in JSON array format, one object per service:
[{{"ip": "x.x.x.x", "port": 3006, "service_name": "Web Application", "technology": "Next.js", "risk": 25, "risk_reason": "Standard web app", "hostname": "webapp-3006"}}]

Only return the JSON array, no other text."""

            ai_result = await openrouter_client.query(
                messages=[{"role": "user", "content": prompt}],
                task_type="triage",
                temperature=0.1,
                max_tokens=2048,
            )

            content = ai_result.get("content", "")
            # Extract JSON from response
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                ai_services = json.loads(json_match.group())
                # Build lookup by ip:port
                ai_lookup: dict[str, dict] = {}
                for item in ai_services:
                    key = f"{item.get('ip', '')}:{item.get('port', 0)}"
                    ai_lookup[key] = item

                # Merge AI analysis into scan results
                for host in result.hosts:
                    for svc in host.services:
                        key = f"{host.ip}:{svc.port}"
                        ai_info = ai_lookup.get(key)
                        if ai_info:
                            if ai_info.get("service_name"):
                                svc.service = ai_info["service_name"]
                            if ai_info.get("hostname"):
                                svc.hostname = ai_info["hostname"]
                            if ai_info.get("risk") is not None:
                                svc.risk_estimate = int(ai_info["risk"])
                            tech = ai_info.get("technology", "")
                            if tech and tech not in svc.technologies:
                                svc.technologies.insert(0, tech)

                logger.info(f"AI enriched {len(ai_lookup)} services from scan")

        except Exception as exc:
            # AI enrichment is best-effort — scan still works without it
            logger.warning(f"AI enrichment failed (scan results unchanged): {exc}")

        return result

    def identify_service(self, port: int, banner: str) -> tuple[str, str]:
        """Map port + banner to (asset_type, friendly_name).

        Returns a tuple of (asset_type, service_name).
        """
        # Check exact port map first
        if port in PORT_SERVICE_MAP:
            asset_type, name = PORT_SERVICE_MAP[port]
        else:
            # Check web port ranges
            asset_type, name = "server", "Unknown"
            for lo, hi in WEB_PORT_RANGES:
                if lo <= port <= hi:
                    asset_type, name = "web_application", "Web App"
                    break

        # Override name with banner info when available
        if banner:
            banner_lower = banner.lower()
            for substr, tech_name in BANNER_TECH_MAP:
                if substr in banner_lower:
                    name = tech_name
                    break

        return asset_type, name

    def suggest_hostname(self, ip: str, port: int, service: str) -> str:
        """Generate a hostname suggestion based on port and service.

        Format: "{service}-{port}" (e.g., "http-8000", "ssh-22").
        Never prefixes with "www." or "mail." + IP octets.
        """
        base = service.lower().replace(" ", "-")
        # Strip special chars
        base = re.sub(r"[^a-z0-9\-]", "", base)
        if not base:
            base = "service"

        return f"{base}-{port}"

    def estimate_risk(self, service: str, port: int, version: str) -> int:
        """Estimate risk score (0-100) based on service type and exposure.

        Factors:
        - Service type (database exposed = very high risk)
        - Port (known-dangerous ports)
        - Version info (outdated = higher risk)
        - Common defaults (e.g., port 22 with old SSH)
        """
        score = 30  # baseline for any open port

        # Service-type risk
        asset_type, _ = self.identify_service(port, version)
        if asset_type in HIGH_RISK_SERVICES:
            score += 40
        elif asset_type == "api_server":
            score += 15
        elif asset_type == "web_application":
            score += 10

        # Dangerous-port bonus
        if port in HIGH_RISK_PORTS:
            score += 20

        # Version-based heuristics
        if version:
            v_lower = version.lower()
            # Old/known-vulnerable indicators
            if any(kw in v_lower for kw in ("outdated", "eol", "1.x", "2.x")):
                score += 10
            # No version info at all can mean something weird
        else:
            score += 5  # Unknown version is slightly suspicious

        return min(score, 100)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_nmap(self, target: str) -> ScanResult:
        """Execute nmap and parse the output."""
        nmap_bin = self.find_nmap()
        if not nmap_bin:
            return ScanResult(
                target=target,
                scan_time_ms=0,
                error="nmap not found. Install with: brew install nmap (macOS) or apt install nmap (Linux)",
            )

        # Full scan: standard + all common web/app/db/cache/monitoring/proxy ports
        # Excludes 2222 and 8888 (AEGIS honeypot ports) to avoid false positives
        extra_ports = ",".join([
            "1080",                          # SOCKS proxy
            "1433-1434",                     # MSSQL
            "1521",                          # Oracle DB
            "2049",                          # NFS
            "2375-2376",                     # Docker API
            "2379-2380",                     # etcd
            "3000-3020",                     # Web apps (Grafana, Next.js, React, etc.)
            "3100",                          # Loki
            "3306",                          # MySQL
            "4000-4010",                     # Various dev servers
            "4040",                          # Spark UI
            "4200",                          # Angular
            "4443",                          # Alt HTTPS
            "5000-5010",                     # Flask, Docker Registry, etc.
            "5050",                          # pgAdmin
            "5173",                          # Vite
            "5432-5433",                     # PostgreSQL
            "5601",                          # Kibana
            "5672",                          # RabbitMQ
            "5900-5910",                     # VNC
            "6060",                          # pprof
            "6379-6380",                     # Redis
            "6443",                          # Kubernetes API
            "7000-7002",                     # Cassandra
            "7070",                          # Various
            "7474",                          # Neo4j
            "7687",                          # Neo4j Bolt
            "8000-8100",                     # API servers, uvicorn, etc.
            "8123",                          # Home Assistant, ClickHouse
            "8200",                          # Vault
            "8300-8302",                     # Consul
            "8443",                          # Alt HTTPS
            "8500",                          # Consul UI
            "8761",                          # Eureka
            "8765",                          # Custom APIs
            "8834",                          # Nessus
            "9000-9010",                     # SonarQube, Portainer, MinIO
            "9042",                          # Cassandra CQL
            "9090-9093",                     # Prometheus, Alertmanager
            "9100",                          # Node Exporter
            "9200-9300",                     # Elasticsearch
            "9411",                          # Zipkin
            "9443",                          # Alt HTTPS
            "9600",                          # Logstash
            "9870",                          # HDFS NameNode
            "9999-10000",                    # Various admin, Webmin
            "10250-10255",                   # Kubernetes kubelet
            "11211",                         # Memcached
            "11434",                         # Ollama
            "15672",                         # RabbitMQ Management
            "16686",                         # Jaeger
            "19999",                         # Netdata
            "27017-27019",                   # MongoDB
            "28017",                         # MongoDB Web UI
            "50000",                         # Jenkins agent
            "50070",                         # HDFS
        ])
        cmd = [
            nmap_bin,
            "-sV",        # service/version detection
            "-T4",        # aggressive timing
            "-p", f"1-1024,{extra_ports}",
            "-oG", "-",   # greppable output to stdout
            target,
        ]

        logger.info(f"Running nmap: {' '.join(cmd)}")
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            elapsed_ms = int((time.monotonic() - start) * 1000)
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ScanResult(target=target, scan_time_ms=elapsed_ms, error="nmap timed out after 300s")
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ScanResult(target=target, scan_time_ms=elapsed_ms, error=str(exc))

        output = stdout.decode(errors="replace")
        err_output = stderr.decode(errors="replace")

        if proc.returncode != 0 and not output.strip():
            return ScanResult(
                target=target,
                scan_time_ms=elapsed_ms,
                error=f"nmap exited with code {proc.returncode}: {err_output[:500]}",
            )

        hosts = self._parse_greppable(output)
        return ScanResult(target=target, scan_time_ms=elapsed_ms, hosts=hosts)

    def _parse_greppable(self, output: str) -> list[HostResult]:
        """Parse nmap greppable (-oG -) output."""
        hosts: list[HostResult] = []
        # Pattern: Host: <ip> (<hostname>)\tPorts: <port>/<state>/<proto>//<service>//<version>/, ...
        host_pattern = re.compile(
            r"^Host:\s+(\S+)\s+\(([^)]*)\).*Ports:\s+(.+)",
            re.MULTILINE,
        )

        for match in host_pattern.finditer(output):
            ip = match.group(1)
            hostname = match.group(2) or ""
            ports_str = match.group(3)

            services: list[DiscoveredService] = []
            # Each port entry: port/state/protocol//service_name//version/
            port_entries = ports_str.split(",")
            for entry in port_entries:
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("/")
                if len(parts) < 7:
                    continue

                port_num = int(parts[0].strip()) if parts[0].strip().isdigit() else 0
                state = parts[1].strip()
                protocol = parts[2].strip()
                service_name = parts[4].strip() if len(parts) > 4 else ""
                version_str = parts[6].strip() if len(parts) > 6 else ""

                if state != "open":
                    continue

                asset_type, friendly = self.identify_service(port_num, f"{service_name} {version_str}")
                risk = self.estimate_risk(friendly, port_num, version_str)
                svc_hostname = hostname or self.suggest_hostname(ip, port_num, friendly)

                # Detect technologies from banner
                techs: list[str] = []
                combined = f"{service_name} {version_str}".lower()
                for substr, tech_name in BANNER_TECH_MAP:
                    if substr in combined:
                        techs.append(tech_name)

                services.append(DiscoveredService(
                    port=port_num,
                    protocol=protocol,
                    state=state,
                    service=friendly,
                    version=version_str,
                    hostname=svc_hostname,
                    asset_type=asset_type,
                    risk_estimate=risk,
                    technologies=techs,
                ))

            if services:
                os_guess = ""
                # Try to extract OS from the Status/OS line
                os_match = re.search(rf"Host:\s+{re.escape(ip)}.*OS:\s+(.+?)(?:\t|$)", output)
                if os_match:
                    os_guess = os_match.group(1).strip()

                hosts.append(HostResult(
                    ip=ip,
                    hostname=hostname or (services[0].hostname if services else ""),
                    os_guess=os_guess,
                    services=services,
                ))

        return hosts


# Singleton
auto_discovery = AutoDiscovery()
