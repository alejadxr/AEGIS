import asyncio
import json
import logging
import shutil
from typing import Optional

from app.config import settings

logger = logging.getLogger("aegis.discovery")


class DiscoveryEngine:
    """Asset discovery pipeline using nmap, subfinder, httpx with graceful fallbacks."""

    def __init__(self):
        self.nmap_path = shutil.which("nmap") or settings.NMAP_PATH
        self.subfinder_path = shutil.which("subfinder") or settings.SUBFINDER_PATH
        self.httpx_path = shutil.which("httpx") or settings.HTTPX_PATH

    async def discover(self, target: str) -> dict:
        """Run full discovery pipeline against a target."""
        results = {
            "target": target,
            "hosts": [],
            "subdomains": [],
            "open_ports": [],
            "technologies": [],
        }

        # Run subdomain enumeration and port scan in parallel
        sub_task = self._discover_subdomains(target)
        port_task = self._scan_ports(target)

        subdomains, ports = await asyncio.gather(sub_task, port_task, return_exceptions=True)

        if isinstance(subdomains, list):
            results["subdomains"] = subdomains
            for sub in subdomains:
                results["hosts"].append({
                    "hostname": sub,
                    "ip": "",
                    "type": "web",
                    "ports": [],
                    "technologies": [],
                })

        if isinstance(ports, list):
            results["open_ports"] = ports

        # If no subdomains found, add the target itself
        if not results["hosts"]:
            results["hosts"].append({
                "hostname": target,
                "ip": "",
                "type": "web",
                "ports": ports if isinstance(ports, list) else [],
                "technologies": [],
            })

        # Run HTTP probing on discovered hosts
        tech_results = await self._probe_http(
            [h["hostname"] for h in results["hosts"][:20]]
        )
        if tech_results:
            results["technologies"] = tech_results

        return results

    async def _discover_subdomains(self, domain: str) -> list[str]:
        """Use subfinder for subdomain enumeration."""
        if not shutil.which("subfinder") and not _tool_exists(self.subfinder_path):
            logger.info("subfinder not available, using fallback")
            return self._fallback_subdomains(domain)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.subfinder_path, "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode == 0:
                subs = [s.strip() for s in stdout.decode().strip().split("\n") if s.strip()]
                logger.info(f"subfinder found {len(subs)} subdomains for {domain}")
                return subs
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning(f"subfinder failed: {e}")

        return self._fallback_subdomains(domain)

    async def _scan_ports(self, target: str) -> list[dict]:
        """Use nmap for port scanning."""
        if not shutil.which("nmap") and not _tool_exists(self.nmap_path):
            logger.info("nmap not available, using fallback")
            return self._fallback_ports(target)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.nmap_path, "-sT", "--top-ports", "100", "-oG", "-", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
            if proc.returncode == 0:
                return self._parse_nmap_greppable(stdout.decode())
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning(f"nmap failed: {e}")

        return self._fallback_ports(target)

    async def _probe_http(self, hosts: list[str]) -> list[dict]:
        """Use httpx for HTTP probing and tech detection."""
        if not hosts:
            return []

        if not shutil.which("httpx") and not _tool_exists(self.httpx_path):
            logger.info("httpx not available, skipping HTTP probing")
            return []

        try:
            input_data = "\n".join(hosts)
            proc = await asyncio.create_subprocess_exec(
                self.httpx_path, "-json", "-silent",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=input_data.encode()), timeout=120
            )
            results = []
            for line in stdout.decode().strip().split("\n"):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            return results
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning(f"httpx probing failed: {e}")
            return []

    def _fallback_subdomains(self, domain: str) -> list[str]:
        """Fallback when subfinder is not available."""
        common_prefixes = ["www", "mail", "api", "admin", "dev", "staging", "app"]
        return [f"{p}.{domain}" for p in common_prefixes]

    def _fallback_ports(self, target: str) -> list[dict]:
        """Fallback when nmap is not available."""
        return [
            {"port": 80, "protocol": "tcp", "service": "http", "state": "unknown"},
            {"port": 443, "protocol": "tcp", "service": "https", "state": "unknown"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "state": "unknown"},
        ]

    def _parse_nmap_greppable(self, output: str) -> list[dict]:
        """Parse nmap greppable output."""
        ports = []
        for line in output.split("\n"):
            if "Ports:" in line:
                port_section = line.split("Ports:")[1].strip()
                for entry in port_section.split(","):
                    parts = entry.strip().split("/")
                    if len(parts) >= 5:
                        port_num = parts[0].strip()
                        state = parts[1].strip()
                        protocol = parts[2].strip()
                        service = parts[4].strip()
                        if state == "open":
                            ports.append({
                                "port": int(port_num),
                                "protocol": protocol,
                                "service": service,
                                "state": state,
                            })
        return ports


def _tool_exists(path: str) -> bool:
    import os
    return os.path.isfile(path) and os.access(path, os.X_OK)


discovery_engine = DiscoveryEngine()
