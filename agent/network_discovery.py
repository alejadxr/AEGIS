"""
AEGIS Network Discovery & System Info Module
================================================
Pure-Python local network discovery and system information collection.
Cross-platform: Linux, macOS, Windows. No nmap dependency.
"""

import hashlib
import ipaddress
import logging
import platform
import socket
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import psutil

log = logging.getLogger("aegis-agent")

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------
_SERVICE_NAMES: dict[int, str] = {
    22: "ssh", 80: "http", 443: "https", 3306: "mysql",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
    5900: "vnc", 3389: "rdp", 21: "ftp", 25: "smtp",
    53: "dns", 110: "pop3", 143: "imap", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2222: "ssh-alt", 5000: "http-dev", 8000: "http-dev",
    8888: "http-dev", 9090: "prometheus", 9100: "node-exporter",
}


# -------------------------------------------------------------------------
# IP / Subnet Detection
# -------------------------------------------------------------------------
def get_local_ip_and_subnet() -> list[dict]:
    """
    Detect the machine's own IPs and subnets from all active interfaces.
    Returns a list of dicts: {"ip": ..., "netmask": ..., "network": ..., "interface": ...}
    """
    results = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(iface)
            if stats and not stats.isup:
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                netmask = addr.netmask
                if not ip or not netmask or ip.startswith("127."):
                    continue
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    results.append({
                        "ip": ip,
                        "netmask": netmask,
                        "network": str(network),
                        "interface": iface,
                    })
                except ValueError:
                    continue
    except Exception as exc:
        log.warning("Failed to enumerate network interfaces: %s", exc)
    return results


# -------------------------------------------------------------------------
# Host Discovery — ARP-based (cross-platform)
# -------------------------------------------------------------------------
def _parse_arp_table() -> list[dict]:
    """
    Parse the system ARP table to find live hosts on the local network.
    Works on Linux, macOS, and Windows without any extra dependencies.
    """
    hosts = []
    system = platform.system()

    try:
        if system == "Linux":
            # Try /proc/net/arp first (no subprocess needed)
            try:
                with open("/proc/net/arp", "r") as f:
                    lines = f.readlines()[1:]  # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6 and parts[2] != "0x0":
                        hosts.append({"ip": parts[0], "mac": parts[3]})
                if hosts:
                    return hosts
            except (FileNotFoundError, PermissionError):
                pass

        # Fallback: arp -a (works on Linux, macOS, Windows)
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # macOS/Linux format: hostname (IP) at MAC ...
            # Windows format: IP  MAC  type
            if system == "Windows":
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        ipaddress.IPv4Address(parts[0])
                        mac = parts[1] if len(parts) > 1 else ""
                        if mac and mac != "ff-ff-ff-ff-ff-ff" and "---" not in mac:
                            hosts.append({"ip": parts[0], "mac": mac})
                    except ValueError:
                        continue
            else:
                # Unix: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ...
                import re
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if m:
                    ip_str, mac = m.group(1), m.group(2)
                    if mac != "(incomplete)" and mac != "ff:ff:ff:ff:ff:ff":
                        hosts.append({"ip": ip_str, "mac": mac})
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.debug("ARP table parse error: %s", exc)

    return hosts


def _ping_sweep(network_str: str, max_hosts: int = 254) -> list[str]:
    """
    Ping sweep a subnet to populate the ARP table.
    Sends pings in parallel using threads. Returns list of responding IPs.
    """
    try:
        network = ipaddress.IPv4Network(network_str, strict=False)
    except ValueError:
        return []

    hosts = list(network.hosts())
    if len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]

    responding: list[str] = []
    lock = threading.Lock()

    system = platform.system()
    ping_count = ["-c", "1"] if system != "Windows" else ["-n", "1"]
    ping_timeout = ["-W", "1"] if system == "Linux" else (
        ["-W", "1000"] if system == "Windows" else ["-t", "1"]
    )

    def _ping_host(ip: str):
        try:
            result = subprocess.run(
                ["ping"] + ping_count + ping_timeout + [ip],
                capture_output=True, timeout=3,
            )
            if result.returncode == 0:
                with lock:
                    responding.append(ip)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(_ping_host, str(h)) for h in hosts]
        for f in as_completed(futures):
            pass  # just wait

    return responding


# -------------------------------------------------------------------------
# Port Scanning & Banner Grabbing
# -------------------------------------------------------------------------
def _scan_ports(ip: str, ports: list[int], timeout: float = 1.0) -> list[dict]:
    """
    Scan a list of TCP ports on a given IP using socket.connect_ex().
    Returns list of dicts for open ports with banner info.
    """
    open_ports = []

    def _check_port(port: int) -> Optional[dict]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = _grab_banner(sock, port)
                service = _SERVICE_NAMES.get(port, f"unknown-{port}")
                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                }
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return None

    with ThreadPoolExecutor(max_workers=min(len(ports), 20)) as pool:
        futures = {pool.submit(_check_port, p): p for p in ports}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    return open_ports


def _grab_banner(sock: socket.socket, port: int) -> str:
    """
    Attempt to grab a service banner from an already-connected socket.
    Sends an appropriate probe based on the port and reads the response.
    """
    try:
        sock.settimeout(2.0)

        # HTTP-based ports: send a HEAD request
        if port in (80, 443, 8080, 8443, 8000, 8888, 5000, 9090):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: check\r\n\r\n")
            data = sock.recv(1024)
            decoded = data.decode("utf-8", errors="replace")
            # Extract Server header
            for line in decoded.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:128]
            # Return first line if no Server header
            first_line = decoded.splitlines()[0] if decoded else ""
            return first_line[:128]

        # For other services, just read what they send
        # Some services send a banner on connect (SSH, FTP, SMTP, etc.)
        sock.settimeout(2.0)
        data = sock.recv(1024)
        if data:
            decoded = data.decode("utf-8", errors="replace").strip()
            # Truncate and clean
            return decoded.splitlines()[0][:128] if decoded else ""
    except (socket.timeout, OSError, UnicodeDecodeError):
        pass
    return ""


# -------------------------------------------------------------------------
# Hostname Resolution
# -------------------------------------------------------------------------
def _resolve_hostname(ip: str) -> str:
    """Try to resolve an IP to a hostname via reverse DNS."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


# -------------------------------------------------------------------------
# Full Discovery Orchestrator
# -------------------------------------------------------------------------
def discover_local_network(
    ports: list[int],
    timeout: float = 1.0,
    max_threads: int = 50,
) -> list[dict]:
    """
    Discover hosts and services on the local network.

    Steps:
      1. Detect local IP and subnet
      2. Ping sweep to populate ARP cache
      3. Parse ARP table for live hosts
      4. Port scan discovered hosts
      5. Banner grab on open ports
      6. Resolve hostnames

    Returns a flat list of discovered services, one entry per open port.
    """
    subnets = get_local_ip_and_subnet()
    if not subnets:
        log.warning("No local subnets detected for network discovery")
        return []

    local_ips = {s["ip"] for s in subnets}
    log.info("Local subnets: %s", [s["network"] for s in subnets])

    # Step 1: Ping sweep to populate ARP cache
    for subnet in subnets:
        network = subnet["network"]
        net = ipaddress.IPv4Network(network, strict=False)
        # Only sweep subnets with <= 1024 hosts (skip huge /16s etc.)
        if net.num_addresses <= 1024:
            log.info("Ping sweeping %s ...", network)
            _ping_sweep(network, max_hosts=254)
        else:
            log.info("Subnet %s too large for ping sweep, using ARP table only", network)

    # Step 2: Parse ARP table
    arp_hosts = _parse_arp_table()
    log.info("ARP table: %d hosts found", len(arp_hosts))

    # Filter to hosts within our subnets and exclude our own IPs
    target_ips = set()
    for host in arp_hosts:
        ip = host["ip"]
        if ip in local_ips:
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
            for subnet in subnets:
                net = ipaddress.IPv4Network(subnet["network"], strict=False)
                if addr in net:
                    target_ips.add(ip)
                    break
        except ValueError:
            continue

    log.info("Scanning %d discovered hosts for services...", len(target_ips))

    # Step 3: Port scan all discovered hosts
    discovered_services: list[dict] = []

    def _scan_host(ip: str) -> list[dict]:
        hostname = _resolve_hostname(ip)
        open_ports = _scan_ports(ip, ports, timeout=timeout)
        results = []
        for p in open_ports:
            results.append({
                "ip": ip,
                "hostname": hostname,
                "port": p["port"],
                "service": p["service"],
                "banner": p["banner"],
            })
        return results

    with ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_scan_host, ip): ip for ip in target_ips}
        for f in as_completed(futures):
            try:
                results = f.result()
                discovered_services.extend(results)
            except Exception as exc:
                log.debug("Host scan error: %s", exc)

    log.info("Discovery complete: %d services found on %d hosts",
             len(discovered_services), len(target_ips))
    return discovered_services


# -------------------------------------------------------------------------
# System Information Collection
# -------------------------------------------------------------------------
def collect_system_info() -> dict:
    """
    Collect detailed system information for the local machine.
    Cross-platform: Linux, macOS, Windows.
    """
    info: dict = {}

    # OS
    info["os"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }

    # CPU
    cpu_freq = psutil.cpu_freq()
    info["cpu"] = {
        "count_physical": psutil.cpu_count(logical=False),
        "count_logical": psutil.cpu_count(logical=True),
        "freq_mhz": round(cpu_freq.current) if cpu_freq else None,
    }

    # RAM
    mem = psutil.virtual_memory()
    info["ram"] = {
        "total_mb": round(mem.total / (1024 * 1024)),
        "available_mb": round(mem.available / (1024 * 1024)),
        "percent_used": mem.percent,
    }

    # Disk
    try:
        root = "C:\\" if platform.system() == "Windows" else "/"
        disk = psutil.disk_usage(root)
        info["disk"] = {
            "total_gb": round(disk.total / (1024 ** 3), 1),
            "free_gb": round(disk.free / (1024 ** 3), 1),
            "percent_used": disk.percent,
        }
    except Exception:
        info["disk"] = {}

    # Network interfaces
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = {"name": iface, "addresses": []}
        for addr in addrs:
            if addr.family == socket.AF_INET:
                iface_info["addresses"].append({
                    "type": "ipv4",
                    "address": addr.address,
                    "netmask": addr.netmask,
                })
            elif addr.family == socket.AF_INET6:
                iface_info["addresses"].append({
                    "type": "ipv6",
                    "address": addr.address,
                })
        if iface_info["addresses"]:
            interfaces.append(iface_info)
    info["network_interfaces"] = interfaces

    # Installed software (best effort, capped)
    info["installed_software"] = _collect_installed_software()

    # Running services (top processes by memory)
    services = []
    try:
        for proc in psutil.process_iter(["pid", "name", "status", "username"]):
            try:
                pinfo = proc.info
                if pinfo["status"] == psutil.STATUS_ZOMBIE:
                    continue
                services.append({
                    "pid": pinfo["pid"],
                    "name": pinfo["name"],
                    "status": pinfo["status"],
                    "user": pinfo.get("username", ""),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    # Deduplicate by name, keep unique service names
    seen_names: set[str] = set()
    unique_services = []
    for s in services:
        if s["name"] not in seen_names:
            seen_names.add(s["name"])
            unique_services.append(s)
    info["running_services"] = unique_services[:200]  # cap at 200

    return info


def _collect_installed_software() -> list[str]:
    """
    Collect a list of installed software names. Best effort, cross-platform.
    Returns a list of package/app names (capped at 500).
    """
    packages: list[str] = []
    system = platform.system()

    try:
        if system == "Linux":
            # Try dpkg first (Debian/Ubuntu)
            try:
                result = subprocess.run(
                    ["dpkg", "--list"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if line.startswith("ii"):
                            parts = line.split()
                            if len(parts) >= 2:
                                packages.append(parts[1])
                    return packages[:500]
            except FileNotFoundError:
                pass

            # Try rpm (RHEL/CentOS/Fedora)
            try:
                result = subprocess.run(
                    ["rpm", "-qa", "--qf", "%{NAME}\n"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    packages = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                    return packages[:500]
            except FileNotFoundError:
                pass

        elif system == "Darwin":
            # Homebrew
            try:
                result = subprocess.run(
                    ["brew", "list", "--formula", "-1"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    packages = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            except FileNotFoundError:
                pass

            # Also list casks
            try:
                result = subprocess.run(
                    ["brew", "list", "--cask", "-1"],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    casks = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                    packages.extend(f"(cask) {c}" for c in casks)
            except FileNotFoundError:
                pass

            return packages[:500]

        elif system == "Windows":
            # PowerShell: Get-Package (faster than wmic)
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-Package | Select-Object -ExpandProperty Name"],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    packages = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                    return packages[:500]
            except FileNotFoundError:
                pass

    except subprocess.TimeoutExpired:
        log.debug("Software collection timed out")
    except Exception as exc:
        log.debug("Software collection error: %s", exc)

    return packages[:500]


# -------------------------------------------------------------------------
# Data Sharing — Anonymization
# -------------------------------------------------------------------------
def anonymize_discovery_data(
    services: list[dict],
    system_info: dict,
    level: str = "anonymous",
) -> dict:
    """
    Anonymize collected data according to the sharing level.

    Levels:
      - anonymous: Only IOCs (malicious IPs/domains/hashes). No system info.
      - basic: IOCs + anonymized service types (no hostnames, no internal IPs).
      - detailed: IOCs + service types + OS version + software versions.
    """
    data: dict = {"level": level}

    if level == "anonymous":
        # Only IOCs are shared — no discovery data at all.
        # IOCs are attached separately by the event pipeline.
        data["services"] = []
        data["system"] = {}
        return data

    if level == "basic":
        # Share service types but strip hostnames and IPs
        anonymized_services = []
        for svc in services:
            anonymized_services.append({
                "port": svc.get("port"),
                "service": svc.get("service"),
                "banner_type": _extract_banner_type(svc.get("banner", "")),
                # No IP, no hostname
            })
        data["services"] = anonymized_services
        data["system"] = {}
        return data

    if level == "detailed":
        # Share service types + OS + software
        anonymized_services = []
        for svc in services:
            anonymized_services.append({
                "port": svc.get("port"),
                "service": svc.get("service"),
                "banner": svc.get("banner", "")[:64],
                # Still no internal IPs or hostnames
            })
        data["services"] = anonymized_services
        data["system"] = {
            "os": system_info.get("os", {}).get("system"),
            "os_version": system_info.get("os", {}).get("release"),
            "cpu_count": system_info.get("cpu", {}).get("count_logical"),
            "ram_mb": system_info.get("ram", {}).get("total_mb"),
            "installed_software": system_info.get("installed_software", []),
        }
        return data

    # Default: share nothing
    data["services"] = []
    data["system"] = {}
    return data


def _extract_banner_type(banner: str) -> str:
    """Extract the software type from a banner without version details."""
    if not banner:
        return ""
    banner_lower = banner.lower()
    known = [
        "nginx", "apache", "iis", "openssh", "postgresql", "mysql",
        "mariadb", "redis", "mongodb", "elasticsearch", "node",
        "python", "go", "caddy", "traefik", "envoy", "haproxy",
    ]
    for k in known:
        if k in banner_lower:
            return k
    return "other"


# -------------------------------------------------------------------------
# Data Sharing Prompt
# -------------------------------------------------------------------------
DATA_SHARING_PROMPT = """
[AEGIS AGENT] Data Sharing

AEGIS can share anonymized threat data with the community to improve
detection for all users. No personal data, hostnames, or internal IPs
are ever shared.

Sharing levels:
  1. Anonymous  -- Only malicious IPs/domains (recommended)
  2. Basic      -- + anonymized service types
  3. Detailed   -- + OS and software versions
  4. None       -- Don't share anything

Set AEGIS_DATA_SHARING=true and AEGIS_DATA_SHARING_LEVEL=anonymous in your .env
""".strip()
