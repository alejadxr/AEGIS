"""
AEGIS Firewall Agent v1.0.1
Single-file FastAPI service that manages iptables on the Raspberry Pi.
Designed to be the firewall backend for AEGIS (Mac Pro).

Port: 8765
Persistence: /etc/aegis/blocked_ips.json
Requires: sudo access to /usr/sbin/iptables (via sudoers.d/aegis-iptables)

v1.0.1 fix: block_ip / unblock_ip / list_blocked_ips now operate on the
AEGIS_BLOCK chain (created by aegis-iptables-init.service) instead of
inserting directly into INPUT/FORWARD.  _restore_iptables_rules flushes
AEGIS_BLOCK then rebuilds it from the persisted JSON so startup is idempotent.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCKED_IPS_FILE = Path("/etc/aegis/blocked_ips.json")
EVENTS_MAX = 500  # Max events kept in memory
ATTACKERS_MAX = 1000  # Max tracked attackers
IPTABLES = "/usr/sbin/iptables"
AEGIS_CHAIN = "AEGIS_BLOCK"  # The chain owned by aegis-iptables-init.service
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

# Tailscale CGNAT range — never block these
_TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")

# Safe networks — never block
_SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    _TAILSCALE_NET,
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis-firewall")

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_start_time: float = 0.0

# Tracked attackers: ip -> {first_seen, last_seen, threat_level, attack_types, stats, intel, blocked}
_attackers: dict[str, dict] = {}

# Recent events: list of dicts
_events: list[dict] = []

# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------


# Attacker allow-list: IPs that should be blockable despite being in safe ranges.
# Used for pentest lab machines (e.g. Kali on Tailscale CGNAT).
_ATTACKER_IPS: set[str] = {
    ip.strip()
    for ip in os.environ.get("AEGIS_ATTACKER_IPS", "").split(",")
    if ip.strip()
}
if _ATTACKER_IPS:
    logger.info(f"Attacker allow-list loaded: {sorted(_ATTACKER_IPS)}")


def _is_safe_ip(ip: str) -> bool:
    """Return True if the IP should never be blocked.

    An IP in AEGIS_ATTACKER_IPS always returns False (blockable).
    """
    if ip in _ATTACKER_IPS:
        return False  # Explicit attacker = always blockable
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # Invalid = don't block
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    for net in _SAFE_NETWORKS:
        if addr in net:
            return True
    return False


def _validate_ip(ip: str) -> str:
    """Validate and normalize an IP address. Raises HTTPException on failure."""
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")


# ---------------------------------------------------------------------------
# iptables operations
# ---------------------------------------------------------------------------


def _run_iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run an iptables command with sudo."""
    cmd = ["sudo", IPTABLES] + list(args)
    logger.debug(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=10)


def _ip_is_blocked(ip: str) -> bool:
    """Check if IP already has a DROP rule in the AEGIS_BLOCK chain."""
    result = _run_iptables("-C", AEGIS_CHAIN, "-s", ip, "-j", "DROP", check=False)
    return result.returncode == 0


def block_ip(ip: str) -> bool:
    """Add DROP rule for an IP in the AEGIS_BLOCK chain (idempotent)."""
    if _ip_is_blocked(ip):
        logger.info(f"IP {ip} already in {AEGIS_CHAIN}, skipping")
        return True
    try:
        _run_iptables("-A", AEGIS_CHAIN, "-s", ip, "-j", "DROP")
        logger.info(f"Blocked IP: {ip} -> {AEGIS_CHAIN}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block {ip}: {e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout blocking {ip}")
        return False


def unblock_ip(ip: str) -> bool:
    """Remove all DROP rules for an IP from the AEGIS_BLOCK chain."""
    removed = False
    while True:
        result = _run_iptables("-D", AEGIS_CHAIN, "-s", ip, "-j", "DROP", check=False)
        if result.returncode != 0:
            break
        removed = True
    if removed:
        logger.info(f"Unblocked IP: {ip} from {AEGIS_CHAIN}")
    else:
        logger.info(f"IP {ip} was not in {AEGIS_CHAIN}")
    return True


def list_blocked_ips() -> list[str]:
    """Parse AEGIS_BLOCK chain for DROP rules and return source IPs."""
    result = _run_iptables("-L", AEGIS_CHAIN, "-n", check=False)
    blocked = []
    for line in result.stdout.splitlines():
        if "DROP" in line:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3]
                try:
                    ipaddress.ip_address(ip)
                    if ip not in blocked:
                        blocked.append(ip)
                except ValueError:
                    continue
    return blocked


def get_iptables_rules_parsed() -> dict:
    """Get full iptables rules as structured JSON."""
    chains = {}
    for chain_name in ("INPUT", "FORWARD", "OUTPUT", AEGIS_CHAIN):
        result = _run_iptables("-L", chain_name, "-n", "--line-numbers", check=False)
        rules = []
        for line in result.stdout.splitlines()[2:]:  # Skip header lines
            parts = line.split()
            # Format: num  target  prot  opt  source  destination  [extra...]
            if len(parts) >= 6:
                rules.append({
                    "num": parts[0] if parts[0].isdigit() else None,
                    "target": parts[1],
                    "prot": parts[2],
                    "opt": parts[3],
                    "source": parts[4],
                    "destination": parts[5],
                    "extra": " ".join(parts[6:]) if len(parts) > 6 else "",
                    "raw": line,
                })
        chains[chain_name] = rules
    return {"chains": chains, "retrieved_at": _now_iso()}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _load_blocked_ips() -> list[str]:
    """Load blocked IPs from persistent file."""
    if not BLOCKED_IPS_FILE.exists():
        return []
    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text())
        return data.get("blocked", []) if isinstance(data, dict) else data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load blocked IPs from {BLOCKED_IPS_FILE}: {e}")
        return []


def _save_blocked_ips(ips: list[str]):
    """Save blocked IPs to persistent file."""
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "blocked": ips,
            "updated_at": _now_iso(),
            "count": len(ips),
        }
        BLOCKED_IPS_FILE.write_text(json.dumps(data, indent=2))
        logger.debug(f"Saved {len(ips)} blocked IPs to {BLOCKED_IPS_FILE}")
    except OSError as e:
        logger.error(f"Failed to save blocked IPs: {e}")


def _restore_iptables_rules():
    """On startup, flush AEGIS_BLOCK and re-apply rules from the persistent file.

    Flushing first makes this idempotent — restarting the service never
    creates duplicate rules.
    """
    ips = _load_blocked_ips()

    # Always flush the chain so we start from a known-clean state.
    logger.info(f"Flushing {AEGIS_CHAIN} chain before restore")
    _run_iptables("-F", AEGIS_CHAIN, check=False)

    if not ips:
        logger.info("No persisted blocked IPs to restore")
        return

    logger.info(f"Restoring {len(ips)} blocked IPs from {BLOCKED_IPS_FILE}")
    restored = 0
    for ip in ips:
        try:
            _validate_ip(ip)
            if block_ip(ip):
                restored += 1
        except Exception as e:
            logger.warning(f"Failed to restore block for {ip}: {e}")
    logger.info(f"Restored {restored}/{len(ips)} iptables rules into {AEGIS_CHAIN}")


# ---------------------------------------------------------------------------
# Attacker tracking
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _track_attacker(ip: str, event_type: str = "block", threat_level: str = "HIGH",
                    attack_types: Optional[list[str]] = None):
    """Add or update an attacker in the in-memory tracker."""
    now = _now_iso()
    if ip in _attackers:
        entry = _attackers[ip]
        entry["last_seen"] = now
        entry["stats"]["total_attempts"] = entry["stats"].get("total_attempts", 0) + 1
        if event_type == "block":
            entry["stats"]["blocked_count"] = entry["stats"].get("blocked_count", 0) + 1
            entry["blocked"] = True
        if attack_types:
            existing = set(entry.get("attack_types", []))
            existing.update(attack_types)
            entry["attack_types"] = list(existing)
        # Escalate threat level
        levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        current_idx = levels.index(entry.get("threat_level", "LOW")) if entry.get("threat_level") in levels else 1
        new_idx = levels.index(threat_level) if threat_level in levels else 1
        if new_idx > current_idx:
            entry["threat_level"] = threat_level
    else:
        _attackers[ip] = {
            "ip": ip,
            "first_seen": now,
            "last_seen": now,
            "threat_level": threat_level,
            "attack_types": attack_types or [],
            "blocked": event_type == "block",
            "stats": {
                "total_attempts": 1,
                "blocked_count": 1 if event_type == "block" else 0,
            },
            "intel": {},
        }

    # Prune if too many
    if len(_attackers) > ATTACKERS_MAX:
        # Remove oldest entries
        sorted_ips = sorted(_attackers, key=lambda k: _attackers[k]["last_seen"])
        for old_ip in sorted_ips[: len(_attackers) - ATTACKERS_MAX]:
            del _attackers[old_ip]


def _add_event(event_type: str, ip: str = "", details: str = "", severity: str = "medium"):
    """Log a firewall event."""
    _events.append({
        "type": event_type,
        "ip": ip,
        "description": details,
        "severity": severity,
        "timestamp": _now_iso(),
    })
    # Trim old events
    while len(_events) > EVENTS_MAX:
        _events.pop(0)


# ---------------------------------------------------------------------------
# Geo lookup
# ---------------------------------------------------------------------------


async def _geo_lookup(ip: str) -> dict:
    """Fetch geo information for an IP from ip-api.com."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(IP_API_URL.format(ip=ip))
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "countryCode": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                        "timezone": data.get("timezone"),
                    }
    except Exception as e:
        logger.warning(f"Geo lookup failed for {ip}: {e}")
    return {}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _start_time
    _start_time = time.time()
    logger.info("AEGIS Firewall Agent starting up")

    # Restore persisted iptables rules into AEGIS_BLOCK chain
    _restore_iptables_rules()

    # Populate attacker list from currently blocked IPs
    for ip in list_blocked_ips():
        if ip not in _attackers:
            _track_attacker(ip, event_type="block", threat_level="HIGH")

    _add_event("startup", details="AEGIS Firewall Agent started", severity="info")
    logger.info("AEGIS Firewall Agent ready on port 8765")

    yield

    logger.info("AEGIS Firewall Agent shutting down")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AEGIS Firewall Agent",
    version="1.0.1",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class IPRequest(BaseModel):
    ip: str


class ChatRequest(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "aegis-firewall"}


@app.get("/status")
async def status():
    blocked = list_blocked_ips()
    return {
        "firewall_online": True,
        "blocked_count": len(blocked),
        "tracked_attackers": len(_attackers),
        "events_count": len(_events),
        "version": "1.0.1",
        "uptime_seconds": int(time.time() - _start_time),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
    }


@app.get("/attackers")
async def get_attackers():
    # Return list sorted by last_seen descending
    sorted_attackers = sorted(
        _attackers.values(),
        key=lambda a: a.get("last_seen", ""),
        reverse=True,
    )
    return {"attackers": sorted_attackers}


@app.get("/attacker/{ip}")
async def get_attacker(ip: str):
    ip = _validate_ip(ip)
    if ip not in _attackers:
        raise HTTPException(status_code=404, detail=f"Attacker {ip} not found")
    return _attackers[ip]


@app.get("/blocked")
async def get_blocked():
    # Read live state from iptables, not just the JSON file
    blocked = list_blocked_ips()
    return {"blocked": blocked, "count": len(blocked)}


@app.post("/block")
async def post_block(req: IPRequest):
    ip = _validate_ip(req.ip)

    # Safety check
    if _is_safe_ip(ip):
        raise HTTPException(
            status_code=403,
            detail=f"Refusing to block safe/internal IP: {ip}",
        )

    success = block_ip(ip)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to block {ip}")

    # Track the attacker
    _track_attacker(ip, event_type="block", threat_level="HIGH")

    # Update persistence (read live iptables state)
    blocked = list_blocked_ips()
    _save_blocked_ips(blocked)

    # Log event
    _add_event("ip_blocked", ip=ip, details=f"Blocked IP {ip} via {AEGIS_CHAIN}", severity="high")

    return {"success": True, "ip": ip, "blocked_count": len(blocked)}


@app.delete("/block/{ip}")
async def delete_block(ip: str):
    ip = _validate_ip(ip)

    unblock_ip(ip)

    # Update attacker state
    if ip in _attackers:
        _attackers[ip]["blocked"] = False

    # Update persistence (read live iptables state)
    blocked = list_blocked_ips()
    _save_blocked_ips(blocked)

    # Log event
    _add_event("ip_unblocked", ip=ip, details=f"Unblocked IP {ip} from {AEGIS_CHAIN}", severity="medium")

    return {"success": True, "ip": ip, "blocked_count": len(blocked)}


@app.post("/analyze")
async def analyze_ip(req: IPRequest):
    ip = _validate_ip(req.ip)
    geo = await _geo_lookup(ip)
    is_blocked = _ip_is_blocked(ip)
    attacker = _attackers.get(ip)

    # Update attacker intel if tracked
    if attacker:
        attacker["intel"] = geo

    result = {
        "ip": ip,
        "geo": geo,
        "blocked": is_blocked,
        "threat_level": attacker["threat_level"] if attacker else "UNKNOWN",
        "attack_types": attacker["attack_types"] if attacker else [],
        "analysis": {
            "country": geo.get("country", "Unknown"),
            "isp": geo.get("isp", "Unknown"),
            "risk_factors": [],
        },
    }

    # Basic risk assessment
    if is_blocked:
        result["analysis"]["risk_factors"].append("Currently blocked in firewall")
    if attacker and attacker["stats"].get("total_attempts", 0) > 5:
        result["analysis"]["risk_factors"].append(
            f"High activity: {attacker['stats']['total_attempts']} attempts"
        )

    _track_attacker(ip, event_type="analyze", threat_level="MEDIUM")
    return result


@app.post("/ai/investigate")
async def investigate_ip(req: IPRequest):
    ip = _validate_ip(req.ip)
    geo = await _geo_lookup(ip)
    is_blocked = _ip_is_blocked(ip)
    attacker = _attackers.get(ip)

    threat_score = 0
    reasons = []

    if is_blocked:
        threat_score += 40
        reasons.append("IP is currently blocked in firewall")

    if attacker:
        attempts = attacker["stats"].get("total_attempts", 0)
        if attempts > 10:
            threat_score += 30
            reasons.append(f"High activity: {attempts} recorded attempts")
        elif attempts > 3:
            threat_score += 15
            reasons.append(f"Moderate activity: {attempts} recorded attempts")

        if attacker.get("attack_types"):
            threat_score += 20
            reasons.append(f"Known attack types: {', '.join(attacker['attack_types'])}")

    # Geo-based heuristics
    if geo:
        threat_score += 10
        reasons.append(f"Located in {geo.get('country', 'Unknown')} ({geo.get('isp', 'Unknown ISP')})")

    threat_level = "LOW"
    if threat_score >= 70:
        threat_level = "CRITICAL"
    elif threat_score >= 50:
        threat_level = "HIGH"
    elif threat_score >= 30:
        threat_level = "MEDIUM"

    # Update tracker
    if attacker:
        attacker["intel"] = geo

    _track_attacker(ip, event_type="investigate", threat_level=threat_level)

    return {
        "ip": ip,
        "threat_score": min(threat_score, 100),
        "threat_level": threat_level,
        "geo": geo,
        "blocked": is_blocked,
        "reasoning": "; ".join(reasons) if reasons else "No significant threat indicators found",
        "recommendations": [
            "Block immediately" if threat_score >= 70 else "Monitor closely" if threat_score >= 40 else "No action needed"
        ],
    }


@app.get("/threat-summary")
async def threat_summary():
    blocked = list_blocked_ips()

    # Top attackers by attempt count
    top_attackers = sorted(
        _attackers.values(),
        key=lambda a: a["stats"].get("total_attempts", 0),
        reverse=True,
    )[:10]

    # Count by threat level
    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for atk in _attackers.values():
        level = atk.get("threat_level", "LOW")
        if level in threat_counts:
            threat_counts[level] += 1

    # Recent blocks (last 10 events of type ip_blocked)
    recent_blocks = [e for e in reversed(_events) if e["type"] == "ip_blocked"][:10]

    return {
        "total_blocked": len(blocked),
        "total_tracked": len(_attackers),
        "threat_breakdown": threat_counts,
        "top_attackers": [
            {
                "ip": a["ip"],
                "threat_level": a["threat_level"],
                "attempts": a["stats"].get("total_attempts", 0),
                "attack_types": a["attack_types"],
            }
            for a in top_attackers
        ],
        "recent_blocks": recent_blocks,
        "generated_at": _now_iso(),
    }


@app.get("/visitors/recent")
async def visitors_recent(minutes: int = 60):
    """Return recent connection data from conntrack or iptables LOG entries."""
    accesses = []

    # Try conntrack first
    try:
        result = subprocess.run(
            ["sudo", "conntrack", "-L", "-o", "extended"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            seen = set()
            for line in result.stdout.splitlines():
                # Parse conntrack output for source IPs
                src_match = re.search(r"src=(\d+\.\d+\.\d+\.\d+)", line)
                dst_match = re.search(r"dst=(\d+\.\d+\.\d+\.\d+)", line)
                proto_match = re.search(r"(tcp|udp|icmp)", line)
                dport_match = re.search(r"dport=(\d+)", line)

                if src_match:
                    src_ip = src_match.group(1)
                    if src_ip in seen:
                        continue
                    seen.add(src_ip)
                    try:
                        if _is_safe_ip(src_ip):
                            continue
                    except Exception:
                        pass
                    accesses.append({
                        "ip": src_ip,
                        "destination": dst_match.group(1) if dst_match else "",
                        "protocol": proto_match.group(1) if proto_match else "unknown",
                        "port": int(dport_match.group(1)) if dport_match else 0,
                        "timestamp": _now_iso(),
                    })
            return {"accesses": accesses[:100]}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: parse /var/log/syslog or kern.log for iptables LOG entries
    for log_path in ("/var/log/kern.log", "/var/log/syslog", "/var/log/messages"):
        if os.path.exists(log_path):
            try:
                result = subprocess.run(
                    ["sudo", "tail", "-n", "200", log_path],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if "iptables" in line.lower() or "netfilter" in line.lower():
                            src_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
                            dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", line)
                            dpt_match = re.search(r"DPT=(\d+)", line)
                            if src_match:
                                accesses.append({
                                    "ip": src_match.group(1),
                                    "destination": dst_match.group(1) if dst_match else "",
                                    "port": int(dpt_match.group(1)) if dpt_match else 0,
                                    "timestamp": _now_iso(),
                                    "source": "kernel_log",
                                })
                break
            except (subprocess.TimeoutExpired, OSError):
                continue

    return {"accesses": accesses[:100]}


@app.get("/iptables/rules")
async def iptables_rules():
    return get_iptables_rules_parsed()


@app.get("/events")
async def get_events():
    # Return most recent events first
    return {"events": list(reversed(_events))[:100]}


@app.get("/auto-response/blocked")
async def auto_response_blocked():
    """Return blocked IPs categorized by type."""
    blocked = list_blocked_ips()
    # Currently all blocks are permanent (manual or AEGIS-triggered)
    return {
        "blocked": blocked,
        "permanent": blocked,
        "temp": [],
        "count": len(blocked),
    }


@app.post("/ai/chat")
async def ai_chat(req: ChatRequest):
    return {
        "response": "AEGIS Firewall Agent does not support interactive chat. "
        "Use /analyze or /ai/investigate endpoints for IP analysis.",
        "status": "unsupported",
    }


# ---------------------------------------------------------------------------
# Additional utility endpoints
# ---------------------------------------------------------------------------


@app.get("/")
async def root():
    return {
        "service": "AEGIS Firewall Agent",
        "version": "1.0.1",
        "endpoints": [
            "/health", "/status", "/attackers", "/attacker/{ip}",
            "/blocked", "/block", "/analyze", "/ai/investigate",
            "/threat-summary", "/visitors/recent", "/iptables/rules",
            "/events", "/auto-response/blocked", "/ai/chat",
        ],
    }
