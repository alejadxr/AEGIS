"""
Real-time attack detection middleware for Cayde-6.

Intercepts every HTTP request BEFORE routing. Double URL-decodes paths,
query params, and POST bodies to catch encoded injection payloads.
Auto-blocks IPs after 10 attacks in 5 minutes.

OPTIMIZED v2: Mega-regex, fast-path skip, lazy body reading, blocked-IP-first,
frozenset scanner UA check, perf_counter instrumentation, pre-built responses,
module-level constants. Target: <30ms per detection.
"""
import asyncio
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("cayde6.attack_detector")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BLOCKED_IPS_FILE = Path.home() / "Cayde-6" / "backend" / "blocked_ips.txt"
BLOCK_THRESHOLD = 3          # attacks before auto-block
BLOCK_WINDOW    = 300         # seconds (5 min)
FIREWALL_URL    = os.getenv("AEGIS_FIREWALL_URL", "")

# Pre-built 403 response content (avoid re-creating per request)
_BLOCKED_BODY = b'{"detail":"blocked"}'
_BLOCKED_MEDIA = "application/json"

# IPs that must NEVER be blocked — configured via AEGIS_SAFE_IPS env var
_safe_ips_str = os.getenv("AEGIS_SAFE_IPS", "127.0.0.1,::1,localhost")
SAFE_IPS = frozenset(ip.strip() for ip in _safe_ips_str.split(",") if ip.strip())

# ---------------------------------------------------------------------------
# FAST-PATH: paths that skip ALL detection (internal/health endpoints)
# ---------------------------------------------------------------------------

SKIP_PATHS = frozenset({
    "/health",
    "/api/v1/nodes/heartbeat",
    "/api/v1/nodes/announce",
    "/api/v1/nodes/events",
})

# Module-level constants (avoid per-request allocation)
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH"})
_AUTH_PATHS = ("/auth/login", "/auth/user/login", "/auth/token")

# ---------------------------------------------------------------------------
# MEGA-REGEX: single compiled pattern with named groups for all attack types
# One re.search() instead of 6 separate calls.
# ---------------------------------------------------------------------------

MEGA_PATTERN = re.compile(
    # SQL Injection
    r"(?P<sql_injection>"
    r"union\s+(all\s+)?select"
    r"|or\s+1\s*=\s*1"
    r"|and\s+1\s*=\s*1"
    r"|'\s*or\s*'"
    r"|;\s*select\b"
    r"|;\s*drop\b"
    r"|;\s*insert\b"
    r"|;\s*update\b.*\bset\b"
    r"|;\s*delete\b"
    r"|information_schema"
    r"|sleep\s*\(\s*\d"
    r"|benchmark\s*\("
    r"|load_file\s*\("
    r"|into\s+outfile"
    r"|'\s*--"
    r"|'\s*#"
    r"|1'\s*or\s*'1'\s*=\s*'1"
    r"|admin'\s*--"
    r"|waitfor\s+delay"
    r"|extractvalue\s*\("
    r"|updatexml\s*\("
    r"|group_concat\s*\("
    r")"
    # XSS
    r"|(?P<xss>"
    r"<script[\s>]"
    r"|javascript\s*:"
    r"|onerror\s*="
    r"|onload\s*="
    r"|onmouseover\s*="
    r"|onfocus\s*="
    r"|<img\s+[^>]*src\s*=\s*['\"]?x"
    r"|<svg[\s/+]"
    r"|<iframe"
    r"|document\.cookie"
    r"|document\.write"
    r"|eval\s*\("
    r"|alert\s*\("
    r"|prompt\s*\("
    r"|confirm\s*\("
    r")"
    # Command Injection
    r"|(?P<command_injection>"
    r";\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b"
    r"|\|\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b"
    r"|&&\s*(?:id|whoami|cat|ls)\b"
    r"|`[^`]*`"
    r"|\$\([^)]*\)"
    r"|\bexec\s*\("
    r"|\bsystem\s*\("
    r"|\bpassthru\s*\("
    r"|\bpopen\s*\("
    r")"
    # Path Traversal
    r"|(?P<path_traversal>"
    r"\.\./|\.\.\\|"
    r"/etc/passwd"
    r"|/etc/shadow"
    r"|/proc/self"
    r"|/windows/system32"
    r"|/var/log"
    r"|\.htaccess"
    r"|\.htpasswd"
    r"|/web\.config"
    r"|wp-config\.php"
    r")"
    # Scanner/Recon signatures (in URL/path, not UA)
    r"|(?P<scanner>"
    r"nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz|nuclei|zgrab"
    r"|hydra|burpsuite|acunetix|nessus|openvas|arachni|w3af"
    r"|nmaplowercheck|/sdk|/evox|/HNAP1|/manager/html"
    r"|/solr/|/actuator|/wp-login|/xmlrpc\.php|/\.env"
    r"|/\.git/|/admin/config|/debug|/server-status|/server-info"
    r")"
    # SSRF indicators
    r"|(?P<ssrf>"
    r"http://169\.254\.169\.254"
    r"|http://metadata\.google"
    r"|http://100\.100\.100\.200"
    r"|http://localhost"
    r"|http://127\.0\.0\.1"
    r"|http://0\.0\.0\.0"
    r"|file:///"
    r")",
    re.IGNORECASE,
)

# Severity mapping for mega-regex named groups
_SEVERITY_MAP = {
    "sql_injection": "high",
    "xss": "medium",
    "command_injection": "critical",
    "path_traversal": "high",
    "scanner": "low",
    "ssrf": "high",
}

# ---------------------------------------------------------------------------
# SCANNER UA: frozenset substring check (no regex needed)
# ---------------------------------------------------------------------------

SCANNER_UAS = frozenset({
    "nmap", "nikto", "sqlmap", "masscan", "gobuster", "dirbuster",
    "wfuzz", "nuclei", "zgrab", "hydra", "burpsuite", "acunetix",
    "nessus", "openvas", "arachni", "python-requests", "go-http-client",
    "libcurl", "wget/", "httpie", "httrack", "scrapy",
    "morfeus", "zmeu", "w3af",
})

# Breadcrumb trap credentials (static indicators)
BREADCRUMB_INDICATORS = (
    "Tr4p_P4ssw0rd_2026",
    "AKIAIOSFODNN7BREADCRUMB",
    "sk-breadcrumb-trap-key",
    "sk_live_breadcrumb_trap",
    "breadcrumb-jwt-secret",
    "Tr4p_Adm1n_2026",
)

# Dynamic breadcrumb patterns from smart honeypots (regex)
import re as _re
BREADCRUMB_PATTERNS = (
    _re.compile(r"sk-breadcrumb-[0-9a-f]{8}"),
    _re.compile(r"sk_live_breadcrumb_[0-9a-f]{8}"),
    _re.compile(r"Pr0d_P4ss_[0-9a-f]{8}"),
    _re.compile(r"nextauth-[0-9a-f]{8}"),
    _re.compile(r"jwt-secret-[0-9a-f]{8}"),
    _re.compile(r"mail_[0-9a-f]{8}"),
    _re.compile(r"pusher-[0-9a-f]{8}"),
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

# Per-IP attack tracking: ip -> deque of (timestamp, pattern_name)
_attack_log: dict[str, deque] = defaultdict(deque)

# Blocked IPs (auto-blocked by this middleware)
_blocked_ips: set[str] = set()

# Stats
_stats = {
    "total_detections": 0,
    "total_blocks": 0,
    "detections_by_type": defaultdict(int),
    "last_detection_us": 0,      # last detection time in microseconds
    "avg_detection_us": 0.0,     # rolling average detection time
    "detection_samples": 0,      # number of samples for average
}


def _load_blocked_ips():
    """Load blocked IPs from file on startup."""
    try:
        if BLOCKED_IPS_FILE.exists():
            for line in BLOCKED_IPS_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    _blocked_ips.add(line)
            logger.info(f"[AttackDetector] Loaded {len(_blocked_ips)} blocked IPs from file")
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to load blocked IPs: {e}")


# Load on import
_load_blocked_ips()


def _double_decode(text: str) -> str:
    """Double URL-decode to catch %25xx and +-as-space encoding tricks.
    Fast-path: skip if no percent sign present."""
    if "%" not in text and "+" not in text:
        return text
    try:
        return unquote_plus(unquote_plus(text))
    except Exception:
        return text


def _check_mega(text: str) -> Optional[tuple[str, str]]:
    """Single mega-regex check. Returns (name, severity) or None."""
    m = MEGA_PATTERN.search(text)
    if m:
        group_name = m.lastgroup
        return (group_name, _SEVERITY_MAP.get(group_name, "medium"))
    return None


def _check_scanner_ua(user_agent: str) -> bool:
    """Fast scanner UA detection using frozenset substring matching."""
    ua_lower = user_agent.lower()
    return any(s in ua_lower for s in SCANNER_UAS)


def _blocked_response() -> Response:
    """Return a pre-formatted 403 response."""
    return Response(content=_BLOCKED_BODY, status_code=403, media_type=_BLOCKED_MEDIA)


async def _block_ip(ip: str, reason: str):
    """Block an IP: add to memory set, append to file, notify external firewall."""
    if ip in SAFE_IPS:
        logger.warning(f"[AttackDetector] Refusing to block safe IP {ip}")
        return

    _blocked_ips.add(ip)
    _stats["total_blocks"] += 1

    # Persist to file
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to write blocked IP to file: {e}")

    # Also update ip_blocker_service if available
    try:
        from app.core.ip_blocker import ip_blocker_service
        ip_blocker_service.block_ip(ip)
    except Exception:
        pass

    # Create incident in DB (fire-and-forget to avoid blocking the response)
    asyncio.ensure_future(_create_block_incident(ip, reason))

    # Notify external firewall (fire-and-forget)
    asyncio.ensure_future(_notify_firewall(ip, reason))

    logger.warning(f"[AttackDetector] AUTO-BLOCKED IP {ip} -- reason: {reason}")

    # Share to MongoDB (fire-and-forget)
    asyncio.ensure_future(_share_to_mongo(ip, reason))


async def _create_block_incident(ip: str, reason: str):
    """Create incident in DB. Runs as fire-and-forget task."""
    try:
        from app.database import async_session as _async_session
        from app.models.incident import Incident
        from app.models.client import Client
        from sqlalchemy import select

        async with _async_session() as db:
            result = await db.execute(select(Client).limit(1))
            client = result.scalar_one_or_none()
            if client:
                incident = Incident(
                    client_id=client.id,
                    title=f"CRITICAL: Auto-blocked IP {ip}",
                    description=(
                        f"IP {ip} was auto-blocked after exceeding "
                        f"{BLOCK_THRESHOLD} attacks in {BLOCK_WINDOW}s. "
                        f"Reason: {reason}"
                    ),
                    severity="critical",
                    status="open",
                    source="attack_detector",
                    source_ip=ip,
                    detected_at=datetime.utcnow(),
                )
                db.add(incident)
                await db.commit()
                logger.info(
                    f"[AttackDetector] Created CRITICAL incident for blocked IP {ip}"
                )
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to create incident: {e}")


async def _notify_firewall(ip: str, reason: str):
    """Notify external firewall to block IP. Runs as fire-and-forget task."""
    if not FIREWALL_URL:
        return
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{FIREWALL_URL}/block",
                json={
                    "ip": ip,
                    "reason": f"aegis_auto_block: {reason}",
                    "duration": 3600,
                },
                timeout=aiohttp.ClientTimeout(total=3),
            )
            logger.info(f"[AttackDetector] Firewall notified to block {ip}")
    except Exception as e:
        logger.debug(f"[AttackDetector] Firewall block failed (non-fatal): {e}")


async def _share_to_mongo(ip: str, reason: str):
    """Share blocked IP to MongoDB. Runs as fire-and-forget task."""
    try:
        from app.services.threat_intel_hub import threat_intel_hub
        await threat_intel_hub.share_ioc({
            "ioc_type": "ip",
            "ioc_value": ip,
            "threat_type": reason.split("(")[0].strip() if "(" in reason else reason,
            "confidence": 0.95,
            "detection_source": "attack_detector",
        })
        logger.info(f"[AttackDetector] Shared blocked IP {ip} to aegis_threats")
    except Exception as e:
        logger.debug(f"[AttackDetector] MongoDB share failed (non-fatal): {e}")


def _record_attack(ip: str, pattern_name: str) -> bool:
    """Record an attack. Returns True if IP should be blocked."""
    now = time.time()
    cutoff = now - BLOCK_WINDOW
    q = _attack_log[ip]
    # Prune old entries
    while q and q[0][0] < cutoff:
        q.popleft()
    q.append((now, pattern_name))

    _stats["total_detections"] += 1
    _stats["detections_by_type"][pattern_name] += 1

    return len(q) >= BLOCK_THRESHOLD


def _record_timing(elapsed_ns: int):
    """Record detection timing in microseconds for stats."""
    us = elapsed_ns // 1000
    _stats["last_detection_us"] = us
    n = _stats["detection_samples"]
    if n == 0:
        _stats["avg_detection_us"] = float(us)
    else:
        # Exponential moving average (alpha=0.1) to avoid unbounded memory
        _stats["avg_detection_us"] = _stats["avg_detection_us"] * 0.9 + us * 0.1
    _stats["detection_samples"] = n + 1


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AttackDetectorMiddleware(BaseHTTPMiddleware):
    """Real-time attack detection middleware.

    Runs BEFORE every request. Optimized hot path:
    1. Blocked IP check (instant O(1) set lookup)
    2. Fast-path skip for health/internal endpoints
    3. Safe IP skip
    4. Mega-regex on path+query only (lazy body read)
    5. Body read only if path+query clean and method is POST/PUT/PATCH
    6. Fire-and-forget for DB/firewall/Mongo on block (non-blocking)
    """

    async def dispatch(self, request: Request, call_next):
        t0 = time.perf_counter_ns()

        # ---- OPTIMIZATION 4: Blocked IP as ABSOLUTE FIRST check ----
        ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip = forwarded.split(",", 1)[0].strip()

        if ip in _blocked_ips:
            return _blocked_response()

        # ---- OPTIMIZATION 2: Fast-path skip for safe endpoints ----
        path = request.url.path
        if path in SKIP_PATHS:
            return await call_next(request)

        # Skip safe IPs entirely
        if ip in SAFE_IPS:
            return await call_next(request)

        # ---- OPTIMIZATION 5: Scanner UA via frozenset (no regex) ----
        user_agent = request.headers.get("user-agent", "")
        if user_agent and _check_scanner_ua(user_agent):
            should_block = _record_attack(ip, "scanner")
            logger.warning(
                f"[DETECT] scanner UA from {ip}: {user_agent[:80]}"
            )
            if should_block:
                await _block_ip(ip, f"scanner User-Agent: {user_agent[:60]}")
            _record_timing(time.perf_counter_ns() - t0)
            if should_block:
                return _blocked_response()

        # ---- Brute force detection: rapid POST to auth endpoints ----
        method = request.method
        if method == "POST" and any(p in path for p in _AUTH_PATHS):
            now_ts = time.time()
            bf_key = f"bf:{ip}"
            bf_q = _attack_log.get(bf_key)
            if bf_q is None:
                bf_q = deque()
                _attack_log[bf_key] = bf_q
            cutoff = now_ts - 60  # 1 minute window
            while bf_q and bf_q[0][0] < cutoff:
                bf_q.popleft()
            bf_q.append((now_ts, "brute_force"))
            if len(bf_q) >= 5:  # 5 auth attempts in 1 min = brute force
                should_block = _record_attack(ip, "brute_force")
                logger.warning(
                    f"[DETECT] HIGH brute_force from {ip} "
                    f"path={path} attempts={len(bf_q)}"
                )
                if should_block:
                    await _block_ip(ip, f"brute_force ({len(bf_q)} attempts)")
                    _record_timing(time.perf_counter_ns() - t0)
                    return _blocked_response()

        # ---- Build check text: path + query (decoded) + UA ----
        decoded_path = _double_decode(path)
        raw_query = request.url.query
        decoded_query = _double_decode(raw_query) if raw_query else ""
        check_text = f"{decoded_path} {decoded_query} {user_agent}"

        # ---- Breadcrumb credential detection (static + dynamic) ----
        _breadcrumb_hit = False
        for crumb in BREADCRUMB_INDICATORS:
            if crumb in check_text:
                _breadcrumb_hit = True
                break
        if not _breadcrumb_hit:
            for pat in BREADCRUMB_PATTERNS:
                if pat.search(check_text):
                    _breadcrumb_hit = True
                    break
        if _breadcrumb_hit:
            should_block = _record_attack(ip, "breadcrumb_credential_used")
            logger.critical(
                f"[DETECT] BREADCRUMB credential used by {ip} "
                f"path={path} method={method}"
            )
            if should_block:
                await _block_ip(ip, "breadcrumb_credential_used (critical)")
                _record_timing(time.perf_counter_ns() - t0)
                return _blocked_response()

        # ---- OPTIMIZATION 1+3: Mega-regex with lazy body reading ----
        match_result = _check_mega(check_text)

        # Only read body if path+query was clean AND method is mutation
        if not match_result and method in _MUTATION_METHODS:
            try:
                body_bytes = await request.body()
                if body_bytes and len(body_bytes) < 65536:  # max 64KB
                    body_text = _double_decode(
                        body_bytes.decode("utf-8", errors="ignore")
                    )
                    # Check breadcrumbs in body too (static + dynamic)
                    _body_crumb = False
                    for crumb in BREADCRUMB_INDICATORS:
                        if crumb in body_text:
                            _body_crumb = True
                            break
                    if not _body_crumb:
                        for pat in BREADCRUMB_PATTERNS:
                            if pat.search(body_text):
                                _body_crumb = True
                                break
                    if _body_crumb:
                        should_block = _record_attack(ip, "breadcrumb_credential_used")
                        logger.critical(
                            f"[DETECT] BREADCRUMB credential in body from {ip} "
                            f"path={path} method={method}"
                        )
                        if should_block:
                            await _block_ip(ip, "breadcrumb_credential_used (critical)")
                            _record_timing(time.perf_counter_ns() - t0)
                            return _blocked_response()
                    # Mega-regex on body
                    match_result = _check_mega(body_text)
            except Exception:
                pass

        if match_result:
            name, severity = match_result
            should_block = _record_attack(ip, name)

            logger.warning(
                f"[DETECT] {severity.upper()} {name} from {ip} "
                f"path={path} method={method}"
            )

            if should_block:
                await _block_ip(ip, f"{name} ({severity})")
                _record_timing(time.perf_counter_ns() - t0)
                return _blocked_response()

        # ---- Configurable firewall rule engine (augments hardcoded checks) ----
        # Uses the sync cache-only path so the detector stays fast. The cache
        # is primed asynchronously by the firewall_engine loader on first hit
        # or via CRUD invalidation.
        try:
            from app.services.firewall_engine import firewall_engine as _fw

            event = {
                "source_ip": ip,
                "path": path,
                "method": method,
                "user_agent": user_agent,
                "protocol": "http",
                "port": request.url.port or 0,
                "event_type": "http_request",
            }
            fw_matches = _fw.evaluate_all_sync(event)
            if fw_matches:
                # Highest priority match wins
                top = fw_matches[0]
                if top.action == "allow":
                    _record_timing(time.perf_counter_ns() - t0)
                    return await call_next(request)
                if top.action in ("block_ip", "quarantine_host"):
                    _record_attack(ip, f"fw_rule:{top.rule_name}")
                    await _block_ip(ip, f"firewall_rule:{top.rule_name}")
                    _record_timing(time.perf_counter_ns() - t0)
                    return _blocked_response()
                if top.action == "alert":
                    logger.warning(
                        f"[FW-RULE] {top.rule_name} alert from {ip} path={path}"
                    )
        except Exception as exc:
            # Never fail the request because of rule engine errors
            logger.debug(f"[AttackDetector] firewall_engine skipped: {exc}")

        # Record timing for clean requests too
        _record_timing(time.perf_counter_ns() - t0)

        # Continue to next middleware / route handler
        return await call_next(request)


# ---------------------------------------------------------------------------
# Public API for admin endpoints
# ---------------------------------------------------------------------------

def get_blocked_ips() -> list[str]:
    """Return sorted list of all blocked IPs."""
    return sorted(_blocked_ips)


def unblock_ip(ip: str) -> bool:
    """Remove an IP from the blocked set. Returns True if it was blocked."""
    was_blocked = ip in _blocked_ips
    _blocked_ips.discard(ip)
    # Also remove from ip_blocker_service
    try:
        from app.core.ip_blocker import ip_blocker_service
        ip_blocker_service.unblock_ip(ip)
    except Exception:
        pass
    # Rewrite file without this IP
    try:
        if BLOCKED_IPS_FILE.exists():
            lines = BLOCKED_IPS_FILE.read_text().splitlines()
            filtered = [l for l in lines if l.strip() != ip]
            BLOCKED_IPS_FILE.write_text("\n".join(filtered) + "\n")
    except Exception:
        pass
    return was_blocked


def get_stats() -> dict:
    """Return detection statistics including timing."""
    return {
        "total_detections": _stats["total_detections"],
        "total_blocks": _stats["total_blocks"],
        "blocked_ips_count": len(_blocked_ips),
        "detections_by_type": dict(_stats["detections_by_type"]),
        "last_detection_us": _stats["last_detection_us"],
        "avg_detection_us": round(_stats["avg_detection_us"], 1),
        "detection_samples": _stats["detection_samples"],
    }
