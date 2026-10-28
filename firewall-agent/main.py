"""
AEGIS Firewall Agent v1.0.0
Single-file FastAPI service that manages iptables on the Raspberry Pi.
Designed to be the firewall backend for AEGIS (Mac Pro).

Port: 8765
Persistence: /etc/aegis/blocked_ips.json
Requires: sudo access to /usr/sbin/iptables (via sudoers.d/aegis-iptables)

Deployment note (BUG-3 fix, 2026-05-31):
    Set AEGIS_SAFE_IPS env var on the Pi systemd unit
    (/etc/systemd/system/aegis-firewall.service) so the Pi rejects block
    requests for safe CIDRs (Googlebot 66.249.0.0/16, Starlink 74.244.193.0/24,
    etc.) even if AEGIS forwards them incorrectly. Example:

        Environment="AEGIS_SAFE_IPS=66.249.0.0/16,74.244.193.0/24,127.0.0.1"

    Then: sudo systemctl daemon-reload && sudo systemctl restart aegis-firewall
    Not deployed automatically — apply manually on Pi when ready.
"""

import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BLOCKED_IPS_FILE = Path("/etc/aegis/blocked_ips.json")
EVENTS_MAX = 500  # Max events kept in memory
ATTACKERS_MAX = 1000  # Max tracked attackers

# AEGIS-FP-FIX 20261019: minimum sightings before an UNCLASSIFIED hit may block.
# A single unclassified request used to be enough to block an IP at HIGH, which
# is how 10 real visitors (2 residential ISP clients, 4 proxy.flipboard.com,
# Cloudflare WARP, 3 more residentials) ended up blocked with attack_types:[]
# and total_attempts:1. An exploit signature still blocks on the first hit.
# Set AEGIS_BLOCK_MIN_ATTEMPTS=1 to restore the pre-2026-10-19 behaviour.
BLOCK_MIN_ATTEMPTS = max(1, int(os.getenv("AEGIS_BLOCK_MIN_ATTEMPTS", "2")))
IPTABLES = "/usr/sbin/iptables"
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

# Shared secret for the Mac Pro <-> Pi firewall channel (B5 / P0-12). See the
# _enforce_shared_secret middleware below for the optional-accept/enforce
# rollout behavior.
AEGIS_FIREWALL_SECRET = os.getenv("AEGIS_FIREWALL_SECRET", "").strip()

# Extra safe IPs from AEGIS_SAFE_IPS env var (comma-separated). Accepts both
# literal IPs (auto-wrapped as /32 or /128) and CIDR ranges (e.g.
# "66.249.0.0/16,74.244.193.0/24,127.0.0.1"). Mirrors the parser used by
# backend/app/core/attack_detector.py so the Pi agent refuses to block any
# CIDR AEGIS itself considers safe even if AEGIS forwards the request.
_EXTRA_SAFE_IPS: set[str] = set()
_safe_ips_env = os.getenv("AEGIS_SAFE_IPS", "")
# Shared general-purpose cloud space (GCP / Azure customer VMs). Never
# unconditionally safe: crawlers there are handled by _verify_crawler (published
# feeds + FCrDNS), and only for behavioural threats. A broad AEGIS_SAFE_IPS
# entry overlapping these would blind the agent to attackers renting a VM.
_SHARED_CLOUD_NETS = [
    ipaddress.ip_network(c) for c in ("34.64.0.0/10", "35.190.0.0/17", "13.66.0.0/17")
]
_SHARED_CLOUD_MAX_SAFE_PREFIX = 24  # operator may pin a /24 or narrower


def _overlaps_shared_cloud_too_broadly(net) -> bool:
    return net.prefixlen < _SHARED_CLOUD_MAX_SAFE_PREFIX and any(
        net.version == c.version and net.overlaps(c) for c in _SHARED_CLOUD_NETS
    )


for _entry in (e.strip() for e in _safe_ips_env.split(",") if e.strip()):
    try:
        if _overlaps_shared_cloud_too_broadly(ipaddress.ip_network(_entry, strict=False)):
            print(f"[aegis-firewall] AEGIS_SAFE_IPS: ignoring {_entry!r}: broad shared "
                  f"cloud range (use /{_SHARED_CLOUD_MAX_SAFE_PREFIX} or narrower; "
                  "crawlers there are verified via feeds/FCrDNS instead)")
            continue
        if "/" in _entry:
            _SAFE_NETWORKS.append(ipaddress.ip_network(_entry, strict=False))
        else:
            # Treat literal IPs as both an exact match and a /32 (or /128) net
            _EXTRA_SAFE_IPS.add(_entry)
            _SAFE_NETWORKS.append(
                ipaddress.ip_network(_entry, strict=False)
            )
    except (ValueError, TypeError):
        # Logger is configured below; defer warning to module-init via print
        print(f"[aegis-firewall] AEGIS_SAFE_IPS: ignoring invalid entry {_entry!r}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis-firewall")

# ---------------------------------------------------------------------------
# Verified-crawler whitelist  (added 2026-08-03 — see incident note)
# ---------------------------------------------------------------------------
#
# INCIDENT 2026-08-03 — why this exists, do NOT revert on intuition:
#   AEGIS had 40.77.167.63 and 52.167.144.233 in the AEGIS_BLOCK chain. Reverse
#   DNS identified both as msnbot-*.search.msn.com — Bing's crawler. Because
#   Sable's middleware.ts turns this blocklist into an app-layer 403 on the real
#   client IP (CF-Connecting-IP), Bing could not crawl sable at all. Bing feeds
#   ChatGPT's index and part of Perplexity's, and Perplexity told Diego straight
#   out that it COULD NOT SEE the site. Meanwhile Sable's robots.txt explicitly
#   Allows GPTBot, ClaudeBot, Google-Extended, PerplexityBot and Bytespider.
#   The two systems contradicted each other and the middleware won, silently.
#
#   Root cause is structural, not a one-off: AEGIS blocks on BEHAVIOUR (many
#   paths, high request rate) and a legitimate crawler is behaviourally
#   indistinguishable from reconnaissance. Unblocking by hand does not fix it —
#   the AEGIS brain just re-pushes the same IP. So the refusal has to live here,
#   at the only choke point every block passes through: POST /block on the Pi.
#
# DESIGN
#   1. Two independent verification methods, because neither alone is enough:
#        - Published CIDR ranges, refreshed from the vendors' own JSON feeds
#          (Google, Bing, OpenAI, Perplexity all publish machine-readable
#          prefix lists). Required for OpenAI and Perplexity: measured
#          2026-08-03, Perplexity's own published IP 3.224.62.45 reverse-
#          resolves to ec2-3-224-62-45.compute-1.amazonaws.com, so FCrDNS can
#          never identify it.
#        - FCrDNS (PTR + forward-confirm) against a small suffix allowlist.
#          Required for Bing/Google IPs that are not yet in a refreshed feed —
#          exactly the failure mode that caused this incident.
#   2. The exemption is CONDITIONAL on the reported threat class. A verified
#      crawler is exempted from behavioural blocks only. If the caller reports
#      an exploit signature (sql_injection, path_traversal, command_injection,
#      xss, ssrf, brute_force_401, ...) the block proceeds regardless of how
#      well the IP verifies. This is why the whitelist lives here and NOT in
#      AEGIS_SAFE_IPS: AEGIS_SAFE_IPS is unconditional and would also exempt
#      real exploitation from crawler-hosting infrastructure.
#   3. Fail-closed on VERIFICATION, fail-open on AVAILABILITY: if DNS times out
#      or a vendor feed is unreachable we do NOT invent an exemption (the block
#      proceeds, i.e. today's behaviour), and we never discard a previously
#      loaded range set.
#
# SECURITY CONCESSION WE ARE KNOWINGLY ACCEPTING (documented, not hidden):
#   An attacker who controls a host inside a published crawler range, or who
#   controls PTR for an IP under one of the suffixes below AND has that PTR
#   forward-resolve back to the same IP, can avoid the AEGIS app-layer 403 for
#   *behavioural* detections only. They still face: Cloudflare upstream, the
#   Pi's DoS netshield, app authentication, and any exploit-signature block
#   (point 2). Scope of the hole is "high-volume crawling from Microsoft/
#   Google/OpenAI/Perplexity address space is not rate-blocked" — which is
#   precisely the behaviour we intend to allow.
#
# NOT COVERED, on purpose:
#   - Bytespider (ByteDance): publishes no reliable prefix feed and no
#     verifiable PTR. robots.txt allows it; AEGIS may still block it.
#   - ClaudeBot (Anthropic): probed 2026-08-03, no machine-readable prefix
#     feed found at anthropic.com / docs.claude.com. Covered only if it ever
#     presents a forward-confirmed PTR under a suffix below.
#   Add either via AEGIS_CRAWLER_NETS the day a feed exists.

# Vendor-published prefix feeds. All verified reachable and JSON-parsing on
# 2026-08-03 from the Pi. Shape: {"prefixes":[{"ipv4Prefix"|"ipv6Prefix": ...}]}
CRAWLER_RANGE_SOURCES: dict[str, str] = {
    "googlebot": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "google-special": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
    "gptbot": "https://openai.com/gptbot.json",
    "oai-searchbot": "https://openai.com/searchbot.json",
    "chatgpt-user": "https://openai.com/chatgpt-user.json",
    "perplexitybot": "https://www.perplexity.ai/perplexitybot.json",
    "perplexity-user": "https://www.perplexity.ai/perplexity-user.json",
}

# How often the feeds are re-fetched. Off the request path entirely — this runs
# in a background task, never inside POST /block.
CRAWLER_REFRESH_SECONDS = int(os.getenv("AEGIS_CRAWLER_REFRESH_SECONDS", "21600"))  # 6h

# PTR suffixes accepted for FCrDNS. Deliberately narrow: only hostnames a
# vendor uses exclusively for crawlers. NOTE the absence of amazonaws.com,
# googleusercontent.com, azure*.net and similar shared-tenant domains — any
# customer can obtain a PTR there, so they prove nothing.
_CRAWLER_PTR_SUFFIXES: dict[str, str] = {
    ".search.msn.com": "bingbot",     # msnbot-40-77-167-63.search.msn.com  <- the incident
    ".googlebot.com": "googlebot",    # crawl-66-249-66-1.googlebot.com
    ".google.com": "google-special",  # google-proxy-* / rate-limited-proxy-*
}

CRAWLER_DNS_TIMEOUT_S = float(os.getenv("AEGIS_CRAWLER_DNS_TIMEOUT", "2.5"))

# Threat classes that must NEVER be exempted, however well the IP verifies.
# Matched as substrings against reason/pattern_name/threat_type, because the
# AEGIS brain sends free-form strings like "aegis_auto_block: sql_injection (3x)".
_EXPLOIT_TOKENS = frozenset({
    "sql_injection", "sqli", "xss", "command_injection", "rce",
    "path_traversal", "lfi", "rfi", "ssrf", "xxe", "deserialization",
    "brute_force", "credential_stuffing", "log4j", "shellshock",
    "webshell", "malware", "exploit", "cve-",
})

# Threat classes that ARE eligible for the exemption — purely behavioural /
# volumetric signals, i.e. "this looks like a crawler because it IS crawling".
_BEHAVIOURAL_TOKENS = frozenset({
    "high_request_rate", "rate_limit", "port_scan", "scanner",
    "recon", "enumeration", "crawl", "bot", "user_agent", "404",
})

# Enable auto-reconcile of ALREADY-persisted blocks at startup/refresh.
# OFF by default: unblocking en masse without an operator asking is surprising.
# Turn on with AEGIS_CRAWLER_AUTO_UNBLOCK=1 once the whitelist has been observed.
CRAWLER_AUTO_UNBLOCK = os.getenv("AEGIS_CRAWLER_AUTO_UNBLOCK", "").strip().lower() in ("1", "true", "yes", "on")

# Live state: list of (network, vendor). Seeded from AEGIS_CRAWLER_NETS so an
# operator can pin a range without waiting for a feed (e.g. a future ClaudeBot).
_crawler_nets: list[tuple] = []       # [(ip_network, vendor), ...]
_crawler_seed_nets: list[tuple] = []  # operator pins from AEGIS_CRAWLER_NETS
_crawler_last_refresh: float = 0.0
_crawler_last_error: str = ""

for _entry in (e.strip() for e in os.getenv("AEGIS_CRAWLER_NETS", "").split(",") if e.strip()):
    try:
        _crawler_seed_nets.append((ipaddress.ip_network(_entry, strict=False), "env"))
    except (ValueError, TypeError):
        print(f"[aegis-firewall] AEGIS_CRAWLER_NETS: ignoring invalid entry {_entry!r}")
_crawler_nets = list(_crawler_seed_nets)


def _crawler_cidr_match(ip: str) -> Optional[str]:
    """Return the vendor name if `ip` falls in a published crawler prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, vendor in _crawler_nets:
        if addr.version == net.version and addr in net:
            return vendor
    return None


def _fcrdns_vendor_blocking(ip: str) -> Optional[str]:
    """Forward-confirmed reverse DNS. Blocking; always call via to_thread.

    PTR must end in an allowlisted suffix AND the forward lookup of that
    hostname must resolve back to the same IP. Any failure returns None
    (fail-closed: no exemption), never an exemption.
    """
    try:
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except Exception:
        return None
    vendor = None
    for suffix, name in _CRAWLER_PTR_SUFFIXES.items():
        if host.endswith(suffix):
            vendor = name
            break
    if vendor is None:
        return None
    try:
        forward = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except Exception:
        return None
    return vendor if ip in forward else None


async def _fcrdns_vendor(ip: str) -> Optional[str]:
    """Async wrapper with a hard timeout so /block can never hang on DNS."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_fcrdns_vendor_blocking, ip),
            timeout=CRAWLER_DNS_TIMEOUT_S,
        )
    except Exception:
        return None  # timeout / resolver failure => no exemption


def _threat_text(*parts: Optional[str]) -> str:
    return " ".join(p for p in parts if p).lower()


def _is_exploit_signal(text: str) -> bool:
    """True if the caller reported a real exploitation attempt.

    Conservative by construction: any exploit token anywhere in the reported
    reason/pattern/threat_type disables the crawler exemption.
    """
    return any(tok in text for tok in _EXPLOIT_TOKENS)


async def _verify_crawler(ip: str, threat_text: str) -> Optional[str]:
    """Return vendor name if `ip` is a verified crawler eligible for exemption.

    Order matters: the CIDR check is free (integer comparisons, no network) and
    covers OpenAI/Perplexity which FCrDNS provably cannot. FCrDNS only runs when
    the CIDR check misses, and only at block time — never per site request.
    """
    if _is_exploit_signal(threat_text):
        return None
    vendor = _crawler_cidr_match(ip)
    if vendor:
        return vendor
    return await _fcrdns_vendor(ip)


async def _fetch_crawler_ranges() -> tuple[list[tuple], list[str]]:
    """Fetch every vendor feed. Returns (nets, errors). Never raises."""
    nets: list[tuple] = []
    errors: list[str] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for vendor, url in CRAWLER_RANGE_SOURCES.items():
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
                count = 0
                for prefix in data.get("prefixes", []):
                    cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
                    if not cidr:
                        continue
                    try:
                        nets.append((ipaddress.ip_network(cidr, strict=False), vendor))
                        count += 1
                    except (ValueError, TypeError):
                        continue
                if count == 0:
                    errors.append(f"{vendor}: feed parsed but contained 0 prefixes")
            except Exception as e:
                errors.append(f"{vendor}: {e}")
    return nets, errors


async def _refresh_crawler_ranges() -> dict:
    """Refresh _crawler_nets from the vendor feeds.

    Fail-open on availability: a failed/empty fetch KEEPS the previous set. We
    never shrink the whitelist because a vendor's CDN had a bad minute — that
    would silently re-create the 2026-08-03 incident.
    """
    global _crawler_nets, _crawler_last_refresh, _crawler_last_error
    nets, errors = await _fetch_crawler_ranges()
    _crawler_last_error = "; ".join(errors)
    if nets:
        _crawler_nets = _crawler_seed_nets + nets
        _crawler_last_refresh = time.time()
        logger.info(
            "Crawler whitelist refreshed: %d networks from %d feeds%s",
            len(_crawler_nets), len(CRAWLER_RANGE_SOURCES),
            f" ({len(errors)} feed errors)" if errors else "",
        )
    else:
        logger.warning(
            "Crawler whitelist refresh produced no networks, KEEPING previous set "
            "(%d networks). Errors: %s", len(_crawler_nets), _crawler_last_error,
        )
    return {
        "networks": len(_crawler_nets),
        "errors": errors,
        "last_refresh": _crawler_last_refresh,
    }


async def _reconcile_blocked_crawlers(dry_run: bool = True) -> dict:
    """Find verified crawlers already sitting in the AEGIS_BLOCK chain.

    Needed because POST /block only guards NEW blocks; the 2026-08-03 Bing IPs
    were already persisted in /etc/aegis/blocked_ips.json and got re-applied on
    every restart. dry_run=True only reports.
    """
    found = []
    for ip in list_blocked_ips():
        vendor = _crawler_cidr_match(ip) or await _fcrdns_vendor(ip)
        if vendor:
            found.append({"ip": ip, "vendor": vendor})
    unblocked = []
    if not dry_run:
        for item in found:
            try:
                unblock_ip(item["ip"])
                if item["ip"] in _attackers:
                    _attackers[item["ip"]]["blocked"] = False
                unblocked.append(item["ip"])
                _add_event(
                    "crawler_unblocked", ip=item["ip"],
                    details=f"Unblocked verified crawler {item['ip']} ({item['vendor']}) "
                            f"— crawler whitelist reconcile (incident 2026-08-03)",
                    severity="info",
                )
            except Exception as e:
                logger.error("Crawler reconcile failed to unblock %s: %s", item["ip"], e)
        if unblocked:
            _save_blocked_ips(list_blocked_ips())
    return {"verified_crawlers_in_blocklist": found, "unblocked": unblocked, "dry_run": dry_run}


async def _crawler_refresh_loop():
    """Background refresher. Never touches the request path."""
    while True:
        try:
            await _refresh_crawler_ranges()
            if CRAWLER_AUTO_UNBLOCK:
                result = await _reconcile_blocked_crawlers(dry_run=False)
                if result["unblocked"]:
                    logger.warning("Crawler auto-unblock released: %s", result["unblocked"])
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Crawler refresh loop error (non-fatal): %s", e)
        await asyncio.sleep(CRAWLER_REFRESH_SECONDS)


# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_start_time: float = 0.0

# Tracked attackers: ip -> {first_seen, last_seen, threat_level, attack_types, stats, intel, blocked}
_attackers: dict[str, dict] = {}

# Recent events: list of dicts
_events: list[dict] = []

# ---------------------------------------------------------------------------
# Durable events log (disk persistence)
# ---------------------------------------------------------------------------
#
# _events above is in-memory only and capped at EVENTS_MAX: every restart of
# aegis-firewall.service wipes it, and past 500 entries the oldest silently
# fall off. That is exactly the labelled "why was this IP blocked" data an ML
# training corpus needs, discarded for free. We additionally append every
# event to an uncapped JSONL file on disk so nothing is ever lost, while
# leaving _events/EVENTS_MAX untouched — /events still reads memory by
# default so it stays fast.


def _resolve_events_log_path() -> Path:
    """Pick a writable location for the events JSONL log.

    Defaults to /var/lib/aegis/events.jsonl (or AEGIS_EVENTS_LOG if set);
    falls back to ~/.aegis/events.jsonl when that directory can't be
    created/written (e.g. running the agent outside systemd/root during
    local dev, where /var/lib/aegis is typically not writable).
    """
    configured = os.getenv("AEGIS_EVENTS_LOG", "").strip()
    candidates = [Path(configured) if configured else Path("/var/lib/aegis/events.jsonl")]
    candidates.append(Path.home() / ".aegis" / "events.jsonl")
    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            if os.access(candidate.parent, os.W_OK):
                return candidate
        except OSError:
            continue
    # Nothing writable — return the last candidate anyway; every write will
    # just hit the except branch in _append_event_jsonl and log a warning.
    return candidates[-1]


EVENTS_LOG_PATH = _resolve_events_log_path()


def _append_event_jsonl(event: dict) -> None:
    """Best-effort durable append of one event to EVENTS_LOG_PATH.

    MUST NEVER raise: blocking IPs is this service's actual job, and a full
    disk / permissions / rotation race must never break that. We open in
    append mode per call rather than holding a long-lived handle, so
    logrotate can rename/truncate the file underneath us safely.
    """
    try:
        # default=str so a datetime (or any other non-JSON type that finds its
        # way into an event) serialises instead of raising. Catching only
        # OSError would let a TypeError from json.dumps escape and take the
        # block path down with it — the exact outcome this function exists to
        # prevent.
        line = json.dumps(event, separators=(",", ":"), default=str)
        EVENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(EVENTS_LOG_PATH, "a") as f:
            f.write(line + "\n")
            f.flush()
    except Exception as e:  # noqa: BLE001 - must never propagate, see docstring
        logger.warning(f"Failed to persist event to {EVENTS_LOG_PATH}: {e}")

# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------


def _is_safe_ip(ip: str) -> bool:
    """Return True if the IP should never be blocked.

    We check explicitly against our _SAFE_NETWORKS list instead of using
    addr.is_private, because Python 3.11+ treats RFC 5737 documentation
    ranges (e.g. 203.0.113.0/24) as private, which would prevent us from
    blocking legitimate test/attacker IPs in those ranges.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # Invalid = don't block
    if ip in _EXTRA_SAFE_IPS:
        return True
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
    """Check if IP already has a DROP rule in INPUT chain."""
    result = _run_iptables("-L", "INPUT", "-n", check=False)
    for line in result.stdout.splitlines():
        if "DROP" in line and ip in line:
            return True
    return False


def block_ip(ip: str) -> bool:
    """Add DROP rules for an IP in INPUT and FORWARD chains."""
    if _ip_is_blocked(ip):
        logger.info(f"IP {ip} already blocked, skipping iptables insert")
        return True
    try:
        _run_iptables("-I", "INPUT", "-s", ip, "-j", "DROP")
        _run_iptables("-I", "FORWARD", "-s", ip, "-j", "DROP")
        logger.info(f"Blocked IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block {ip}: {e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout blocking {ip}")
        return False


def unblock_ip(ip: str) -> bool:
    """Remove all DROP rules for an IP from INPUT and FORWARD chains."""
    removed = False
    # Remove all matching rules (there might be duplicates)
    for chain in ("INPUT", "FORWARD"):
        while True:
            result = _run_iptables("-D", chain, "-s", ip, "-j", "DROP", check=False)
            if result.returncode != 0:
                break
            removed = True
    if removed:
        logger.info(f"Unblocked IP: {ip}")
    else:
        logger.info(f"IP {ip} was not blocked in iptables")
    return True


def list_blocked_ips() -> list[str]:
    """Parse iptables INPUT chain for DROP rules and return source IPs."""
    result = _run_iptables("-L", "INPUT", "-n", check=False)
    blocked = []
    for line in result.stdout.splitlines():
        if "DROP" in line:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3]
                # Validate it looks like an IP
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
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
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
# Block expiry
# ---------------------------------------------------------------------------

# Callers send `duration` (seconds) for temporary blocks (attack_detector: 1h,
# aegis_honeypot: 24h). The field used to be parsed and ignored, so every
# "temporary" block was permanent. ip -> epoch seconds; an IP with no entry is a
# permanent block. Persisted in records[ip]["expires_at"] so a restart neither
# resurrects expired blocks nor forgets live ones.
MAX_BLOCK_DURATION = 30 * 24 * 3600
EXPIRY_SWEEP_INTERVAL = 30
_block_expiry: dict[str, float] = {}


def _now_ts() -> float:
    return time.time()


def _is_expired(ip: str) -> bool:
    exp = _block_expiry.get(ip)
    return exp is not None and exp <= _now_ts()


def _release_block(ip: str) -> bool:
    """Remove the iptables rule and forget the block. Single path shared by
    DELETE /block/{ip} and the expiry sweep so rule and record cannot diverge.

    unblock_ip() reports success even when `iptables -D` failed (check=False),
    so verify the rule is really gone. On failure nothing is forgotten: the
    record stays and the caller decides whether to retry.
    """
    unblock_ip(ip)
    try:
        still_blocked = _ip_is_blocked(ip)
    except (subprocess.SubprocessError, OSError) as e:
        logger.error(f"Could not verify unblock of {ip}: {e}")
        return False
    if still_blocked:
        logger.error(f"Unblock of {ip} failed: DROP rule still present, keeping record")
        return False
    _block_expiry.pop(ip, None)
    if ip in _attackers:
        _attackers[ip]["blocked"] = False
    _save_blocked_ips(list_blocked_ips())
    return True


def expire_blocks() -> list[str]:
    """Release every block whose expiry has passed. Returns the IPs released."""
    released = []
    for ip in [i for i in list(_block_expiry) if _is_expired(i)]:
        reason = ((_attackers.get(ip) or {}).get("intel") or {}).get("reason")
        try:
            ok = _release_block(ip)
        except Exception as e:
            logger.error(f"Expiry release of {ip} raised: {e}")
            continue
        if not ok:
            continue  # record kept; retried on the next sweep
        logger.info(f"Block expired, released {ip} (reason: {reason or 'not reported'})")
        _add_event("ip_block_expired", ip=ip,
                   details=f"Block expired for {ip}: {reason or 'reason not reported'}",
                   severity="info")
        released.append(ip)
    return released


async def _expiry_sweep_loop():
    while True:
        await asyncio.sleep(EXPIRY_SWEEP_INTERVAL)
        try:
            expire_blocks()
        except Exception as e:
            logger.warning(f"Expiry sweep failed: {e}")


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


def _load_blocked_records() -> dict:
    """AEGIS-FP-FIX 20261019: per-IP block metadata saved next to `blocked`.

    Returns {} for a pre-fix file, which makes the caller fall back to the old
    HIGH/[] default -- but it now says so explicitly in intel.reason instead of
    silently looking like a confirmed high-threat attacker.
    """
    if not BLOCKED_IPS_FILE.exists():
        return {}
    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text())
        recs = data.get("records") if isinstance(data, dict) else None
        return recs if isinstance(recs, dict) else {}
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load blocked records from {BLOCKED_IPS_FILE}: {e}")
        return {}


def _save_blocked_ips(ips: list[str]):
    """Save blocked IPs to persistent file."""
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # AEGIS-FP-FIX 20261019: persist WHY each IP is blocked. Until today only
        # the bare IP list was saved, so every restart rebuilt /attackers as
        # HIGH/attack_types:[] and the original reason was lost for good — which
        # is exactly why 120 blocks could not be audited after the 2026-10-17
        # restart. `records` is purely additive: _load_blocked_ips still reads
        # `blocked`, so an older file (or an older build) keeps working.
        records = {}
        for _ip in ips:
            _a = _attackers.get(_ip)
            if not _a:
                # No classification, but the expiry must still survive a restart.
                if _ip in _block_expiry:
                    records[_ip] = {"expires_at": _block_expiry[_ip]}
                continue
            records[_ip] = {
                "threat_level": _a.get("threat_level", "HIGH"),
                "attack_types": _a.get("attack_types", []),
                "first_seen": _a.get("first_seen"),
                "last_seen": _a.get("last_seen"),
                "reason": (_a.get("intel") or {}).get("reason"),
                "total_attempts": (_a.get("stats") or {}).get("total_attempts", 0),
            }
            if _ip in _block_expiry:
                records[_ip]["expires_at"] = _block_expiry[_ip]
        data = {
            "blocked": ips,
            "records": records,
            "updated_at": _now_iso(),
            "count": len(ips),
        }
        BLOCKED_IPS_FILE.write_text(json.dumps(data, indent=2))
        logger.debug(f"Saved {len(ips)} blocked IPs to {BLOCKED_IPS_FILE}")
    except OSError as e:
        logger.error(f"Failed to save blocked IPs: {e}")


def _restore_iptables_rules():
    """On startup, re-apply iptables rules from the persistent file."""
    ips = _load_blocked_ips()
    if not ips:
        logger.info("No persisted blocked IPs to restore")
        return
    _recs = _load_blocked_records()
    for _ip, _r in _recs.items():
        if isinstance(_r, dict) and isinstance(_r.get("expires_at"), (int, float)):
            _block_expiry[_ip] = float(_r["expires_at"])
    # Blocks that lapsed while the agent was down are dropped, not re-applied.
    lapsed = [i for i in ips if _is_expired(i)]
    for ip in lapsed:
        logger.info(f"Block for {ip} expired while agent was down, not restoring")
        _block_expiry.pop(ip, None)
    ips = [i for i in ips if i not in lapsed]
    if lapsed:
        _save_blocked_ips(ips)
    logger.info(f"Restoring {len(ips)} blocked IPs from {BLOCKED_IPS_FILE}")
    for ip in ips:
        try:
            _validate_ip(ip)
            block_ip(ip)
        except Exception as e:
            logger.warning(f"Failed to restore block for {ip}: {e}")
    logger.info(f"Restored iptables rules for {len(ips)} IPs")


# ---------------------------------------------------------------------------
# Attacker tracking
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_to_threat_level(severity: Optional[str]) -> str:
    """Map a caller-reported severity onto the tracker's threat levels.

    Added 2026-08-03. Previously every block was recorded as HIGH regardless of
    what actually happened, so /attackers could not distinguish an SQLi attempt
    from a fast crawler. Unknown/absent severity keeps the old HIGH default, so
    nothing regresses for callers that report nothing.
    """
    mapping = {
        "info": "INFO", "informational": "INFO", "debug": "INFO",
        "low": "LOW",
        "medium": "MEDIUM", "moderate": "MEDIUM", "warning": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL", "severe": "CRITICAL",
    }
    if not severity:
        return "HIGH"
    return mapping.get(str(severity).strip().lower(), "HIGH")


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
    """Log a firewall event.

    Appends to both the in-memory list (fast, capped at EVENTS_MAX — powers
    the default /events response) and the durable JSONL log on disk
    (uncapped — survives restarts). This is additive: the in-memory path
    and its cap are unchanged.
    """
    event = {
        "type": event_type,
        "ip": ip,
        "description": details,
        "severity": severity,
        "timestamp": _now_iso(),
    }
    _events.append(event)
    # Trim old events
    while len(_events) > EVENTS_MAX:
        _events.pop(0)
    _append_event_jsonl(event)


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

    # Restore persisted iptables rules
    _restore_iptables_rules()

    # Populate attacker list from currently blocked IPs
    # AEGIS-FP-FIX 20261019: restore the SAVED classification instead of stamping
    # every persisted IP as HIGH with no attack types. That hardcoded HIGH is what
    # made the whole blocklist unauditable after the 2026-10-17 restart.
    _recs = _load_blocked_records()
    for ip in list_blocked_ips():
        if ip in _attackers:
            continue
        _r = _recs.get(ip) or {}
        _track_attacker(
            ip,
            event_type="block",
            threat_level=_r.get("threat_level") or "HIGH",
            attack_types=_r.get("attack_types") or None,
        )
        _e = _attackers[ip]
        if _r:
            if _r.get("first_seen"):
                _e["first_seen"] = _r["first_seen"]
            if _r.get("last_seen"):
                _e["last_seen"] = _r["last_seen"]
            if _r.get("total_attempts"):
                _e["stats"]["total_attempts"] = _r["total_attempts"]
            if _r.get("reason"):
                _e["intel"]["reason"] = _r["reason"]
        else:
            _e["intel"]["reason"] = (
                "restored from persistence written before 2026-10-19; the original "
                "block reason was never saved, so this threat_level is a default, "
                "NOT evidence"
            )

    # Verified-crawler whitelist (2026-08-03 incident): populate the published
    # vendor prefix feeds and keep them fresh. Started as a background task so
    # a slow/unreachable feed can never delay the agent coming up — until the
    # first refresh completes the whitelist is just the AEGIS_CRAWLER_NETS seed,
    # i.e. exactly today's behaviour. FCrDNS works from the first request.
    crawler_task = asyncio.create_task(_crawler_refresh_loop())
    expiry_task = asyncio.create_task(_expiry_sweep_loop())

    _add_event("startup", details="AEGIS Firewall Agent started", severity="info")
    logger.info("AEGIS Firewall Agent ready on port 8765")

    yield

    for _t in (crawler_task, expiry_task):
        _t.cancel()
        try:
            await _t
        except (asyncio.CancelledError, Exception):
            pass
    logger.info("AEGIS Firewall Agent shutting down")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AEGIS Firewall Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Read-only GET paths reachable without the secret once it is set. Exists for
# consumers that cannot send the header (the Sable middleware polls /blocked).
# Only GET is ever public; mutating methods always need the secret.
_PUBLIC_READ_PATHS = frozenset(
    p.strip().rstrip("/") or "/"
    for p in os.getenv("AEGIS_FIREWALL_PUBLIC_READ", "/blocked").split(",")
    if p.strip()
)
_REJECT_LOG_INTERVAL = 30.0  # seconds, per (client ip, method, path)
_reject_last_logged: dict[tuple, float] = {}


def _log_rejected(request: Request) -> None:
    """WARNING for a rejected request, at most once per interval per key."""
    client_ip = request.client.host if request.client else "unknown"
    key = (client_ip, request.method, request.url.path)
    now = time.monotonic()
    if now - _reject_last_logged.get(key, -_REJECT_LOG_INTERVAL) < _REJECT_LOG_INTERVAL:
        return
    if len(_reject_last_logged) > 1000:
        _reject_last_logged.clear()
    _reject_last_logged[key] = now
    logger.warning(
        "auth rejected: %s %s from %s (missing/invalid X-AEGIS-FW-Auth)",
        request.method, request.url.path, client_ip,
    )


def _is_public_read(request: Request) -> bool:
    path = request.url.path.rstrip("/") or "/"
    return request.method == "GET" and path in _PUBLIC_READ_PATHS


@app.middleware("http")
async def _enforce_shared_secret(request: Request, call_next):
    """Authenticate the Mac Pro <-> Pi firewall channel (B5 / P0-12).

    When AEGIS_FIREWALL_SECRET is set, every request must carry header
    `X-AEGIS-FW-Auth: <shared secret>` (compared in constant time), except:
      * GET /health (uptime probes)
      * GET on the paths in AEGIS_FIREWALL_PUBLIC_READ (default "/blocked",
        needed by the Sable middleware, which cannot send the header).
    Mutating methods are never public. Rejections are logged at WARNING,
    rate-limited per (client, method, path).

    COMPAT MODE: if AEGIS_FIREWALL_SECRET is unset, nothing is enforced and
    all requests are accepted, so a staged rollout cannot lock AEGIS out.
    """
    if request.url.path == "/health" and request.method in ("GET", "HEAD"):
        return await call_next(request)
    if not AEGIS_FIREWALL_SECRET:
        return await call_next(request)
    if request.method == "OPTIONS":
        return await call_next(request)  # CORS preflight carries no headers
    if _is_public_read(request):
        return await call_next(request)
    supplied = request.headers.get("X-AEGIS-FW-Auth", "")
    if not hmac.compare_digest(supplied.encode(), AEGIS_FIREWALL_SECRET.encode()):
        _log_rejected(request)
        return JSONResponse(
            status_code=401,
            content={"detail": "invalid or missing X-AEGIS-FW-Auth header"},
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class IPRequest(BaseModel):
    ip: str
    # --- classification, added 2026-08-03 ---------------------------------
    # Before today this model was `ip: str` only. FastAPI/pydantic drops
    # unknown fields silently, so attack_detector.py's `reason` — which it HAS
    # been sending all along — was thrown away on arrival. Consequence: all 65
    # entries in /attackers read `threat_level: HIGH, attack_types: []`, and it
    # was impossible to tell why ANY IP was blocked, including the Bing crawler.
    # These fields are all Optional so every existing caller keeps working
    # unchanged; they are used to decide whether a verified crawler qualifies
    # for the behavioural exemption (see _verify_crawler).
    reason: Optional[str] = None
    pattern_name: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    duration: Optional[int] = None
    # AEGIS-FP-FIX 20261019: bypass the evidence gate for a deliberate
    # operator/admin block (the gate only guards automated, unclassified ones).
    force: Optional[bool] = False


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
        "version": "1.0.0",
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
    # Filter expired entries here too: a stalled sweeper must not keep a stale
    # block visible (and thus trusted) to AEGIS.
    blocked = [i for i in list_blocked_ips() if not _is_expired(i)]
    return {"blocked": blocked, "count": len(blocked)}


# --- Verified-crawler whitelist endpoints (2026-08-03) ----------------------


@app.get("/crawlers")
async def get_crawlers():
    """Whitelist status. Read-only introspection for operators."""
    by_vendor: dict[str, int] = {}
    for _net, vendor in _crawler_nets:
        by_vendor[vendor] = by_vendor.get(vendor, 0) + 1
    return {
        "enabled": True,
        "networks": len(_crawler_nets),
        "by_vendor": by_vendor,
        "ptr_suffixes": _CRAWLER_PTR_SUFFIXES,
        "sources": CRAWLER_RANGE_SOURCES,
        "last_refresh": _crawler_last_refresh,
        "last_refresh_iso": (
            datetime.fromtimestamp(_crawler_last_refresh, timezone.utc).isoformat()
            if _crawler_last_refresh else None
        ),
        "last_error": _crawler_last_error,
        "auto_unblock": CRAWLER_AUTO_UNBLOCK,
        "refresh_seconds": CRAWLER_REFRESH_SECONDS,
        "note": "Whitelist exempts BEHAVIOURAL blocks only; exploit signatures still block. Incident 2026-08-03 (Bing/msnbot).",
    }


@app.get("/crawlers/allowlist")
async def get_crawler_allowlist():
    """Flat CIDR list, consumed by Sable's Edge middleware.

    The middleware cannot do DNS (Edge runtime), so it gets the CIDR half of
    the whitelist here and uses it as a last-resort override on the 403 path.
    """
    return {
        "cidrs": [str(net) for net, _vendor in _crawler_nets],
        "count": len(_crawler_nets),
        "last_refresh": _crawler_last_refresh,
    }


@app.post("/crawlers/verify")
async def post_crawler_verify(req: IPRequest):
    """Ask whether a given IP would be treated as a verified crawler."""
    ip = _validate_ip(req.ip)
    threat_text = _threat_text(req.reason, req.pattern_name, req.threat_type)
    return {
        "ip": ip,
        "cidr_vendor": _crawler_cidr_match(ip),
        "fcrdns_vendor": await _fcrdns_vendor(ip),
        "reported_threat": threat_text or None,
        "exploit_signal": _is_exploit_signal(threat_text),
        "would_be_exempted": await _verify_crawler(ip, threat_text) is not None,
    }


@app.post("/crawlers/refresh")
async def post_crawler_refresh():
    """Force a re-fetch of the vendor prefix feeds."""
    return await _refresh_crawler_ranges()


@app.post("/crawlers/reconcile")
async def post_crawler_reconcile(dry_run: bool = True):
    """Report (dry_run=true, default) or release verified crawlers already blocked."""
    return await _reconcile_blocked_crawlers(dry_run=dry_run)


@app.post("/block")
async def post_block(req: IPRequest):
    ip = _validate_ip(req.ip)

    if req.duration is not None and req.duration <= 0:
        raise HTTPException(status_code=400,
                            detail="duration must be a positive number of seconds")
    duration = min(req.duration, MAX_BLOCK_DURATION) if req.duration is not None else None

    # Safety check
    if _is_safe_ip(ip):
        raise HTTPException(
            status_code=403,
            detail=f"Refusing to block safe/internal IP: {ip}",
        )

    # --- Verified-crawler whitelist (2026-08-03 incident) -------------------
    # AEGIS blocked Bing's msnbot on behaviour, which made Sable invisible to
    # Bing/ChatGPT/Perplexity while robots.txt said they were welcome. Every
    # block funnels through here, so this is the one place where refusing is
    # durable against the AEGIS brain simply re-pushing the same IP.
    # An exploit signature always wins over the whitelist — see _is_exploit_signal.
    threat_text = _threat_text(req.reason, req.pattern_name, req.threat_type)
    crawler_vendor = await _verify_crawler(ip, threat_text)
    if crawler_vendor:
        behavioural = [t for t in _BEHAVIOURAL_TOKENS if t in threat_text]
        detail = (
            f"Refusing to block verified crawler {ip} ({crawler_vendor}). "
            f"Reported threat: {threat_text or 'unclassified'}"
            + (f" [behavioural: {', '.join(sorted(behavioural))}]" if behavioural else "")
            + ". Crawler whitelist active since 2026-08-03 (Bing/msnbot incident); "
              "exploit-signature blocks are NOT exempted."
        )
        logger.warning(detail)
        _add_event("crawler_block_refused", ip=ip, details=detail, severity="info")
        raise HTTPException(status_code=403, detail=detail)

    # --- AEGIS-FP-FIX 20261019: evidence gate -------------------------------
    # A block now needs EITHER a real exploit signature (_EXPLOIT_TOKENS, which
    # still blocks on the very first hit) OR a repeat sighting. A first contact
    # that is unclassified or merely behavioural ("404", "scanner",
    # "high_request_rate") is recorded as an observation and NOT blocked; the
    # next hit from the same IP blocks it. This is the fix for the 2026-10-19
    # false-positive audit, where every blocked IP had exactly 1 attempt and no
    # attack type. Operator blocks pass `force: true`.
    if not req.force:
        _seen = ((_attackers.get(ip) or {}).get("stats") or {}).get("total_attempts", 0)
        if not _is_exploit_signal(threat_text) and (_seen + 1) < BLOCK_MIN_ATTEMPTS:
            _track_attacker(ip, event_type="observe", threat_level="LOW")
            if threat_text:
                _attackers[ip]["intel"]["reason"] = threat_text
            detail = (
                f"Not blocking {ip}: no exploit signature and only {_seen + 1} "
                f"sighting(s) (minimum {BLOCK_MIN_ATTEMPTS}). Reported threat: "
                f"{threat_text or 'unclassified'}. Recorded as an observation; a "
                "repeat hit will block it. Use force:true to override."
            )
            logger.info(detail)
            _add_event("block_deferred_no_evidence", ip=ip, details=detail,
                       severity="info")
            return {
                "success": False,
                "ip": ip,
                "blocked": False,
                "deferred": True,
                "sightings": _seen + 1,
                "min_attempts": BLOCK_MIN_ATTEMPTS,
                "detail": detail,
            }

    # A temporary request must never downgrade an existing permanent block, so
    # look before block_ip() adds the rule.
    was_permanent = _ip_is_blocked(ip) and ip not in _block_expiry

    success = block_ip(ip)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to block {ip}")

    if duration is None:
        _block_expiry.pop(ip, None)
    elif not was_permanent:
        _block_expiry[ip] = max(_block_expiry.get(ip, 0.0), _now_ts() + duration)

    # Track the attacker — now WITH the classification the caller sent, instead
    # of the hardcoded HIGH/[] that made /attackers useless (see IPRequest).
    threat_level = _severity_to_threat_level(req.severity)
    attack_types = [t for t in (req.pattern_name, req.threat_type) if t]
    _track_attacker(ip, event_type="block", threat_level=threat_level,
                    attack_types=attack_types or None)
    # AEGIS-FP-FIX 20261019: keep the free-text reason too, so it survives a
    # restart via _save_blocked_ips -> records[ip]["reason"].
    if threat_text:
        _attackers[ip]["intel"]["reason"] = threat_text

    # Update persistence
    blocked = list_blocked_ips()
    _save_blocked_ips(blocked)

    # Log event
    reason_suffix = f" — {threat_text}" if threat_text else " — reason not reported by caller"
    _add_event(
        "ip_blocked", ip=ip,
        details=f"Blocked IP {ip} via iptables{reason_suffix}",
        severity=threat_level.lower() if threat_level != "INFO" else "info",
    )

    return {
        "success": True,
        "ip": ip,
        "blocked_count": len(blocked),
        "threat_level": threat_level,
        "attack_types": attack_types,
        "expires_at": _block_expiry.get(ip),
    }


@app.delete("/block/{ip}")
async def delete_block(ip: str):
    ip = _validate_ip(ip)

    if not _release_block(ip):
        raise HTTPException(status_code=500, detail=f"Failed to unblock {ip}")
    blocked = list_blocked_ips()

    # Log event
    _add_event("ip_unblocked", ip=ip, details=f"Unblocked IP {ip}", severity="medium")

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
async def get_events(since: Optional[str] = None, limit: Optional[int] = None):
    """Return recent events, most recent first.

    Default (no query params): served straight from the in-memory list, so
    it stays as fast as before — unchanged behavior.

    `since` (ISO8601 timestamp) and/or `limit` (> 100) go beyond what
    EVENTS_MAX keeps in memory, so they instead stream EVENTS_LOG_PATH
    line-by-line (never loading the whole file into memory at once) to
    recover events that already fell off the in-memory cap or predate the
    last restart.
    """
    if since is None and (limit is None or limit <= EVENTS_MAX):
        cap = limit or 100
        return {"events": list(reversed(_events))[:cap]}

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid since timestamp: {since}")

    matched: list[dict] = []
    try:
        with open(EVENTS_LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if since_dt is not None:
                    try:
                        evt_dt = datetime.fromisoformat(str(evt.get("timestamp", "")))
                    except ValueError:
                        continue
                    if evt_dt < since_dt:
                        continue
                matched.append(evt)
    except OSError as e:
        logger.warning(f"Failed to read events log {EVENTS_LOG_PATH}: {e}")
        return {"events": list(reversed(_events))[:(limit or 100)]}

    matched.reverse()
    if limit:
        matched = matched[:limit]
    return {"events": matched}


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
# DoS Netshield (network tier) — DEFAULT OFF, gated endpoints
# ---------------------------------------------------------------------------
#
# These endpoints wrap dos_netshield.py (dedicated AEGIS_DOS iptables chain +
# sysctl SYN hardening). They are NO-OPS unless BOTH:
#   (1) the Pi env AEGIS_DOS_NETSHIELD=1 is set on the systemd unit, AND
#   (2) the caller sends header  X-AEGIS-Netshield: enable
# so the network tier can NEVER be applied accidentally. The dos_netshield
# module ALWAYS prepends host-safety ACCEPT rules (Mac Pro + Tailscale CGNAT +
# loopback) before any limit/DROP, so the gateway cannot lock out its own host.
# Nothing here runs at import or startup — application is explicit only.

try:
    import dos_netshield  # type: ignore
    _NETSHIELD_AVAILABLE = True
except Exception as _e:  # pragma: no cover - defensive import
    dos_netshield = None  # type: ignore
    _NETSHIELD_AVAILABLE = False
    logger.warning(f"dos_netshield module unavailable: {_e}")

_NETSHIELD_ENV_GATE = os.getenv("AEGIS_DOS_NETSHIELD", "").strip().lower() in ("1", "true", "yes", "on")


class DoSRateLimitRequest(BaseModel):
    rate: int = 50
    burst: int = 100
    connlimit: int = 100
    port: int = 8000


def _require_netshield(request: Request) -> None:
    """Enforce the double gate: env var + confirmation header. Raises 403."""
    if not _NETSHIELD_AVAILABLE:
        raise HTTPException(status_code=503, detail="dos_netshield module not available")
    if not _NETSHIELD_ENV_GATE:
        raise HTTPException(
            status_code=403,
            detail="netshield disabled (set AEGIS_DOS_NETSHIELD=1 on the Pi unit)",
        )
    if request.headers.get("X-AEGIS-Netshield", "").strip().lower() != "enable":
        raise HTTPException(
            status_code=403,
            detail="netshield confirmation header missing (X-AEGIS-Netshield: enable)",
        )


@app.get("/dos/status")
async def dos_status():
    """Read-only netshield state. Safe to call regardless of gate."""
    if not _NETSHIELD_AVAILABLE:
        return {"available": False, "env_gate": _NETSHIELD_ENV_GATE}
    state = dos_netshield.status()
    state["available"] = True
    state["env_gate"] = _NETSHIELD_ENV_GATE
    return state


@app.post("/dos/ratelimit")
async def dos_ratelimit(req: DoSRateLimitRequest, request: Request):
    """Apply per-source SYN hashlimit + connlimit in the dedicated AEGIS_DOS chain."""
    _require_netshield(request)
    try:
        result = dos_netshield.apply_ratelimit(
            rate=req.rate, burst=req.burst, connlimit=req.connlimit, port=req.port,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if result.get("success"):
        _add_event("dos_ratelimit", details=f"Netshield ratelimit applied: {result}", severity="high")
    return result


@app.post("/dos/harden")
async def dos_harden(request: Request):
    """Enable tcp_syncookies + tune SYN backlog via sysctl (snapshotted, reversible)."""
    _require_netshield(request)
    result = dos_netshield.harden_synflood()
    if result.get("success"):
        _add_event("dos_harden", details="Netshield SYN-flood sysctl hardening applied", severity="high")
    return result


@app.post("/dos/revert")
async def dos_revert(request: Request):
    """FULL rollback: remove AEGIS_DOS chain + restore sysctl. Requires env gate + header."""
    # Revert must be reachable to recover, but still requires the env gate so a
    # stray caller can't tear down rules on a Pi that never enabled netshield.
    if not _NETSHIELD_AVAILABLE:
        raise HTTPException(status_code=503, detail="dos_netshield module not available")
    if not _NETSHIELD_ENV_GATE:
        raise HTTPException(status_code=403, detail="netshield disabled (nothing to revert)")
    result = dos_netshield.revert()
    if result.get("success"):
        _add_event("dos_revert", details="Netshield reverted (chain removed, sysctl restored)", severity="medium")
    return result


# ---------------------------------------------------------------------------
# Additional utility endpoints
# ---------------------------------------------------------------------------


@app.get("/")
async def root():
    return {
        "service": "AEGIS Firewall Agent",
        "version": "1.0.0",
        "endpoints": [
            "/health", "/status", "/attackers", "/attacker/{ip}",
            "/blocked", "/block", "/analyze", "/ai/investigate",
            "/threat-summary", "/visitors/recent", "/iptables/rules",
            "/events", "/auto-response/blocked", "/ai/chat",
            "/dos/status", "/dos/ratelimit", "/dos/harden", "/dos/revert",
        ],
    }
