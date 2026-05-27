"""
IP Intelligence Enrichment Service — AEGIS v1.7

NO AI. This module is pure REST aggregation + observational correlation.
It does NOT call OpenAI, Anthropic, Gemini, OpenRouter, or any LLM. It
does NOT pass through ai_manager or any AEGIS AI subsystem. Behavior is
identical regardless of AEGIS_AI_MODE (full/local/offline).

Default providers (free, no auth, parallel):
  - ipinfo   : ipinfo.io/<ip>/json
  - ipguide  : ip.guide/<ip>
  - ipquery  : api.ipquery.io/<ip>
  - greynoise: api.greynoise.io/v3/community/<ip>  (free community endpoint)
  - ipapi    : ip-api.com/json/<ip>?fields=...    (45 req/min throttled)
  - geojs    : get.geojs.io/v1/ip/geo/<ip>.json

Deep-mode-only (slow / heavy):
  - shodan        : internetdb.shodan.io/<ip>     (open ports + tags + vulns)
  - torlist       : local cache of torproject exit list
  - spamhaus      : local cache of spamhaus DROP CIDR list
  - asn_reputation: in-process ASN classification table
  - behavioral    : observation of /web-logs/aegis-feed.jsonl
  - abuseipdb     : api.abuseipdb.com (REQUIRES env ABUSEIPDB_KEY; skipped otherwise)

Aggregate post-processing (always):
  - classification : single label (tor_exit / vpn_user / datacenter_bot /
                     known_crawler / consumer_isp / known_attacker / unknown)
  - confidence     : per-flag votes (tor / vpn / proxy / datacenter / attacker)

Safe-net filter: private / loopback / link-local / multicast / Tailscale CGNAT
(100.64.0.0/10) and IPv6 ULA short-circuit to {"ip": <ip>, "internal": True}.

Backward-compatible: the legacy fields are still populated; new fields ADD only.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("aegis.ip_intel")

# ---------------------------------------------------------------------------
# Safe networks (mirrors log_watcher._SAFE_NETWORKS exactly)
# ---------------------------------------------------------------------------

_SAFE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / Tailscale
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
]

_ASN_RE = re.compile(r"^(AS\d+)\s+(.*)")


def _is_internal(ip: str) -> bool:
    """Return True for private / loopback / link-local / multicast / Tailscale CGNAT."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_private:
        return True
    return any(addr in net for net in _SAFE_NETS)


# ---------------------------------------------------------------------------
# In-memory caches
# ---------------------------------------------------------------------------

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 86_400.0  # 24 hours (static intel)
_DEEP_CACHE: dict[str, tuple[float, dict]] = {}
_DEEP_CACHE_TTL = 900.0  # 15 min (behavioral fingerprint changes with traffic)


def _cache_get(ip: str) -> dict | None:
    entry = _CACHE.get(ip)
    if entry and time.monotonic() < entry[0]:
        return entry[1]
    if entry:
        del _CACHE[ip]
    return None


def _cache_set(ip: str, result: dict) -> None:
    _CACHE[ip] = (time.monotonic() + _CACHE_TTL, result)


def _deep_cache_get(ip: str) -> dict | None:
    entry = _DEEP_CACHE.get(ip)
    if entry and time.monotonic() < entry[0]:
        return entry[1]
    if entry:
        del _DEEP_CACHE[ip]
    return None


def _deep_cache_set(ip: str, result: dict) -> None:
    _DEEP_CACHE[ip] = (time.monotonic() + _DEEP_CACHE_TTL, result)


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------

# All free, no-auth providers active by default. abuseipdb only when key set.
_DEFAULT_PROVIDERS = "ipinfo,ipguide,ipquery,greynoise,ipapi,geojs"
_TIMEOUT = httpx.Timeout(3.0, connect=2.0)
_DEEP_TIMEOUT = httpx.Timeout(6.0, connect=2.0)


def _enabled_providers() -> list[str]:
    raw = os.environ.get("AEGIS_IPINTEL_PROVIDERS", _DEFAULT_PROVIDERS)
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# Per-provider async fetchers — each returns a partial dict or {} on error
# ---------------------------------------------------------------------------

async def _fetch_ipinfo(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        r = await client.get(f"https://ipinfo.io/{ip}/json", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("ipinfo error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipinfo"}
    if data.get("hostname"):
        out["hostname"] = data["hostname"]
    if data.get("city"):
        out["city"] = data["city"]
    if data.get("region"):
        out["region"] = data["region"]
    if data.get("country"):
        out["country"] = data["country"]

    org_raw = data.get("org", "")
    m = _ASN_RE.match(org_raw)
    if m:
        out["asn"] = m.group(1)
        out["org"] = m.group(2)
    elif org_raw:
        out["org"] = org_raw
    return out


async def _fetch_ipguide(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        r = await client.get(f"https://ip.guide/{ip}", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("ipguide error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipguide"}
    net = data.get("network") or {}
    asn_data = net.get("autonomous_system") or {}
    if asn_data.get("asn"):
        out["asn"] = f"AS{asn_data['asn']}"
    if asn_data.get("organization"):
        out["org"] = asn_data["organization"]
    if asn_data.get("name") and not out.get("org"):
        out["org"] = asn_data["name"]

    loc = data.get("location") or {}
    if loc.get("country"):
        out["country"] = loc["country"]
    if loc.get("city"):
        out["city"] = loc["city"]
    return out


async def _fetch_ipquery(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        r = await client.get(f"https://api.ipquery.io/{ip}", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("ipquery error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipquery"}
    isp = data.get("isp") or {}
    if isp.get("asn"):
        out["asn"] = isp["asn"]
    if isp.get("org"):
        out["org"] = isp["org"]

    loc = data.get("location") or {}
    if loc.get("country_code"):
        out["country"] = loc["country_code"]
    if loc.get("city"):
        out["city"] = loc["city"]
    if loc.get("state"):
        out["region"] = loc["state"]

    risk = data.get("risk") or {}
    for flag in ("is_vpn", "is_tor", "is_proxy", "is_datacenter"):
        if flag in risk:
            out[flag] = risk[flag]
    if "risk_score" in risk:
        out["risk_score"] = risk["risk_score"]
    return out


async def _fetch_greynoise(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    GreyNoise community endpoint (free, no auth).
    Shape (verified 2026-05-27):
      {"ip","noise":bool,"riot":bool,
       "classification":"benign|unknown|malicious",
       "name":"...","link":"...","last_seen":"YYYY-MM-DD","message":"Success"}
    """
    try:
        r = await client.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        # 404 means "we don't know this IP" — return empty (not an error)
        if r.status_code == 404:
            return {"_provider": "greynoise", "greynoise_seen": False}
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("greynoise error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "greynoise", "greynoise_seen": True}
    cls = (data.get("classification") or "").lower()
    out["greynoise_classification"] = cls or None
    out["greynoise_noise"] = bool(data.get("noise"))
    out["greynoise_riot"] = bool(data.get("riot"))
    if data.get("name") and data["name"] != "unknown":
        out["greynoise_name"] = data["name"]
    if data.get("link"):
        out["greynoise_link"] = data["link"]
    if data.get("last_seen"):
        out["greynoise_last_seen"] = data["last_seen"]

    # Vote into shared flags
    if cls == "malicious":
        out["is_malicious"] = True
    if data.get("noise") is True:
        # noise = internet-scanning bot (not human attacker, not VPN)
        out["is_scanner"] = True
    if data.get("riot") is True:
        # riot = common benign service (CDN, Google, etc.)
        out["is_known_service"] = True
    return out


async def _fetch_ipapi(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    ip-api.com (free, 45 req/min from same IP, no key).
    fields=66846719 = everything.
    """
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=66846719",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "success":
            return {}
    except Exception as exc:
        logger.debug("ipapi error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipapi"}
    if data.get("countryCode"):
        out["country"] = data["countryCode"]
    if data.get("city"):
        out["city"] = data["city"]
    if data.get("regionName"):
        out["region"] = data["regionName"]
    if data.get("reverse"):
        out["hostname"] = data["reverse"]

    asn_raw = data.get("as", "")
    m = _ASN_RE.match(asn_raw)
    if m:
        out["asn"] = m.group(1)
    if data.get("isp"):
        out["org"] = data["isp"]

    # ip-api flags
    if "proxy" in data:
        out["is_proxy"] = bool(data["proxy"])
    if "hosting" in data:
        out["is_datacenter"] = bool(data["hosting"])
    if "mobile" in data:
        out["is_mobile"] = bool(data["mobile"])
    return out


async def _fetch_geojs(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """get.geojs.io (free, no auth) — geo + ASN backup."""
    try:
        r = await client.get(
            f"https://get.geojs.io/v1/ip/geo/{ip}.json",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("geojs error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "geojs"}
    if data.get("country_code"):
        out["country"] = data["country_code"]
    if data.get("city"):
        out["city"] = data["city"]
    if data.get("region"):
        out["region"] = data["region"]
    if data.get("asn"):
        out["asn"] = f"AS{data['asn']}"
    if data.get("organization_name"):
        out["org"] = data["organization_name"]
    return out


async def _fetch_shodan_internetdb(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    Shodan InternetDB (free, no auth) — open ports, hostnames, CPEs, tags, vulns.
    Adds attacker-infra signal. Slow-ish; only called in deep mode.
    """
    try:
        r = await client.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=_DEEP_TIMEOUT,
        )
        if r.status_code == 404:
            return {"_provider": "shodan", "shodan_seen": False}
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("shodan error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "shodan", "shodan_seen": True}
    out["shodan_ports"] = data.get("ports") or []
    out["shodan_hostnames"] = data.get("hostnames") or []
    out["shodan_cpes"] = data.get("cpes") or []
    out["shodan_tags"] = data.get("tags") or []
    out["shodan_vulns"] = data.get("vulns") or []
    # tag-based flag derivations
    tags_lower = {t.lower() for t in out["shodan_tags"]}
    if "tor" in tags_lower:
        out["is_tor"] = True
    if "vpn" in tags_lower:
        out["is_vpn"] = True
    if "proxy" in tags_lower:
        out["is_proxy"] = True
    return out


async def _fetch_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """AbuseIPDB (optional, requires ABUSEIPDB_KEY env). 1000 req/day free tier."""
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return {}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=_DEEP_TIMEOUT,
        )
        r.raise_for_status()
        data = (r.json() or {}).get("data") or {}
    except Exception as exc:
        logger.debug("abuseipdb error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "abuseipdb"}
    score = data.get("abuseConfidenceScore")
    if isinstance(score, (int, float)):
        out["abuseipdb_score"] = int(score)
        if score >= 50:
            out["is_malicious"] = True
    if data.get("totalReports") is not None:
        out["abuseipdb_reports"] = int(data["totalReports"])
    if data.get("lastReportedAt"):
        out["abuseipdb_last_reported"] = data["lastReportedAt"]
    if data.get("usageType"):
        out["abuseipdb_usage_type"] = data["usageType"]
    return out


# ---------------------------------------------------------------------------
# Local data sources (tor exit list, spamhaus drop, asn reputation)
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_TOR_EXIT_FILE = _DATA_DIR / "tor_exits.txt"
_SPAMHAUS_FILE = _DATA_DIR / "spamhaus_drop.txt"
_TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"

_TOR_EXITS: set[str] = set()
_TOR_EXITS_LOADED_AT: float = 0.0
_TOR_EXITS_TTL = 3600.0  # reload every hour

_SPAMHAUS_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_SPAMHAUS_LOADED_AT: float = 0.0
_SPAMHAUS_TTL = 3600.0


def _load_tor_exits() -> set[str]:
    """Load Tor exit IPs from local cache file. Returns set of IPs."""
    global _TOR_EXITS, _TOR_EXITS_LOADED_AT
    now = time.monotonic()
    if _TOR_EXITS and (now - _TOR_EXITS_LOADED_AT) < _TOR_EXITS_TTL:
        return _TOR_EXITS

    ips: set[str] = set()
    try:
        if _TOR_EXIT_FILE.exists():
            with _TOR_EXIT_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # accept "IP" or "ExitAddress IP ..."
                    parts = line.split()
                    candidate = parts[1] if (len(parts) > 1 and parts[0] == "ExitAddress") else parts[0]
                    with contextlib.suppress(ValueError):
                        ipaddress.ip_address(candidate)
                        ips.add(candidate)
    except Exception as exc:
        logger.debug("tor exit list load error: %s", exc)

    _TOR_EXITS = ips
    _TOR_EXITS_LOADED_AT = now
    return _TOR_EXITS


async def _ensure_tor_exits_async(client: httpx.AsyncClient) -> set[str]:
    """If the local file is empty / missing, fetch the Tor list directly."""
    cur = _load_tor_exits()
    if cur:
        return cur
    try:
        r = await client.get(_TOR_EXIT_URL, timeout=_DEEP_TIMEOUT)
        r.raise_for_status()
        ips: set[str] = set()
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            with contextlib.suppress(ValueError):
                ipaddress.ip_address(line)
                ips.add(line)
        global _TOR_EXITS, _TOR_EXITS_LOADED_AT
        _TOR_EXITS = ips
        _TOR_EXITS_LOADED_AT = time.monotonic()
        # persist for next call
        with contextlib.suppress(Exception):
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            _TOR_EXIT_FILE.write_text("\n".join(sorted(ips)), encoding="utf-8")
        return ips
    except Exception as exc:
        logger.debug("tor exit refresh failed: %s", exc)
        return set()


def _load_spamhaus_nets() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Load Spamhaus DROP CIDRs from local cache."""
    global _SPAMHAUS_NETS, _SPAMHAUS_LOADED_AT
    now = time.monotonic()
    if _SPAMHAUS_NETS and (now - _SPAMHAUS_LOADED_AT) < _SPAMHAUS_TTL:
        return _SPAMHAUS_NETS

    nets: list = []
    try:
        if _SPAMHAUS_FILE.exists():
            with _SPAMHAUS_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith(";") or line.startswith("#"):
                        continue
                    cidr = line.split(";")[0].split()[0].strip()
                    with contextlib.suppress(ValueError):
                        nets.append(ipaddress.ip_network(cidr, strict=False))
    except Exception as exc:
        logger.debug("spamhaus load error: %s", exc)

    _SPAMHAUS_NETS = nets
    _SPAMHAUS_LOADED_AT = now
    return _SPAMHAUS_NETS


# ASN reputation table — manually curated. Best-effort, not authoritative.
# Tags: crawler / cloud / vpn / tor / hosting / consumer
_ASN_REPUTATION: dict[str, dict[str, Any]] = {
    "AS15169": {"tag": "crawler",  "name": "Google",          "owner": "Google LLC"},
    "AS8075":  {"tag": "crawler",  "name": "Microsoft",       "owner": "Microsoft Corp"},
    "AS8068":  {"tag": "crawler",  "name": "Microsoft",       "owner": "Microsoft Corp"},
    "AS13238": {"tag": "crawler",  "name": "Yandex",          "owner": "YANDEX"},
    "AS32934": {"tag": "crawler",  "name": "Facebook/Meta",   "owner": "Meta Platforms"},
    "AS54113": {"tag": "cloud",    "name": "Fastly",          "owner": "Fastly"},
    "AS13335": {"tag": "cloud",    "name": "Cloudflare",      "owner": "Cloudflare, Inc."},
    "AS16509": {"tag": "cloud",    "name": "AWS",             "owner": "Amazon"},
    "AS14618": {"tag": "cloud",    "name": "AWS",             "owner": "Amazon"},
    "AS16276": {"tag": "hosting",  "name": "OVH",             "owner": "OVH SAS"},
    "AS14061": {"tag": "hosting",  "name": "DigitalOcean",    "owner": "DigitalOcean"},
    "AS24940": {"tag": "hosting",  "name": "Hetzner",         "owner": "Hetzner Online"},
    "AS63949": {"tag": "hosting",  "name": "Linode/Akamai",   "owner": "Akamai (Linode)"},
    "AS20473": {"tag": "hosting",  "name": "Vultr",           "owner": "Choopa/Vultr"},
    "AS60729": {"tag": "tor",      "name": "Tor Project (Stiftung Erneuerbare Freiheit)", "owner": "TorServers.net"},
    "AS4224":  {"tag": "tor",      "name": "Calyx Institute", "owner": "The Calyx Institute"},
    "AS208323":{"tag": "tor",      "name": "Foundation for Applied Privacy", "owner": "FAP"},
}


def _asn_reputation(asn: str | None) -> dict[str, Any]:
    if not asn:
        return {}
    rec = _ASN_REPUTATION.get(asn.upper())
    if not rec:
        return {}
    return {
        "asn_reputation_tag": rec["tag"],
        "asn_reputation_name": rec["name"],
        "asn_reputation_owner": rec["owner"],
    }


# ---------------------------------------------------------------------------
# Behavioral fingerprint (from local aegis-feed.jsonl)
# ---------------------------------------------------------------------------

_FEED_PATH_DEFAULT = "/Users/alejandxr/web-logs/aegis-feed.jsonl"
_FEED_MAX_BYTES = 8 * 1024 * 1024  # tail last 8 MB


def _feed_path() -> Path:
    return Path(os.environ.get("AEGIS_FEED_PATH", _FEED_PATH_DEFAULT))


def _read_feed_tail(path: Path, max_bytes: int = _FEED_MAX_BYTES) -> list[str]:
    """Read up to max_bytes from the end of the file. Returns lines."""
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # skip partial first line
            data = fh.read().decode("utf-8", errors="ignore")
        return data.splitlines()
    except Exception as exc:
        logger.debug("feed tail read error: %s", exc)
        return []


def _behavioral_for_ip(ip: str) -> dict[str, Any]:
    """
    Scan the local aegis-feed.jsonl tail for activity by `ip`.

    Returns a fingerprint:
      hits, distinct_apps, distinct_paths, distinct_uas,
      paths[], uas[], apps[], first_seen, last_seen,
      request_interval_mean_sec, session_fingerprint (hash)
    """
    lines = _read_feed_tail(_feed_path())
    if not lines:
        return {"hits": 0}

    matched: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line or '"' + ip + '"' not in line:
            # quick substring filter; still parse to confirm
            if ip not in line:
                continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        evt_ip = evt.get("ip") or evt.get("source_ip") or evt.get("remote_addr")
        if evt_ip != ip:
            continue
        matched.append(evt)

    if not matched:
        return {"hits": 0}

    apps = Counter()
    paths_c = Counter()
    uas_c = Counter()
    timestamps: list[float] = []
    for evt in matched:
        if evt.get("app"):
            apps[evt["app"]] += 1
        path = evt.get("path") or evt.get("url") or evt.get("request_path")
        if path:
            paths_c[path] += 1
        ua = evt.get("user_agent") or evt.get("ua")
        if ua:
            uas_c[ua] += 1
        ts = evt.get("ts") or evt.get("timestamp")
        if isinstance(ts, (int, float)):
            timestamps.append(float(ts))
        elif isinstance(ts, str):
            with contextlib.suppress(Exception):
                # accept ISO 8601 or unix-as-string
                if ts.replace(".", "").isdigit():
                    timestamps.append(float(ts))
                else:
                    from datetime import datetime
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())

    timestamps.sort()
    interval_mean = None
    interval_stddev = None
    if len(timestamps) >= 2:
        diffs = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        interval_mean = sum(diffs) / len(diffs)
        mean = interval_mean
        var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
        interval_stddev = var ** 0.5

    first_seen = timestamps[0] if timestamps else None
    last_seen = timestamps[-1] if timestamps else None

    # session fingerprint: opaque hash of (first 5 paths, primary UA, hour of day, interval bucket)
    import hashlib
    primary_ua = uas_c.most_common(1)[0][0] if uas_c else ""
    first5_paths = "|".join([p for p, _ in paths_c.most_common(5)])
    hour_of_day = ""
    if first_seen:
        from datetime import datetime, timezone
        hour_of_day = str(datetime.fromtimestamp(first_seen, tz=timezone.utc).hour)
    interval_bucket = ""
    if interval_stddev is not None:
        # buckets: <1s, 1-5s, 5-30s, 30s-5m, >5m
        if interval_stddev < 1:
            interval_bucket = "burst"
        elif interval_stddev < 5:
            interval_bucket = "fast"
        elif interval_stddev < 30:
            interval_bucket = "steady"
        elif interval_stddev < 300:
            interval_bucket = "slow"
        else:
            interval_bucket = "sparse"
    fp_input = f"{first5_paths}::{primary_ua}::{hour_of_day}::{interval_bucket}"
    session_fp = hashlib.sha1(fp_input.encode("utf-8")).hexdigest()[:16]

    return {
        "hits": len(matched),
        "distinct_apps": len(apps),
        "distinct_paths": len(paths_c),
        "distinct_uas": len(uas_c),
        "apps": [a for a, _ in apps.most_common(8)],
        "paths": [p for p, _ in paths_c.most_common(8)],
        "uas": [u for u, _ in uas_c.most_common(3)],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "request_interval_mean_sec": interval_mean,
        "request_interval_stddev_sec": interval_stddev,
        "session_fingerprint": session_fp,
    }


def _correlated_sessions(session_fp: str | None) -> list[str]:
    """Find other IPs sharing the same session fingerprint (deep grep)."""
    if not session_fp:
        return []
    lines = _read_feed_tail(_feed_path())
    if not lines:
        return []
    ip_to_paths: dict[str, list[str]] = {}
    ip_to_ua: dict[str, str] = {}
    ip_to_ts: dict[str, list[float]] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        evt_ip = evt.get("ip") or evt.get("source_ip") or evt.get("remote_addr")
        if not evt_ip:
            continue
        path = evt.get("path") or evt.get("url") or evt.get("request_path")
        ua = evt.get("user_agent") or evt.get("ua")
        ts = evt.get("ts") or evt.get("timestamp")
        if path:
            ip_to_paths.setdefault(evt_ip, []).append(path)
        if ua and evt_ip not in ip_to_ua:
            ip_to_ua[evt_ip] = ua
        if isinstance(ts, (int, float)):
            ip_to_ts.setdefault(evt_ip, []).append(float(ts))

    import hashlib
    matches: list[str] = []
    for other_ip, paths in ip_to_paths.items():
        paths_c = Counter(paths)
        first5_paths = "|".join([p for p, _ in paths_c.most_common(5)])
        primary_ua = ip_to_ua.get(other_ip, "")
        ts_list = sorted(ip_to_ts.get(other_ip, []))
        hour_of_day = ""
        interval_bucket = ""
        if ts_list:
            from datetime import datetime, timezone
            hour_of_day = str(datetime.fromtimestamp(ts_list[0], tz=timezone.utc).hour)
        if len(ts_list) >= 2:
            diffs = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
            mean = sum(diffs) / len(diffs)
            var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
            sd = var ** 0.5
            if sd < 1: interval_bucket = "burst"
            elif sd < 5: interval_bucket = "fast"
            elif sd < 30: interval_bucket = "steady"
            elif sd < 300: interval_bucket = "slow"
            else: interval_bucket = "sparse"
        fp_input = f"{first5_paths}::{primary_ua}::{hour_of_day}::{interval_bucket}"
        other_fp = hashlib.sha1(fp_input.encode("utf-8")).hexdigest()[:16]
        if other_fp == session_fp:
            matches.append(other_ip)
    return matches


# ---------------------------------------------------------------------------
# Merge + classification
# ---------------------------------------------------------------------------

_SCALAR_FIELDS = ("asn", "org", "country", "city", "region", "hostname",
                  "is_tor", "is_vpn", "is_proxy", "is_datacenter", "is_mobile",
                  "is_malicious", "is_scanner", "is_known_service",
                  "risk_score")

# Precedence per provider: lower index wins for scalar merge
_ORDER = {
    "ipquery": 0,
    "ipinfo": 1,
    "ipapi": 2,
    "geojs": 3,
    "ipguide": 4,
    "greynoise": 5,
    "shodan": 6,
    "abuseipdb": 7,
}


def _merge(ip: str, results: list[dict]) -> dict:
    valid = [r for r in results if r and not r.get("error")]
    valid.sort(key=lambda r: _ORDER.get(r.get("_provider", ""), 99))
    providers_used = [r["_provider"] for r in valid if "_provider" in r]

    merged: dict[str, Any] = {
        "ip": ip,
        "asn": None,
        "org": None,
        "country": None,
        "city": None,
        "region": None,
        "hostname": None,
        "is_tor": None,
        "is_vpn": None,
        "is_proxy": None,
        "is_datacenter": None,
        "risk_score": None,
        "providers": providers_used,
        "cached": False,
        "internal": False,
    }

    for field in _SCALAR_FIELDS:
        for r in valid:
            val = r.get(field)
            if val is not None:
                merged[field] = val
                break

    # Pull through provider-specific extras for transparency
    for r in valid:
        for k, v in r.items():
            if k.startswith("greynoise_") or k.startswith("shodan_") or k.startswith("abuseipdb_"):
                merged[k] = v
    return merged


def _hostname_flags(hostname: str | None) -> dict[str, bool]:
    """Heuristic flag derivation from reverse DNS."""
    if not hostname:
        return {}
    h = hostname.lower()
    out: dict[str, bool] = {}
    if re.search(r"(tor|exit-node|torexit)", h):
        out["host_tor_hint"] = True
    if re.search(r"(vpn|nordvpn|expressvpn|protonvpn|surfshark|mullvad)", h):
        out["host_vpn_hint"] = True
    if re.search(r"(proxy|relay|gateway)", h):
        out["host_proxy_hint"] = True
    if re.search(r"(aws|amazon|azure|google|cloud|gcp|hetzner|ovh|linode|digitalocean|vultr|hosting|datacenter)", h):
        out["host_dc_hint"] = True
    return out


def _classify(merged: dict, tor_match: bool, spamhaus_match: bool, asn_rep: dict) -> tuple[str, dict]:
    """
    Roll up signals into a single classification + confidence votes.

    Returns: (classification_label, confidence_dict)
    confidence_dict has tor/vpn/proxy/datacenter/attacker keys ∈ [0.0, 1.0]
    """
    votes_tor = 0.0
    votes_vpn = 0.0
    votes_proxy = 0.0
    votes_dc = 0.0
    votes_attacker = 0.0
    weight_total = 0.0

    # Provider votes (each = weight 1)
    n_providers = max(1, len(merged.get("providers") or []))
    weight_total += n_providers
    if merged.get("is_tor"): votes_tor += 1
    if merged.get("is_vpn"): votes_vpn += 1
    if merged.get("is_proxy"): votes_proxy += 1
    if merged.get("is_datacenter"): votes_dc += 1
    if merged.get("is_malicious"): votes_attacker += 1

    # Tor exit ground truth (weight 2)
    if tor_match:
        votes_tor += 2
        weight_total += 2

    # Hostname hints (weight 0.5)
    host_flags = _hostname_flags(merged.get("hostname"))
    if host_flags.get("host_tor_hint"): votes_tor += 0.5
    if host_flags.get("host_vpn_hint"): votes_vpn += 0.5
    if host_flags.get("host_proxy_hint"): votes_proxy += 0.5
    if host_flags.get("host_dc_hint"): votes_dc += 0.5
    if host_flags:
        weight_total += 0.5

    # ASN reputation
    tag = asn_rep.get("asn_reputation_tag")
    if tag == "tor": votes_tor += 2; weight_total += 2
    elif tag == "cloud": votes_dc += 1; weight_total += 1
    elif tag == "hosting": votes_dc += 1; weight_total += 1
    elif tag == "crawler": pass  # crawlers stay separate

    # Spamhaus
    if spamhaus_match:
        votes_attacker += 2
        weight_total += 2

    # Greynoise classification
    gn_cls = merged.get("greynoise_classification")
    if gn_cls == "malicious":
        votes_attacker += 2
        weight_total += 2
    elif gn_cls == "benign":
        # benign drops attacker confidence (no vote)
        pass

    # Normalize
    norm = max(weight_total, 1.0)
    confidence = {
        "tor": round(min(1.0, votes_tor / 3.0), 2),
        "vpn": round(min(1.0, votes_vpn / 2.0), 2),
        "proxy": round(min(1.0, votes_proxy / 2.0), 2),
        "datacenter": round(min(1.0, votes_dc / 2.0), 2),
        "attacker": round(min(1.0, votes_attacker / 3.0), 2),
    }

    # Classification (priority: ground-truth > attacker > tor > vpn > crawler > dc > consumer)
    if confidence["tor"] >= 0.6 or tor_match:
        label = "tor_exit"
    elif confidence["attacker"] >= 0.6:
        label = "known_attacker"
    elif tag == "crawler":
        label = "known_crawler"
    elif confidence["vpn"] >= 0.5:
        label = "vpn_user"
    elif merged.get("is_scanner") or (merged.get("greynoise_noise") and confidence["attacker"] < 0.4):
        label = "datacenter_bot"
    elif confidence["datacenter"] >= 0.5:
        label = "datacenter_bot"
    elif merged.get("is_known_service") or (tag == "cloud"):
        label = "known_service"
    else:
        label = "unknown"

    return label, confidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_FETCHERS = {
    "ipinfo": _fetch_ipinfo,
    "ipguide": _fetch_ipguide,
    "ipquery": _fetch_ipquery,
    "greynoise": _fetch_greynoise,
    "ipapi": _fetch_ipapi,
    "geojs": _fetch_geojs,
}

_DEEP_FETCHERS = {
    "shodan": _fetch_shodan_internetdb,
    "abuseipdb": _fetch_abuseipdb,
}


async def lookup(ip: str, deep: bool = False) -> dict:
    """
    Enrich a public IP.

    deep=False (default): all free no-auth providers in parallel, 24h cache.
    deep=True: + shodan internetdb + abuseipdb (if key) + tor list + spamhaus
               + asn_reputation + behavioral fingerprint + correlated sessions.

    Returns a dict with stable fields (asn, org, country, city, region, hostname,
    is_tor, is_vpn, is_proxy, is_datacenter, risk_score, providers, cached,
    internal) plus additive ones (classification, confidence, greynoise_*,
    shodan_*, abuseipdb_*, asn_reputation_*, tor_list_match, spamhaus_match,
    behavioral, correlated_sessions).
    """
    if _is_internal(ip):
        return {"ip": ip, "internal": True}

    # Validate format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "internal": True}

    # Fast path: check static cache
    cached = _cache_get(ip)
    if cached is not None and not deep:
        return {**cached, "cached": True}

    enabled = _enabled_providers()
    async with httpx.AsyncClient() as client:
        tasks = [_FETCHERS[p](ip, client) for p in enabled if p in _FETCHERS]
        if deep:
            for name, fn in _DEEP_FETCHERS.items():
                if name in enabled or name in ("shodan", "abuseipdb"):
                    tasks.append(fn(ip, client))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=8.0 if deep else 4.0,
            )
        except asyncio.TimeoutError:
            logger.warning("IP intel lookup timed out for %s (deep=%s)", ip, deep)
            results = []

        clean: list[dict] = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug("Provider exception for %s: %s", ip, r)
            elif isinstance(r, dict):
                clean.append(r)

        merged = _merge(ip, clean)

        # Always: ASN reputation (purely local, no cost)
        asn_rep = _asn_reputation(merged.get("asn"))
        merged.update(asn_rep)

        # Deep-mode local lookups
        tor_match = False
        spamhaus_match = False
        behavioral: dict = {}
        corr_sessions: list[str] = []

        if deep:
            tor_set = _load_tor_exits()
            if not tor_set:
                tor_set = await _ensure_tor_exits_async(client)
            if ip in tor_set:
                tor_match = True
                merged["is_tor"] = True
                merged["tor_list_match"] = True
            else:
                merged["tor_list_match"] = False

            try:
                addr = ipaddress.ip_address(ip)
                for net in _load_spamhaus_nets():
                    if addr in net:
                        spamhaus_match = True
                        break
            except ValueError:
                pass
            merged["spamhaus_match"] = spamhaus_match
            if spamhaus_match:
                merged["is_malicious"] = True

            try:
                behavioral = _behavioral_for_ip(ip)
            except Exception as exc:
                logger.debug("behavioral fingerprint error for %s: %s", ip, exc)
                behavioral = {"hits": 0, "error": "fingerprint failed"}
            merged["behavioral"] = behavioral

            if behavioral.get("session_fingerprint"):
                try:
                    corr_sessions = _correlated_sessions(behavioral["session_fingerprint"])
                    # Don't include the queried IP itself
                    corr_sessions = [c for c in corr_sessions if c != ip]
                except Exception as exc:
                    logger.debug("correlated_sessions error: %s", exc)
                    corr_sessions = []
            merged["correlated_sessions"] = corr_sessions

    # Classification + confidence (always)
    label, confidence = _classify(merged, tor_match, spamhaus_match, asn_rep)
    merged["classification"] = label
    merged["confidence"] = confidence
    merged["deep"] = deep

    if deep:
        _deep_cache_set(ip, merged)
    else:
        _cache_set(ip, merged)
    return merged
