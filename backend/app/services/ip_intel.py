"""
IP Intelligence Enrichment Service — AEGIS v1.8

NO AI by default. This module is pure REST aggregation + observational
correlation. The ONE exception is the optional `ai_summary` field, which is:
  - opt-in: produced only when deep=True AND AEGIS_AI_MODE != offline
  - separated from deterministic classification (which never uses an LLM)
  - clearly provenance-tagged ({"kind": "agent", "source": "<provider>:<model>"})
When AEGIS_AI_MODE is offline (the prod default for AI gating), behavior is
fully deterministic and identical across runs. The ai_manager call is the
only LLM hook and is implemented in `ip_intel_history._ai_threat_brief`.

Default providers (free, no auth, parallel):
  - ipinfo     : ipinfo.io/<ip>/json
  - ipguide    : ip.guide/<ip>
  - ipquery    : api.ipquery.io/<ip>
  - greynoise  : api.greynoise.io/v3/community/<ip>  (free community endpoint)
  - ipapi      : ip-api.com/json/<ip>?fields=...    (45 req/min throttled)
  - geojs      : get.geojs.io/v1/ip/geo/<ip>.json
  - ipapi_is   : api.ipapi.is/?q=<ip>              (1000/day, abuse score + is_abuser)
  - proxycheck : proxycheck.io/v2/<ip>?vpn=1&risk=1 (1000/day, proxy type VPN/TOR/CGI)
  - otx        : otx.alienvault.com (community pulses, optional OTX_API_KEY)
  - ipinfo_lite: ipinfo.io/lite/<ip> (requires IPINFO_LITE_TOKEN — skipped otherwise)

Deep-mode-only (slow / heavy):
  - shodan        : internetdb.shodan.io/<ip>     (open ports + tags + vulns)
  - torlist       : local cache of torproject exit list
  - spamhaus      : local cache of spamhaus DROP CIDR list
  - asn_reputation: in-process ASN classification table
  - behavioral    : observation of /web-logs/aegis-feed.jsonl
  - abuseipdb     : api.abuseipdb.com (REQUIRES env ABUSEIPDB_KEY; skipped otherwise)
  - virustotal    : virustotal.com api/v3 (REQUIRES env VIRUSTOTAL_API_KEY; 4/min,500/day)

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

# All free, no-auth providers active by default. abuseipdb / vt only when key set.
_DEFAULT_PROVIDERS = (
    "ipinfo,ipguide,ipquery,greynoise,ipapi,geojs,"
    "ipapi_is,proxycheck,ipinfo_lite"
)
# OTX is opt-in default for deep-only (it can be slow without an API key)
_TIMEOUT = httpx.Timeout(3.0, connect=2.0)
_DEEP_TIMEOUT = httpx.Timeout(6.0, connect=2.0)


# ---------------------------------------------------------------------------
# Per-provider rate limiting (token-bucket via async lock + last-call ts)
# ---------------------------------------------------------------------------
# Limits requested by the spec:
#   ipapi_is  : 30 req/min  -> min interval 2.0s
#   proxycheck: 50 req/min  -> min interval 1.2s
#   otx       : 1000/day    -> ~0.7 req/min -> min interval 90s (very loose)
#   virustotal: 4 req/min   -> min interval 15s
# Soft limits: we just delay (await sleep) up to a small cap; if the cap is
# exceeded the call is skipped (returns {} so deep response still completes).

_RATE_INTERVALS: dict[str, float] = {
    "ipapi_is": 2.0,
    "proxycheck": 1.2,
    "otx": 0.5,           # community endpoint — courtesy spacing
    "virustotal": 15.0,
}
_RATE_LAST: dict[str, float] = {}
_RATE_LOCKS: dict[str, asyncio.Lock] = {}
_RATE_MAX_WAIT = 3.0  # seconds we are willing to wait before skipping a call


def _rate_lock(provider: str) -> asyncio.Lock:
    lock = _RATE_LOCKS.get(provider)
    if lock is None:
        lock = asyncio.Lock()
        _RATE_LOCKS[provider] = lock
    return lock


async def _rate_acquire(provider: str) -> bool:
    """Acquire a slot for `provider`. Returns False if the wait would exceed
    _RATE_MAX_WAIT (caller should skip the request)."""
    interval = _RATE_INTERVALS.get(provider)
    if not interval:
        return True
    async with _rate_lock(provider):
        now = time.monotonic()
        last = _RATE_LAST.get(provider, 0.0)
        wait = interval - (now - last)
        if wait > _RATE_MAX_WAIT:
            return False
        if wait > 0:
            await asyncio.sleep(wait)
        _RATE_LAST[provider] = time.monotonic()
    return True


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


async def _fetch_ipapi_is(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    ipapi.is — free 1000/day, no auth.
    Returns is_proxy, is_tor, is_vpn, is_abuser, is_datacenter, is_crawler,
    asn{asn,route,descr,country}, company{abuser_score string}, abuse{email}.
    """
    if not await _rate_acquire("ipapi_is"):
        logger.debug("ipapi_is rate limit skip for %s", ip)
        return {}
    try:
        r = await client.get(
            "https://api.ipapi.is/",
            params={"q": ip},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("ipapi_is error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipapi_is"}
    # core flags
    for flag in ("is_tor", "is_vpn", "is_proxy", "is_datacenter",
                 "is_mobile", "is_abuser", "is_crawler"):
        if flag in data:
            out[flag] = bool(data[flag])

    # ASN
    asn_block = data.get("asn") or {}
    if asn_block.get("asn"):
        out["asn"] = f"AS{asn_block['asn']}"
    if asn_block.get("descr"):
        out["org"] = asn_block["descr"]

    # Geo
    loc = data.get("location") or {}
    if loc.get("country_code"):
        out["country"] = loc["country_code"]
    if loc.get("city"):
        out["city"] = loc["city"]
    if loc.get("state"):
        out["region"] = loc["state"]

    # Abuse score — ipapi.is stores it as a *string* inside `company.abuser_score`
    # ("0.5273 (Very High)"). Parse to float 0..1. Also `asn.abuser_score` exists.
    company = data.get("company") or {}
    score_raw = company.get("abuser_score") or (asn_block.get("abuser_score") if asn_block else None)
    score_val: float | None = None
    if isinstance(score_raw, str):
        try:
            score_val = float(score_raw.split()[0])
        except Exception:
            score_val = None
    elif isinstance(score_raw, (int, float)):
        score_val = float(score_raw)
    if score_val is not None:
        out["ipapi_is_abuse_score"] = round(score_val, 4)
        # Mirror into legacy field for backward-compat: scale 0-100
        if score_val >= 0.5:
            out["is_malicious"] = True

    # Abuser contact
    abuse_block = data.get("abuse") or {}
    if abuse_block.get("email"):
        out["ipapi_is_abuse_contact"] = abuse_block["email"]
    if company.get("name"):
        out["ipapi_is_company"] = company["name"]
    if company.get("type"):
        out["ipapi_is_company_type"] = company["type"]
    return out


async def _fetch_proxycheck(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    proxycheck.io v2 — free 1000/day, no auth.
    Schema: {status:"ok", "<ip>": {proxy:"yes"|"no", type:"VPN"|"TOR"|"CGI"|"Compromised Server"|"Business"|..., risk:0..100, provider, organisation, asn, isocode, ...}}
    """
    if not await _rate_acquire("proxycheck"):
        logger.debug("proxycheck rate limit skip for %s", ip)
        return {}
    try:
        r = await client.get(
            f"http://proxycheck.io/v2/{ip}",
            params={"vpn": "1", "risk": "1", "asn": "1"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        logger.debug("proxycheck error for %s: %s", ip, exc)
        return {}

    if (data.get("status") or "ok") not in ("ok", None):
        return {}

    entry = data.get(ip) or {}
    if not isinstance(entry, dict):
        return {}

    out: dict[str, Any] = {"_provider": "proxycheck"}

    proxy_yn = (entry.get("proxy") or "").lower() == "yes"
    ptype = entry.get("type")  # may be None
    if proxy_yn:
        out["is_proxy"] = True
    if ptype:
        out["proxycheck_type"] = ptype
        tl = ptype.lower()
        if tl == "vpn":
            out["is_vpn"] = True
        elif tl == "tor":
            out["is_tor"] = True
        elif tl in ("cgi", "public proxy", "open proxy"):
            out["is_proxy"] = True
        elif "compromised" in tl:
            out["is_malicious"] = True
        elif tl in ("hosting", "datacenter"):
            out["is_datacenter"] = True

    if isinstance(entry.get("risk"), (int, float)):
        out["proxycheck_risk"] = int(entry["risk"])
        if entry["risk"] >= 66:
            out["is_malicious"] = True

    if entry.get("provider"):
        out["proxycheck_provider"] = entry["provider"]
    if entry.get("organisation"):
        out["proxycheck_org"] = entry["organisation"]
    if entry.get("asn"):
        out["asn"] = entry["asn"]
    if entry.get("isocode"):
        out["country"] = entry["isocode"]
    if entry.get("city"):
        out["city"] = entry["city"]
    if entry.get("hostname"):
        out["hostname"] = entry["hostname"]
    return out


async def _fetch_otx(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    AlienVault OTX — community endpoint works without a key for `general`.
    OTX_API_KEY (optional) raises rate limits + unlocks private pulses.
    """
    if not await _rate_acquire("otx"):
        return {}
    headers: dict[str, str] = {"Accept": "application/json"}
    api_key = os.environ.get("OTX_API_KEY")
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=_DEEP_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json() or {}
    except Exception as exc:
        logger.debug("otx error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "otx"}
    if data.get("country_name"):
        out["country"] = data.get("country_code") or data["country_name"]
    if data.get("asn"):
        # OTX returns "AS15169 GOOGLE - ..."
        m = _ASN_RE.match(data["asn"])
        if m:
            out["asn"] = m.group(1)
            if not out.get("org"):
                out["org"] = m.group(2)

    pulse_info = data.get("pulse_info") or {}
    count = int(pulse_info.get("count") or 0)
    out["otx_pulse_count"] = count
    pulses = pulse_info.get("pulses") or []

    top_pulses: list[dict] = []
    adversaries: set[str] = set()
    malware_families: set[str] = set()
    for p in pulses[:15]:
        if p.get("adversary"):
            adversaries.add(p["adversary"])
        for mf in p.get("malware_families") or []:
            if isinstance(mf, dict) and mf.get("display_name"):
                malware_families.add(mf["display_name"])
            elif isinstance(mf, str):
                malware_families.add(mf)
        if len(top_pulses) < 3:
            top_pulses.append({
                "name": p.get("name") or "unnamed",
                "adversary": p.get("adversary") or None,
                "tags": (p.get("tags") or [])[:5],
                "references_count": len(p.get("references") or []),
                "id": p.get("id"),
            })
    out["otx_pulses"] = top_pulses
    out["otx_adversaries"] = sorted(adversaries)
    out["otx_malware_families"] = sorted(malware_families)
    if isinstance(data.get("reputation"), (int, float)):
        out["otx_reputation"] = int(data["reputation"])
    if count > 0:
        out["is_malicious"] = True
    return out


async def _fetch_virustotal(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    VirusTotal v3 — requires VIRUSTOTAL_API_KEY. 4 req/min, 500/day free tier.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {}
    if not await _rate_acquire("virustotal"):
        logger.debug("virustotal rate limit skip for %s", ip)
        return {}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=_DEEP_TIMEOUT,
        )
        r.raise_for_status()
        data = (r.json() or {}).get("data") or {}
    except Exception as exc:
        logger.debug("virustotal error for %s: %s", ip, exc)
        return {}

    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    votes = attrs.get("total_votes") or {}
    out: dict[str, Any] = {"_provider": "virustotal"}
    out["vt_malicious_count"] = int(stats.get("malicious") or 0)
    out["vt_suspicious_count"] = int(stats.get("suspicious") or 0)
    out["vt_harmless_count"] = int(stats.get("harmless") or 0)
    out["vt_undetected_count"] = int(stats.get("undetected") or 0)
    if isinstance(attrs.get("reputation"), (int, float)):
        out["vt_reputation"] = int(attrs["reputation"])
    out["vt_total_votes"] = {
        "harmless": int(votes.get("harmless") or 0),
        "malicious": int(votes.get("malicious") or 0),
    }
    if attrs.get("country"):
        out["country"] = attrs["country"]
    if attrs.get("network"):
        out["vt_network"] = attrs["network"]
    if attrs.get("as_owner"):
        out["org"] = attrs["as_owner"]
    if attrs.get("asn"):
        out["asn"] = f"AS{attrs['asn']}"
    out["vt_link"] = f"https://www.virustotal.com/gui/ip-address/{ip}"
    if out["vt_malicious_count"] >= 1:
        out["is_malicious"] = True
    return out


async def _fetch_ipinfo_lite(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    IPInfo.io Lite — endpoint `https://api.ipinfo.io/lite/<ip>?token=...`.
    Probed 2026-05-27: returns 403 "Unknown token" without a token. The
    "no-auth generous free" assumption in the spec did NOT hold; we treat
    this as auth-required and skip silently when IPINFO_LITE_TOKEN is unset.
    """
    token = os.environ.get("IPINFO_LITE_TOKEN") or os.environ.get("IPINFO_TOKEN")
    if not token:
        return {}
    try:
        r = await client.get(
            f"https://api.ipinfo.io/lite/{ip}",
            params={"token": token},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json() or {}
    except Exception as exc:
        logger.debug("ipinfo_lite error for %s: %s", ip, exc)
        return {}

    out: dict[str, Any] = {"_provider": "ipinfo_lite"}
    if data.get("country"):
        out["country"] = data["country"]
    if data.get("country_code"):
        out["country"] = data["country_code"]
    if data.get("continent"):
        out["ipinfo_lite_continent"] = data["continent"]
    if data.get("asn"):
        out["asn"] = data["asn"] if str(data["asn"]).startswith("AS") else f"AS{data['asn']}"
    if data.get("as_name"):
        out["org"] = data["as_name"]
    if data.get("as_domain"):
        out["ipinfo_lite_as_domain"] = data["as_domain"]
    # Privacy fields (if returned by lite tier)
    for k in ("vpn", "proxy", "tor", "relay", "hosting"):
        if data.get(k) is True:
            out[f"is_{k}" if k != "relay" else "is_proxy"] = True
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
                  "is_malicious", "is_scanner", "is_known_service", "is_abuser",
                  "is_crawler", "is_hosting",
                  "risk_score")

# Precedence per provider: lower index wins for scalar merge.
# Sources with paid/curated abuse data outrank generic geo aggregators.
_ORDER = {
    "ipapi_is": 0,     # highest-fidelity abuse + tor/vpn flags (curated)
    "proxycheck": 1,   # commercial proxy-type taxonomy
    "ipquery": 2,
    "ipinfo": 3,
    "ipapi": 4,
    "geojs": 5,
    "ipguide": 6,
    "ipinfo_lite": 7,
    "greynoise": 8,
    "otx": 9,
    "shodan": 10,
    "abuseipdb": 11,
    "virustotal": 12,
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
    _EXTRA_PREFIXES = (
        "greynoise_", "shodan_", "abuseipdb_",
        "ipapi_is_", "proxycheck_", "otx_", "vt_", "ipinfo_lite_",
    )
    for r in valid:
        for k, v in r.items():
            if k.startswith(_EXTRA_PREFIXES):
                # Last writer wins; valid list is already sorted by precedence
                # but extras are namespaced per-provider so collisions are rare.
                if k not in merged or merged[k] in (None, [], {}):
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


_CLOUD_TAGS = {
    "cloud", "aws", "amazon", "azure", "gcp", "google",
    "digitalocean", "ovh", "hetzner", "linode", "vultr",
    "alibaba", "tencent", "oracle",
}


def _consensus_risk(merged: dict, tor_match: bool, spamhaus_match: bool) -> int:
    """
    Aggregate per-provider risk signals into a single 0-100 score.

    Strategy: collect every available risk signal on a 0-100 scale and take
    the MAX. This avoids the previous UI behaviour where a single provider's
    score (often 0 from ipquery for known clouds) overrode everything else.
    """
    signals: list[float] = []

    # ipquery / ipapi.is style numeric risk_score (already 0-100 in our schema)
    rs = merged.get("risk_score")
    if isinstance(rs, (int, float)) and rs >= 0:
        signals.append(float(rs))

    # proxycheck.io 0-100
    pc_risk = merged.get("proxycheck_risk")
    if isinstance(pc_risk, (int, float)):
        signals.append(float(pc_risk))

    # ipapi.is abuse_score (0..1) -> 0..100
    abuse_score = merged.get("ipapi_is_abuse_score")
    if isinstance(abuse_score, (int, float)) and abuse_score > 0:
        signals.append(min(100.0, float(abuse_score) * 100.0))

    # AbuseIPDB confidence 0-100
    aip = merged.get("abuseipdb_score")
    if isinstance(aip, (int, float)) and aip > 0:
        signals.append(float(aip))

    # VirusTotal malicious engines ratio
    vt_mal = merged.get("vt_malicious_count") or 0
    vt_total = (
        (merged.get("vt_total_engines") or 0)
        or (merged.get("vt_malicious_count") or 0)
        + (merged.get("vt_harmless_count") or 0)
        + (merged.get("vt_undetected_count") or 0)
        + (merged.get("vt_suspicious_count") or 0)
    )
    if vt_mal > 0 and vt_total > 0:
        signals.append(min(100.0, (vt_mal / vt_total) * 100.0))
    elif vt_mal > 0:
        signals.append(min(95.0, 60.0 + vt_mal * 5))

    # Tor exit (live list or provider flag) → 90 baseline (de-facto high risk
    # for services that don't expect Tor traffic).
    if tor_match or merged.get("is_tor"):
        signals.append(90.0)

    # GreyNoise classification
    gn_cls = (merged.get("greynoise_classification") or "").lower()
    if gn_cls == "malicious":
        signals.append(95.0)
    elif gn_cls == "suspicious":
        signals.append(70.0)

    # OTX pulses
    otx = merged.get("otx_pulse_count") or 0
    if otx > 0:
        signals.append(min(95.0, 60.0 + otx * 5.0))

    # Internal external_feeds matches
    feeds = merged.get("external_feeds") or []
    if feeds:
        signals.append(80.0)

    # Spamhaus DROP list
    if spamhaus_match:
        signals.append(95.0)

    # ipapi.is is_abuser
    if merged.get("is_abuser"):
        signals.append(75.0)

    if not signals:
        return 0
    return int(round(max(signals)))


def _confidence_additive(merged: dict, tor_match: bool, asn_rep: dict) -> dict:
    """
    Additive per-flag confidence (0..1 clamped) computed independently from
    the vote-aggregator used for classification. Result is merged via max()
    into the existing `confidence` dict so labels stay stable but the UI sees
    accurate strength of evidence for each axis.

    Datacenter votes:
      - any provider's is_datacenter=true  → +0.4 each (cap +0.7 from providers)
      - Shodan tags include known cloud    → +0.3
      - ASN reputation tag in {cloud,hosting,datacenter} → +0.3
      - Hostname matches DC regex          → +0.2
    """
    out: dict[str, float] = {"tor": 0.0, "vpn": 0.0, "proxy": 0.0,
                              "datacenter": 0.0, "attacker": 0.0}

    # --- Datacenter -------------------------------------------------------
    dc_from_providers = 0.0
    if merged.get("is_datacenter"):
        dc_from_providers += 0.4
    # ipapi.is + proxycheck both report is_datacenter; treat their explicit
    # type='hosting' as an extra provider vote.
    if (merged.get("proxycheck_type") or "").lower() in ("hosting", "datacenter"):
        dc_from_providers += 0.4
    if merged.get("ipapi_is_datacenter") is True:
        dc_from_providers += 0.4
    out["datacenter"] += min(0.7, dc_from_providers)

    shodan_tags = {(t or "").lower() for t in (merged.get("shodan_tags") or [])}
    if shodan_tags & _CLOUD_TAGS:
        out["datacenter"] += 0.3

    asn_tag = (asn_rep.get("asn_reputation_tag") or "").lower()
    if asn_tag in {"cloud", "hosting", "datacenter"}:
        out["datacenter"] += 0.3

    # Owner string (e.g. "Alibaba (US) Technology Co., Ltd.") — additional
    # signal beyond hostname regex.
    owner_blob = " ".join(str(x).lower() for x in (
        merged.get("asn_reputation_owner") or "",
        merged.get("org") or "",
    ))
    if any(k in owner_blob for k in (
        "amazon", "aws", "google", "microsoft", "azure", "alibaba", "tencent",
        "digitalocean", "ovh", "hetzner", "linode", "vultr", "oracle",
        "cloudflare", "fastly",
    )):
        out["datacenter"] += 0.3

    host_flags = _hostname_flags(merged.get("hostname"))
    if host_flags.get("host_dc_hint"):
        out["datacenter"] += 0.2

    # --- Tor --------------------------------------------------------------
    if tor_match:
        out["tor"] = 1.0
    elif merged.get("is_tor"):
        out["tor"] += 0.7
    if (merged.get("proxycheck_type") or "").lower() == "tor":
        out["tor"] += 0.5
    if host_flags.get("host_tor_hint"):
        out["tor"] += 0.2
    if asn_tag == "tor":
        out["tor"] += 0.5

    # --- VPN --------------------------------------------------------------
    if merged.get("is_vpn"):
        out["vpn"] += 0.5
    if (merged.get("proxycheck_type") or "").lower() == "vpn":
        out["vpn"] += 0.5
    if host_flags.get("host_vpn_hint"):
        out["vpn"] += 0.3

    # --- Proxy ------------------------------------------------------------
    if merged.get("is_proxy"):
        out["proxy"] += 0.5
    if (merged.get("proxycheck_type") or "").lower() in ("cgi", "public proxy", "open proxy"):
        out["proxy"] += 0.5
    if host_flags.get("host_proxy_hint"):
        out["proxy"] += 0.3

    # --- Attacker ---------------------------------------------------------
    if merged.get("is_malicious") or merged.get("is_abuser"):
        out["attacker"] += 0.4
    pc_risk = merged.get("proxycheck_risk")
    if isinstance(pc_risk, (int, float)) and pc_risk >= 66:
        out["attacker"] += 0.3
    if (merged.get("greynoise_classification") or "").lower() == "malicious":
        out["attacker"] += 0.5
    aip = merged.get("abuseipdb_score") or 0
    if isinstance(aip, (int, float)) and aip >= 50:
        out["attacker"] += 0.4
    if (merged.get("vt_malicious_count") or 0) >= 3:
        out["attacker"] += 0.3
    if (merged.get("otx_pulse_count") or 0) >= 1:
        out["attacker"] += 0.2
    if merged.get("external_feeds"):
        out["attacker"] += 0.3
    if tor_match or merged.get("is_tor"):
        # Tor exits attacking non-Tor services → moderate boost
        out["attacker"] += 0.3

    # Clamp 0..1
    return {k: round(min(1.0, v), 2) for k, v in out.items()}


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

    # ipapi.is abuse_score (0..1, curated by ipapi.is from spam/scanning reports)
    abuse_score = merged.get("ipapi_is_abuse_score")
    if isinstance(abuse_score, (int, float)) and abuse_score > 0:
        # Score >= 0.5 is "Very High"; treat as strong attacker signal
        votes_attacker += min(abuse_score * 2, 2.0)
        weight_total += 2

    # proxycheck.io explicit type
    pc_type = (merged.get("proxycheck_type") or "").lower()
    if pc_type == "vpn":
        votes_vpn += 1.5
        weight_total += 1.5
    elif pc_type == "tor":
        votes_tor += 1.5
        weight_total += 1.5
    elif pc_type in ("cgi", "public proxy", "open proxy"):
        votes_proxy += 1.5
        weight_total += 1.5
    elif "compromised" in pc_type:
        votes_attacker += 2
        weight_total += 2
    pc_risk = merged.get("proxycheck_risk")
    if isinstance(pc_risk, (int, float)) and pc_risk >= 66:
        votes_attacker += 1
        weight_total += 1

    # OTX pulses — community-curated threat indicators
    otx_count = merged.get("otx_pulse_count") or 0
    if otx_count >= 1:
        # Saturates at 20 pulses
        votes_attacker += min(otx_count / 20.0, 1.0) * 2
        weight_total += 2

    # VirusTotal malicious engines
    vt_mal = merged.get("vt_malicious_count") or 0
    if vt_mal >= 1:
        votes_attacker += min(vt_mal / 5.0, 1.0) * 2
        weight_total += 2

    # ipapi.is is_abuser flag — additional discrete boost
    if merged.get("is_abuser"):
        votes_attacker += 1
        weight_total += 1

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
    "ipapi_is": _fetch_ipapi_is,
    "proxycheck": _fetch_proxycheck,
    "ipinfo_lite": _fetch_ipinfo_lite,
}

_DEEP_FETCHERS = {
    "shodan": _fetch_shodan_internetdb,
    "abuseipdb": _fetch_abuseipdb,
    "virustotal": _fetch_virustotal,
    "otx": _fetch_otx,
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
                if name in enabled or name in ("shodan", "abuseipdb", "virustotal", "otx"):
                    tasks.append(fn(ip, client))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=12.0 if deep else 5.0,
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

        # Always: db-ip.com Lite offline lookup (no external HTTP). Backfills
        # ASN / country / region / city when online providers were slow,
        # rate-limited, or returned partial data. Source-tagged so the UI
        # can show `[algorithm:dbip_offline]`.
        try:
            from app.services.offline_geoip import lookup as _offline_lookup
            off = _offline_lookup(ip)
            if off:
                if off.get("asn") and not merged.get("asn"):
                    merged["asn"] = off["asn"]
                if off.get("asn_owner") and not merged.get("org"):
                    merged["org"] = off["asn_owner"]
                if off.get("country") and not merged.get("country"):
                    merged["country"] = off["country"]
                if off.get("region") and not merged.get("region"):
                    merged["region"] = off["region"]
                if off.get("city") and not merged.get("city"):
                    merged["city"] = off["city"]
                # Provenance: tag in providers list (used for UI badges) only
                # when we actually contributed data.
                provs = merged.setdefault("providers", [])
                if "dbip_offline" not in provs:
                    provs.append("dbip_offline")
                merged["dbip_offline_match"] = True
        except Exception as exc:
            logger.debug("offline_geoip enrichment skipped for %s: %s", ip, exc)

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

    # Internal history blocks (deep only). DB-only, parallel, 4 s budget.
    if deep:
        try:
            from app.services.ip_intel_history import (
                _ai_threat_brief,
                _external_feeds_match,
                _related_ips,
                assemble_history,
            )
            history = await assemble_history(ip, merged.get("asn"))
            merged["history"] = history

            feeds = await _external_feeds_match(ip)
            merged["external_feeds"] = feeds or []
            if feeds:
                # If a real feed lists this IP, raise the malicious vote
                merged["is_malicious"] = True

            # Synthetic offline-feed markers — surface Spamhaus DROP /
            # Emerging Threats / db-ip enrichment as source-tagged entries in
            # the same `external_feeds` list the UI already renders.
            try:
                _existing_sources = {f.get("feed") for f in merged["external_feeds"]}
                if spamhaus_match and "spamhaus_drop" not in _existing_sources:
                    merged["external_feeds"].append({
                        "feed": "spamhaus_drop",
                        "threat_type": "drop_list",
                        "confidence": 0.95,
                        "last_seen": None,
                        "tags": ["offline", "spamhaus", "algorithm:spamhaus_drop"],
                    })
            except Exception as exc:
                logger.debug("synthetic feeds error for %s: %s", ip, exc)

            related = await _related_ips(ip, merged.get("asn"))
            merged["related"] = related or {"same_subnet": [], "same_asn": []}

            # Honeypot canary captures (defensive leak detection)
            try:
                from app.database import async_session
                from app.modules.phantom.canary import canaries_for_ip
                async with async_session() as db:
                    merged["honeypot_canaries"] = await canaries_for_ip(db, ip, limit=10)
            except Exception as exc:
                logger.debug("canaries_for_ip enrichment failed: %s", exc)
                merged.setdefault("honeypot_canaries", [])
        except Exception as exc:
            logger.warning("history/feeds enrichment failed for %s: %s", ip, exc)
            merged.setdefault("history", {"incidents": {"count": 0}, "honeypot": {"total": 0},
                                          "profile": None, "actions": []})
            merged.setdefault("external_feeds", [])
            merged.setdefault("related", {"same_subnet": [], "same_asn": []})

    # Classification + confidence (always)
    label, confidence = _classify(merged, tor_match, spamhaus_match, asn_rep)
    # Additive-clamp confidence — merged via max() so existing thresholds and
    # labels (vote_aggregation) stay stable; UI just sees stronger evidence on
    # the per-flag pills when multiple datacenter/tor/etc signals coincide.
    try:
        conf_v2 = _confidence_additive(merged, tor_match, asn_rep)
        for k, v in conf_v2.items():
            confidence[k] = max(confidence.get(k, 0.0), v)
    except Exception as exc:
        logger.debug("confidence_additive failed for %s: %s", ip, exc)
    merged["classification"] = label
    merged["confidence"] = confidence
    # Consensus risk (0-100) — max across every provider's risk signal.
    try:
        merged["consensus_risk"] = _consensus_risk(merged, tor_match, spamhaus_match)
    except Exception as exc:
        logger.debug("consensus_risk failed for %s: %s", ip, exc)
        merged["consensus_risk"] = merged.get("risk_score") or 0
    merged["deep"] = deep

    # Optional AI threat brief — ONLY path where ip_intel touches an LLM.
    # Gated: deep=True AND AEGIS_AI_MODE != offline. Field omitted entirely
    # in default mode for backward compat.
    if deep:
        try:
            from app.services.ip_intel_history import _ai_threat_brief
            brief = await _ai_threat_brief(ip, merged)
            merged["ai_summary"] = brief
        except Exception as exc:
            logger.debug("ai_summary skipped for %s: %s", ip, exc)
            merged["ai_summary"] = None

    if deep:
        _deep_cache_set(ip, merged)
    else:
        _cache_set(ip, merged)
    return merged
