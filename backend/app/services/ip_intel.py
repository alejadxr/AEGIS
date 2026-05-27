"""
IP Intelligence Enrichment Service — AEGIS v1.7

NO AI. This module is pure REST aggregation. It does NOT call OpenAI,
Anthropic, Gemini, OpenRouter, or any LLM. It does NOT pass through the
ai_manager or any AEGIS AI subsystem. Behavior is identical regardless
of AEGIS_AI_MODE (full/local/offline).

Queries free public IP-info APIs in parallel and merges results into
a normalized IPIntel dict. Results are cached in-memory for 24 hours.

Providers (configurable via AEGIS_IPINTEL_PROVIDERS env var):
  - ipinfo  : ipinfo.io/<ip>/json   — geo, hostname, org/ASN string
  - ipguide : ip.guide/<ip>         — ASN, org, network (no geo in free tier)
  - ipquery : api.ipquery.io/<ip>   — risk flags, VPN/Tor/proxy/datacenter

Safe-net filter:
  Private / loopback / link-local / multicast / Tailscale CGNAT (100.64.0.0/10)
  all return {"ip": <ip>, "internal": True} immediately.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
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
        # Unparseable → treat as internal (fail closed)
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_private:
        return True
    return any(addr in net for net in _SAFE_NETS)


# ---------------------------------------------------------------------------
# In-memory cache  {ip: (expires_at_float, result_dict)}
# ---------------------------------------------------------------------------

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 86_400.0  # 24 hours


def _cache_get(ip: str) -> dict | None:
    entry = _CACHE.get(ip)
    if entry and time.monotonic() < entry[0]:
        return entry[1]
    if entry:
        del _CACHE[ip]
    return None


def _cache_set(ip: str, result: dict) -> None:
    _CACHE[ip] = (time.monotonic() + _CACHE_TTL, result)


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------

_DEFAULT_PROVIDERS = "ipinfo,ipguide,ipquery"
_TIMEOUT = httpx.Timeout(3.0, connect=2.0)


def _enabled_providers() -> list[str]:
    raw = os.environ.get("AEGIS_IPINTEL_PROVIDERS", _DEFAULT_PROVIDERS)
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# Per-provider async fetchers — each returns a partial dict or {} on error
# ---------------------------------------------------------------------------

async def _fetch_ipinfo(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    ipinfo.io/1.1.1.1/json shape (confirmed):
      {"ip","hostname","city","region","country","loc","org","postal","timezone","anycast"}
    org is "AS13335 Cloudflare, Inc." — split with regex.
    """
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

    # Split "AS13335 Cloudflare, Inc." → asn + org
    org_raw = data.get("org", "")
    m = _ASN_RE.match(org_raw)
    if m:
        out["asn"] = m.group(1)
        out["org"] = m.group(2)
    elif org_raw:
        out["org"] = org_raw

    return out


async def _fetch_ipguide(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    ip.guide/1.1.1.1 shape (confirmed):
      {
        "ip": "1.1.1.1",
        "network": {
          "cidr": "1.1.1.0/24",
          "autonomous_system": {
            "asn": 13335,          ← integer, NOT "AS13335"
            "name": "CLOUDFLARENET - Cloudflare, Inc.",
            "organization": "Cloudflare, Inc.",
            "country": "US",
            "rir": "ARIN"
          }
        },
        "location": {"city": null, ...}   ← nulls on free tier
      }
    """
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
        # Integer → normalize to "AS13335" string
        out["asn"] = f"AS{asn_data['asn']}"
    if asn_data.get("organization"):
        out["org"] = asn_data["organization"]
    if asn_data.get("name") and not out.get("org"):
        out["org"] = asn_data["name"]

    # Location nulls in free tier — only populate if non-null
    loc = data.get("location") or {}
    if loc.get("country"):
        out["country"] = loc["country"]
    if loc.get("city"):
        out["city"] = loc["city"]

    return out


async def _fetch_ipquery(ip: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """
    api.ipquery.io/1.1.1.1 shape (confirmed):
      {
        "ip": "1.1.1.1",
        "isp": {"asn": "AS13335", "org": "Cloudflare, Inc.", "isp": "Cloudflare, Inc."},
        "location": {"country": "Australia", "country_code": "AU", "city": "Sydney",
                     "state": "New South Wales", "zipcode": "1001", ...},
        "risk": {"is_mobile": false, "is_vpn": false, "is_tor": false,
                 "is_proxy": false, "is_datacenter": true, "risk_score": 0}
      }
    """
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
    # Only set boolean fields if they're explicitly present (don't default-false unknown)
    for flag in ("is_vpn", "is_tor", "is_proxy", "is_datacenter"):
        if flag in risk:
            out[flag] = risk[flag]
    if "risk_score" in risk:
        out["risk_score"] = risk["risk_score"]

    return out


# ---------------------------------------------------------------------------
# Merge strategy: first non-None wins, provider order is ipquery → ipinfo → ipguide
# ---------------------------------------------------------------------------

_SCALAR_FIELDS = ("asn", "org", "country", "city", "region", "hostname",
                  "is_tor", "is_vpn", "is_proxy", "is_datacenter", "risk_score")


def _merge(ip: str, results: list[dict]) -> dict:
    """
    Merge partial provider dicts into a single normalized IPIntel dict.

    Merge order: ipquery → ipinfo → ipguide (first non-None wins per field).
    """
    # Sort by provider preference
    _ORDER = {"ipquery": 0, "ipinfo": 1, "ipguide": 2}
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

    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def lookup(ip: str) -> dict:
    """
    Return enriched IPIntel for a public IP.

    - Internal IPs short-circuit to {"ip": ip, "internal": True}.
    - Cache hit (24h TTL) returns immediately with "cached": True.
    - Providers are queried in parallel; failures are silently skipped.
    - If all providers fail and no cache, returns minimal dict with providers=[].
    """
    # Guard: internal / private
    if _is_internal(ip):
        return {"ip": ip, "internal": True}

    # Cache hit
    cached = _cache_get(ip)
    if cached is not None:
        return {**cached, "cached": True}

    enabled = _enabled_providers()
    _FETCHERS = {
        "ipinfo": _fetch_ipinfo,
        "ipguide": _fetch_ipguide,
        "ipquery": _fetch_ipquery,
    }

    async with httpx.AsyncClient() as client:
        tasks = [
            _FETCHERS[p](ip, client)
            for p in enabled
            if p in _FETCHERS
        ]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=4.0,
            )
        except asyncio.TimeoutError:
            logger.warning("IP intel lookup timed out for %s", ip)
            results = []

    # Filter out exceptions — treat them as empty results
    clean: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            logger.debug("Provider exception for %s: %s", ip, r)
        elif isinstance(r, dict):
            clean.append(r)

    result = _merge(ip, clean)
    _cache_set(ip, result)
    return result
