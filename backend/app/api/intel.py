"""
IP Intelligence API — AEGIS

GET /api/v1/intel/ip/{ip}
  Returns enriched geolocation, ASN, risk flags, and threat info for a public IP.
  Results are cached 24h in-memory. Internal/private IPs return {"internal": True}.

Requires viewer-level auth (X-API-Key or Bearer JWT).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.auth import AuthContext, require_viewer
from app.services.ip_intel import lookup

logger = logging.getLogger("aegis.api.intel")

# No prefix here — main.py mounts with prefix="/api/v1/intel" to avoid
# any collision with the existing intel_cloud router at "/api/v1/intel".
router = APIRouter(tags=["ip-intel"])


@router.get("/ip/{ip}")
async def get_ip_intel(
    ip: str,
    deep: bool = Query(False, description="Enable deep lookup: Shodan, Spamhaus, Tor list, ASN reputation, behavioral fingerprint from local feed, correlated sessions."),
    auth: AuthContext = Depends(require_viewer),
):
    """
    Enrich an attacker IP with ASN, geo, ISP, risk score, and threat flags.

    Default (`deep=false`): up to 6 free public providers in parallel
    (ipinfo, ipguide, ipquery, greynoise, ipapi, geojs), 24h cache.

    Deep mode (`deep=true`): adds Shodan InternetDB (open ports / tags / vulns),
    Tor exit-list ground truth, Spamhaus DROP CIDR check, ASN reputation
    table, behavioral fingerprint from local aegis-feed.jsonl, and
    cross-IP session correlation. 15-minute cache.

    - Private/internal IPs return `{"ip": "...", "internal": true}` (HTTP 200).
    - All provider failures return an empty-enrichment dict (HTTP 200, not 500).

    Response schema (additive; old fields preserved):
      ip, asn, org, country, city, region, hostname,
      is_tor, is_vpn, is_proxy, is_datacenter, is_mobile, is_malicious,
      is_scanner, is_known_service,
      risk_score, providers, cached, internal,
      classification, confidence,
      greynoise_*, shodan_* (deep), abuseipdb_* (deep & key set),
      asn_reputation_*, tor_list_match, spamhaus_match,
      behavioral (deep), correlated_sessions (deep), deep
    """
    ip = ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")

    try:
        result = await lookup(ip, deep=deep)
    except Exception as exc:
        logger.error("Unexpected error in ip_intel.lookup(%s, deep=%s): %s", ip, deep, exc)
        raise HTTPException(status_code=500, detail="IP intel lookup failed")

    return result
