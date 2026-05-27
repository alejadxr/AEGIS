"""
IP Intelligence API — AEGIS

GET /api/v1/intel/ip/{ip}
  Returns enriched geolocation, ASN, risk flags, and threat info for a public IP.
  Results are cached 24h in-memory. Internal/private IPs return {"internal": True}.

Requires viewer-level auth (X-API-Key or Bearer JWT).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import AuthContext, require_viewer
from app.services.ip_intel import lookup

logger = logging.getLogger("aegis.api.intel")

# No prefix here — main.py mounts with prefix="/api/v1/intel" to avoid
# any collision with the existing intel_cloud router at "/api/v1/intel".
router = APIRouter(tags=["ip-intel"])


@router.get("/ip/{ip}")
async def get_ip_intel(
    ip: str,
    auth: AuthContext = Depends(require_viewer),
):
    """
    Enrich an attacker IP with ASN, geo, ISP, risk score, and threat flags.

    Returns a merged result from up to 3 free public providers (ipinfo.io,
    ip.guide, api.ipquery.io). Results are cached 24h per IP.

    - Private/internal IPs return `{"ip": "...", "internal": true}` (HTTP 200).
    - All provider failures return an empty-enrichment dict (HTTP 200, not 500).

    Response schema:
      ip, asn, org, country, city, region, hostname,
      is_tor, is_vpn, is_proxy, is_datacenter,
      risk_score, providers, cached, internal
    """
    # Basic format validation — catch obvious garbage before hitting providers
    ip = ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address required")

    try:
        result = await lookup(ip)
    except Exception as exc:
        logger.error("Unexpected error in ip_intel.lookup(%s): %s", ip, exc)
        raise HTTPException(status_code=500, detail="IP intel lookup failed")

    return result
