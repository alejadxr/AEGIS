"""
Network monitoring API endpoints for AEGIS.

Provides DNS monitoring stats/threats and NDR connection/anomaly data.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.core.auth import AuthContext, require_analyst, require_viewer
from app.modules.network.dns_monitor import dns_monitor
from app.modules.network.ndr_lite import ndr_lite

router = APIRouter(prefix="/network", tags=["network"])


# --- Schemas ---

class DNSQuerySubmit(BaseModel):
    domain: str
    query_type: str = "A"
    source_ip: Optional[str] = None


class BaselineResetResponse(BaseModel):
    status: str
    message: str


# --- DNS Endpoints ---

@router.get("/dns/stats")
async def dns_stats(auth: AuthContext = Depends(require_viewer)):
    """Return DNS monitoring statistics."""
    return dns_monitor.get_stats()


@router.get("/dns/threats")
async def dns_threats(
    limit: int = Query(50, ge=1, le=500),
    auth: AuthContext = Depends(require_viewer),
):
    """Return recent DNS threats (DGA, tunneling, beaconing, etc.)."""
    return {
        "threats": dns_monitor.get_recent_threats(limit=limit),
        "total_threats": dns_monitor._stats["threats_detected"],
    }


@router.get("/dns/top-domains")
async def dns_top_domains(
    limit: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(require_viewer),
):
    """Return top queried domains by volume."""
    return {"domains": dns_monitor.get_top_queried(limit=limit)}


@router.post("/dns/submit")
async def dns_submit_query(
    body: DNSQuerySubmit,
    auth: AuthContext = Depends(require_analyst),
):
    """Submit a DNS query for analysis (for external log integrations)."""
    await dns_monitor.submit_query(
        domain=body.domain,
        query_type=body.query_type,
        source_ip=body.source_ip,
    )
    return {"status": "processed", "domain": body.domain}


# --- NDR Endpoints ---

@router.get("/connections")
async def get_connections(
    limit: int = Query(100, ge=1, le=1000),
    auth: AuthContext = Depends(require_viewer),
):
    """Return current active network connections snapshot."""
    connections = ndr_lite.get_current_connections(limit=limit)
    return {
        "connections": connections,
        "total": len(ndr_lite._current_connections),
        "returned": len(connections),
    }


@router.get("/anomalies")
async def get_anomalies(
    limit: int = Query(50, ge=1, le=500),
    auth: AuthContext = Depends(require_viewer),
):
    """Return detected network anomalies."""
    return {
        "anomalies": ndr_lite.get_recent_anomalies(limit=limit),
        "total_anomalies": ndr_lite._stats["anomalies_detected"],
    }


@router.get("/baseline")
async def get_baseline(auth: AuthContext = Depends(require_viewer)):
    """Return the current learned network baseline."""
    return ndr_lite.get_baseline()


@router.post("/baseline/reset", response_model=BaselineResetResponse)
async def reset_baseline(auth: AuthContext = Depends(require_analyst)):
    """Reset the network baseline and restart learning."""
    ndr_lite.reset_baseline()
    return BaselineResetResponse(
        status="ok",
        message="Baseline reset. Learning period restarted (24h).",
    )


@router.get("/stats")
async def network_stats(auth: AuthContext = Depends(require_viewer)):
    """Return combined network monitoring statistics (DNS + NDR)."""
    return {
        "dns": dns_monitor.get_stats(),
        "ndr": ndr_lite.get_stats(),
    }
