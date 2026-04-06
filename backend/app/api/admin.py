"""Admin API endpoints for attack detection and IP blocking management."""
import logging
from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import AuthContext, require_admin
from app.core.attack_detector import get_blocked_ips, unblock_ip, get_stats

logger = logging.getLogger("aegis.api.admin")

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/blocked-ips")
async def list_blocked_ips(auth: AuthContext = Depends(require_admin)):
    """List all auto-blocked IPs."""
    ips = get_blocked_ips()
    return {"blocked_ips": ips, "count": len(ips)}


@router.delete("/unblock/{ip}")
async def unblock_ip_endpoint(ip: str, auth: AuthContext = Depends(require_admin)):
    """Unblock a previously blocked IP."""
    was_blocked = unblock_ip(ip)
    if not was_blocked:
        raise HTTPException(status_code=404, detail=f"IP {ip} was not blocked")
    logger.info(f"[Admin] IP {ip} unblocked by {auth.user_id or 'api_key'}")
    return {"message": f"IP {ip} unblocked", "ip": ip}


@router.get("/detection-stats")
async def detection_stats(auth: AuthContext = Depends(require_admin)):
    """Get real-time attack detection statistics."""
    return get_stats()
