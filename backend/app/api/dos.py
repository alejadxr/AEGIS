"""DoS Shield read/ops API (v1.6.4.0).

Read-only surface over the ``dos_shield`` singleton for the live dashboard and
operators. Guarded by the existing viewer auth dependency (any authenticated
user), matching the pattern used by the other read-only API routers.

Routes (mounted under /api/v1 by main.py):
    GET /api/v1/dos/status     -> full dos_shield snapshot (mode, under_attack,
                                  global rps, thresholds, counters, offenders)
    GET /api/v1/dos/offenders  -> {"offenders": [...]} (top current offenders)
    GET /api/v1/dos/config     -> thresholds + {mode, netshield_enabled}

Enforcement/ops mutation endpoints (POST /mode, /netshield/*) are owned by the
contract but intentionally kept OFF this read-only surface for the monitor-first
rollout — flipping to active/netshield is a deliberate human action.
"""

from fastapi import APIRouter, Depends

from app.core.auth import AuthContext, require_viewer

router = APIRouter(prefix="/dos", tags=["dos-shield"])


def _snapshot() -> dict:
    """Read dos_shield state, tolerating either snapshot() or status()."""
    try:
        from app.services.dos_shield import dos_shield
    except Exception:  # dos_shield not present (partial deploy)
        return {
            "mode": "monitor",
            "under_attack": False,
            "global_rps": 0.0,
            "netshield_enabled": False,
            "available": False,
        }
    snap_fn = getattr(dos_shield, "snapshot", None) or getattr(
        dos_shield, "status", None
    )
    if snap_fn is None:
        return {"available": False}
    try:
        data = snap_fn()
    except Exception as exc:  # never 500 the dashboard on a snapshot glitch
        return {"available": False, "error": str(exc)}
    if not isinstance(data, dict):
        return {"available": False}
    data.setdefault("available", True)
    return data


@router.get("/status")
async def dos_status(auth: AuthContext = Depends(require_viewer)):
    """Full DoS Shield state for the live dashboard."""
    return _snapshot()


@router.get("/offenders")
async def dos_offenders(auth: AuthContext = Depends(require_viewer)):
    """Top current per-IP offenders (rps / concurrency / last reason)."""
    snap = _snapshot()
    return {"offenders": snap.get("top_offenders", [])}


@router.get("/config")
async def dos_config(auth: AuthContext = Depends(require_viewer)):
    """Live thresholds + current mode + netshield gate state."""
    snap = _snapshot()
    return {
        "thresholds": snap.get("thresholds", {}),
        "mode": snap.get("mode", "monitor"),
        "netshield_enabled": snap.get("netshield_enabled", False),
        "netshield_env_gate": snap.get("netshield_env_gate", False),
        "under_attack": snap.get("under_attack", False),
    }
