"""MikroTik switch health + device inventory (read-only).

GET /switch/status   -> board, version, uptime, cpu, memory, module state
GET /switch/ports    -> per-port link state, counters, device count, problems
GET /switch/devices  -> MAC inventory with vendor (offline OUI) and first/last seen

Data comes from the monitor's in-memory state (refreshed every 60s), so a
request never touches the switch. With AEGIS_SWITCH_URL unset every endpoint
answers 200 {"enabled": false}.
"""
from fastapi import APIRouter, Depends

from app.core.auth import AuthContext, require_viewer
from app.services.switch_monitor import switch_monitor

router = APIRouter(prefix="/switch", tags=["switch"])


@router.get("/status")
async def switch_status(auth: AuthContext = Depends(require_viewer)) -> dict:
    return switch_monitor.status_view()


@router.get("/ports")
async def switch_ports(auth: AuthContext = Depends(require_viewer)) -> dict:
    return switch_monitor.ports_view()


@router.get("/devices")
async def switch_devices(auth: AuthContext = Depends(require_viewer)) -> dict:
    return switch_monitor.devices_view()
