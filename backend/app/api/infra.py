import json
import os
import platform
import subprocess
import time

import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, get_auth_context, require_viewer

router = APIRouter(prefix="/infra", tags=["infra"])


def _uptime_str(boot_timestamp: float) -> str:
    """Convert boot timestamp to human-readable uptime string."""
    elapsed = time.time() - boot_timestamp
    days = int(elapsed // 86400)
    hours = int((elapsed % 86400) // 3600)
    if days > 0:
        return f"{days}d {hours}h"
    minutes = int((elapsed % 3600) // 60)
    return f"{hours}h {minutes}m"


def _pm2_uptime_str(pm_uptime_ms: int) -> str:
    """Convert PM2 pm_uptime (epoch ms) to human-readable uptime."""
    if not pm_uptime_ms:
        return "—"
    elapsed = time.time() - (pm_uptime_ms / 1000)
    if elapsed < 0:
        return "just now"
    days = int(elapsed // 86400)
    hours = int((elapsed % 86400) // 3600)
    if days > 0:
        return f"{days}d {hours}h"
    minutes = int((elapsed % 3600) // 60)
    return f"{hours}h {minutes}m"


def _get_pm2_processes() -> list[dict]:
    """Get PM2 process list via pm2 jlist."""
    try:
        env = {**os.environ, "PATH": f"/usr/local/bin:/opt/homebrew/bin:{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            ["pm2", "jlist"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            return []
        apps = json.loads(result.stdout)
        return [
            {
                "name": a.get("name", "unknown"),
                "status": a.get("pm2_env", {}).get("status", "unknown"),
                "cpu": a.get("monit", {}).get("cpu", 0),
                "mem": f"{round(a.get('monit', {}).get('memory', 0) / 1024 / 1024)}MB",
                "uptime": _pm2_uptime_str(a.get("pm2_env", {}).get("pm_uptime", 0)),
                "restarts": a.get("pm2_env", {}).get("restart_time", 0),
            }
            for a in apps
        ]
    except Exception:
        return []


@router.get("/systems")
async def get_systems(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    """Return system metrics filtered by tenant. Only the server-owner tenant sees the local server."""

    systems = []
    client = auth.client

    # --- Local server metrics (only for the primary/demo tenant that owns the server) ---
    if client and client.slug == "demo":
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        pm2_processes = _get_pm2_processes()
        service_names = [p["name"] for p in pm2_processes]

        local = {
            "name": platform.node() or "Server",
            "ip": os.environ.get("AEGIS_HOST_IP", "0.0.0.0"),
            "role": "Production",
            "status": "online",
            "cpu": round(cpu),
            "mem": round(mem.percent),
            "disk": round(disk.percent),
            "uptime": _uptime_str(psutil.boot_time()),
            "services": service_names,
            "pm2_processes": pm2_processes,
        }
        systems.append(local)

    # --- Registered endpoint agents (filtered by client_id) ---
    try:
        from app.models.endpoint_agent import EndpointAgent
        from sqlalchemy import select

        from app.models.endpoint_agent import AgentStatus
        query = select(EndpointAgent).where(EndpointAgent.status != AgentStatus.deregistered)
        if client:
            query = query.where(EndpointAgent.client_id == client.id)
        result = await db.execute(query)
        agents = result.scalars().all()
        for agent in agents:
            metrics = (agent.config or {}).get("last_metrics", {})
            _node_type = getattr(agent, "node_type", None) or "workspace"
            systems.append({
                "name": agent.hostname or "Unknown",
                "ip": agent.ip_address or "",
                "role": "Server" if _node_type == "server" else "Node Agent",
                "node_type": _node_type,
                "status": "online" if agent.status == AgentStatus.online else "offline",
                "cpu": round(metrics.get("cpu", 0)),
                "mem": round(metrics.get("mem", 0)),
                "disk": round(metrics.get("disk", 0)),
                "uptime": "",
                "services": [],
                "pm2_processes": [],
                "agent_id": str(agent.id),
                "os": agent.os_info or "",
            })
    except Exception:
        pass  # EndpointAgent table may not exist yet

    return {"systems": systems}


@router.get("/pm2")
async def get_pm2(
    _auth=Depends(require_viewer),
):
    """Return PM2 process list only."""
    return {"processes": _get_pm2_processes()}
