"""Setup wizard API endpoints for AEGIS.

Provides auto-discovery, batch asset registration, AI-assisted
configuration, setup status, and dependency checking.
"""

import asyncio
import logging
import shutil
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.database import get_db
from app.core.auth import AuthContext, require_admin, require_viewer
from app.models.asset import Asset
from app.models.user import User
from app.services.auto_discovery import auto_discovery, DiscoveredService
from app.services.ai_configurator import ai_configurator

logger = logging.getLogger("aegis.setup")

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/setup", tags=["setup"])


# ---------------------------------------------------------------------------
# In-memory scan store (background scans)
# ---------------------------------------------------------------------------

_background_scans: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DiscoverRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=200, description="IP address or CIDR range")


class DiscoverResponse(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    message: str


class DiscoveredServiceOut(BaseModel):
    port: int
    service: str
    version: str
    hostname: str
    asset_type: str
    risk_estimate: int
    technologies: list[str] = []


class DiscoverResultResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    scan_time_ms: int = 0
    services: list[DiscoveredServiceOut] = []
    error: Optional[str] = None


class AssetRegisterItem(BaseModel):
    hostname: str = Field(..., max_length=500)
    ip: str = Field("", max_length=45)
    asset_type: str = Field("server", max_length=50)
    ports: list[int] = []
    technologies: list[str] = []


class RegisterAssetsRequest(BaseModel):
    assets: list[AssetRegisterItem] = Field(..., min_length=1, max_length=500)


class RegisteredAssetOut(BaseModel):
    id: str
    hostname: str
    ip: str
    asset_type: str


class RegisterAssetsResponse(BaseModel):
    created: int
    assets: list[RegisteredAssetOut]


class AIConfigureRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    context: str = Field("setup", max_length=50)


class AIConfigureAction(BaseModel):
    type: str
    key: Optional[str] = None
    value: Optional[object] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    asset_type: Optional[str] = None
    honeypot_type: Optional[str] = None
    port: Optional[int] = None
    provider: Optional[str] = None


class AIConfigureResponse(BaseModel):
    understood: str
    actions: list[dict]
    applied: bool
    error: Optional[str] = None


class SetupStatusResponse(BaseModel):
    setup_completed: bool
    has_admin: bool
    has_assets: bool
    has_ai_provider: bool


class ToolStatus(BaseModel):
    name: str
    available: bool
    path: Optional[str] = None
    version: Optional[str] = None
    install_hint: Optional[str] = None


class InstallDepsResponse(BaseModel):
    tools: list[ToolStatus]
    all_available: bool


# ---------------------------------------------------------------------------
# Background scan task
# ---------------------------------------------------------------------------

async def _run_discovery_scan(scan_id: str, target: str) -> None:
    """Run nmap discovery in the background and store results."""
    _background_scans[scan_id]["status"] = "running"

    try:
        # Determine scan method
        if "/" in target:
            result = await auto_discovery.discover_network(target)
        else:
            result = await auto_discovery.discover_host(target)

        # Flatten all services from all hosts
        services: list[dict] = []
        for host in result.hosts:
            for svc in host.services:
                services.append({
                    "port": svc.port,
                    "service": svc.service,
                    "version": svc.version,
                    "hostname": svc.hostname,
                    "asset_type": svc.asset_type,
                    "risk_estimate": svc.risk_estimate,
                    "technologies": svc.technologies,
                })

        _background_scans[scan_id].update({
            "status": "completed" if not result.error else "failed",
            "target": result.target,
            "scan_time_ms": result.scan_time_ms,
            "services": services,
            "error": result.error,
            "completed_at": datetime.utcnow().isoformat(),
        })

    except Exception as exc:
        logger.error(f"Background scan {scan_id} failed: {exc}")
        _background_scans[scan_id].update({
            "status": "failed",
            "error": str(exc),
            "completed_at": datetime.utcnow().isoformat(),
        })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/discover", response_model=DiscoverResponse, status_code=202)
@limiter.limit("3/minute")
async def discover_services(
    request: Request,
    body: DiscoverRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_admin),
):
    """Launch an nmap auto-discovery scan against a target IP or CIDR range.

    The scan runs in the background.  Poll GET /setup/discover/{scan_id}
    for results.
    """
    scan_id = f"disc_{uuid.uuid4().hex[:12]}"

    _background_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "target": body.target,
        "scan_time_ms": 0,
        "services": [],
        "error": None,
        "started_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(_run_discovery_scan, scan_id, body.target)

    return DiscoverResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Discovery scan queued for {body.target}. Poll /setup/discover/{scan_id} for results.",
    )


@router.get("/discover/{scan_id}", response_model=DiscoverResultResponse)
async def get_discover_result(
    scan_id: str,
    auth: AuthContext = Depends(require_viewer),
):
    """Poll for discovery scan results."""
    scan = _background_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return DiscoverResultResponse(
        scan_id=scan["scan_id"],
        status=scan["status"],
        target=scan["target"],
        scan_time_ms=scan.get("scan_time_ms", 0),
        services=[
            DiscoveredServiceOut(**svc) for svc in scan.get("services", [])
        ],
        error=scan.get("error"),
    )


@router.get("/discover", response_model=list[DiscoverResultResponse])
async def list_discover_scans(
    auth: AuthContext = Depends(require_viewer),
):
    """List all discovery scans."""
    return [
        DiscoverResultResponse(
            scan_id=scan["scan_id"],
            status=scan["status"],
            target=scan["target"],
            scan_time_ms=scan.get("scan_time_ms", 0),
            services=[
                DiscoveredServiceOut(**svc) for svc in scan.get("services", [])
            ],
            error=scan.get("error"),
        )
        for scan in _background_scans.values()
    ]


@router.post("/register-assets", response_model=RegisterAssetsResponse, status_code=201)
async def register_assets(
    body: RegisterAssetsRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Batch register discovered assets into the database."""
    client = auth.client
    created_assets: list[RegisteredAssetOut] = []

    for item in body.assets:
        # Calculate risk score from ports/services instead of leaving at 0
        risk = 0.0
        port_objects: list[dict] = []
        for p in item.ports:
            _, friendly = auto_discovery.identify_service(p, "")
            port_objects.append({"port": p, "service": friendly})
            port_risk = auto_discovery.estimate_risk(friendly, p, "")
            if port_risk > risk:
                risk = port_risk

        # Scale from 0-100 to 0-10 for display
        risk_score = round(risk / 10.0, 1)

        asset = Asset(
            client_id=client.id,
            hostname=item.hostname,
            ip_address=item.ip,
            asset_type=item.asset_type,
            ports=port_objects,
            technologies=item.technologies,
            status="active",
            risk_score=risk_score,
            last_scan_at=datetime.utcnow(),
        )
        db.add(asset)
        await db.flush()

        created_assets.append(RegisteredAssetOut(
            id=asset.id,
            hostname=asset.hostname or "",
            ip=asset.ip_address or "",
            asset_type=asset.asset_type or "server",
        ))

    await db.commit()
    logger.info(f"Registered {len(created_assets)} assets for client {client.id}")

    return RegisterAssetsResponse(
        created=len(created_assets),
        assets=created_assets,
    )


@router.post("/ai-configure", response_model=AIConfigureResponse)
async def ai_configure(
    body: AIConfigureRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """AI-assisted configuration via natural language.

    The AI interprets the user's request and maps it to allowed
    configuration actions.  Actions are validated against a strict
    whitelist before being applied.
    """
    client = auth.client
    client_settings = client.settings or {}

    result = await ai_configurator.configure(
        question=body.question,
        client_id=client.id,
        client_settings=client_settings,
        db=db,
    )

    return AIConfigureResponse(
        understood=result.get("understood", ""),
        actions=result.get("actions", []),
        applied=result.get("applied", False),
        error=result.get("error"),
    )


@router.get("/status", response_model=SetupStatusResponse)
async def setup_status(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Check whether the initial setup has been completed.

    Returns booleans indicating which setup steps are done:
    - has_admin: at least one admin user exists
    - has_assets: at least one asset has been registered
    - has_ai_provider: an OpenRouter API key is configured
    - setup_completed: all of the above are true
    """
    client = auth.client

    # Check for admin user
    has_admin = False
    try:
        admin_count = await db.scalar(
            select(func.count(User.id)).where(
                User.client_id == client.id,
                User.role == "admin",
                User.is_active == True,
            )
        )
        has_admin = (admin_count or 0) > 0
    except Exception:
        # If the query fails (e.g. enum comparison issue), check any user
        user_count = await db.scalar(select(func.count(User.id)))
        has_admin = (user_count or 0) > 0

    # Check for assets
    asset_count = await db.scalar(
        select(func.count(Asset.id)).where(Asset.client_id == client.id)
    ) or 0
    has_assets = asset_count > 0

    # Check for AI provider
    has_ai_provider = bool(settings.OPENROUTER_API_KEY)
    # Also check client-level key
    client_key = (client.settings or {}).get("ai_keys", {}).get("openrouter", "")
    if client_key:
        has_ai_provider = True

    setup_completed = has_admin and has_assets and has_ai_provider

    return SetupStatusResponse(
        setup_completed=setup_completed,
        has_admin=has_admin,
        has_assets=has_assets,
        has_ai_provider=has_ai_provider,
    )


@router.post("/install-deps", response_model=InstallDepsResponse)
async def check_install_deps(
    auth: AuthContext = Depends(require_admin),
):
    """Check which security tools are available and report their versions.

    Does NOT install anything -- only reports what is present and suggests
    install commands for missing tools.
    """
    tools_to_check = [
        {
            "name": "nmap",
            "config_path": settings.NMAP_PATH,
            "install_hint": "brew install nmap (macOS) | apt install nmap (Linux)",
        },
        {
            "name": "nuclei",
            "config_path": settings.NUCLEI_PATH,
            "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        {
            "name": "subfinder",
            "config_path": settings.SUBFINDER_PATH,
            "install_hint": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
        {
            "name": "httpx",
            "config_path": settings.HTTPX_PATH,
            "install_hint": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
    ]

    results: list[ToolStatus] = []

    for tool in tools_to_check:
        name = tool["name"]
        # Try config path first, then search PATH
        found_path = None
        for candidate in [tool["config_path"], f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"/opt/homebrew/bin/{name}"]:
            if shutil.which(candidate):
                found_path = candidate
                break
        if not found_path:
            found_path = shutil.which(name)

        version_str = None
        if found_path:
            try:
                proc = await asyncio.create_subprocess_exec(
                    found_path, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                version_str = (stdout or stderr).decode(errors="replace").strip().split("\n")[0][:200]
            except Exception:
                version_str = "installed (version unknown)"

        results.append(ToolStatus(
            name=name,
            available=found_path is not None,
            path=found_path,
            version=version_str,
            install_hint=tool["install_hint"] if not found_path else None,
        ))

    return InstallDepsResponse(
        tools=results,
        all_available=all(t.available for t in results),
    )
