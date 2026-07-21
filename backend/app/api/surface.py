from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services.scanner import scan_orchestrator
from app.services import asset_risk
from app.modules.surface.hardener import hardening_engine

router = APIRouter(prefix="/surface", tags=["surface"])


# --- Schemas ---

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"  # full, discovery, vuln


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    message: str


class ScanDetail(BaseModel):
    id: str
    target: str
    type: str
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    results: dict = {}
    assets_found: int = 0


class AssetOut(BaseModel):
    id: str
    hostname: str | None = None
    ip_address: str | None = None
    asset_type: str | None = None
    ports: list = []
    technologies: list = []
    status: str
    risk_score: float
    last_scan_at: str | None = None
    vulnerability_count: int = 0
    # service_weighted_v1 (see app.services.asset_risk) — deterministic,
    # recomputed fresh on every read so the displayed number can never drift
    # from the algorithm, even between scheduled scans.
    risk_band: str = "contained"
    risk_method: str = "service_weighted_v1"
    risk_ai_used: bool = False
    exposure: str = "unknown"
    exposure_multiplier: float = 0.6
    base_score: float = 0.0
    vuln_term: float = 0.0
    risk_drivers: list = []
    service_classes: list = []
    host_wide_count: int = 0
    owned_count: int = 0


class VulnOut(BaseModel):
    id: str
    asset_id: str
    title: str
    description: str | None = None
    severity: str
    cvss_score: float | None = None
    cve_id: str | None = None
    status: str
    ai_risk_score: float | None = None
    remediation: str | None = None
    found_at: str | None = None


class VulnUpdate(BaseModel):
    status: str  # open, remediated, accepted, false_positive


class HardenRequest(BaseModel):
    target: str
    asset_type: str = "web"


# --- Routes ---

@router.post("/scan", response_model=ScanResponse)
async def launch_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Launch a new scan against a target. Analyst or admin only."""
    client = auth.client
    result = await scan_orchestrator.launch_scan(body.target, body.scan_type, client, db)
    return ScanResponse(
        scan_id=result["id"],
        target=body.target,
        status=result["status"],
        message=f"Scan {'completed' if result['status'] == 'completed' else 'started'} for {body.target}",
    )


@router.get("/scans", response_model=list[ScanDetail])
async def list_scans(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List scans for the current tenant.

    Reads from the persisted ``scans`` table so history survives restarts
    (previously scans lived only in an in-memory dict and vanished on reboot).
    """
    scans = await scan_orchestrator.list_scans(client_id=auth.client.id, db=db)
    return [
        ScanDetail(
            id=s["id"],
            target=s["target"],
            type=s["type"],
            status=s["status"],
            started_at=s.get("started_at"),
            completed_at=s.get("completed_at"),
            results=s.get("results", {}),
            assets_found=s.get("assets_found", 0),
        )
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get scan details and results. Scoped to current tenant."""
    scan = await scan_orchestrator.get_scan(scan_id, client_id=auth.client.id, db=db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanDetail(
        id=scan["id"],
        target=scan["target"],
        type=scan["type"],
        status=scan["status"],
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        results=scan.get("results", {}),
        assets_found=scan.get("assets_found", 0),
    )


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    status: Optional[str] = None,
    asset_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List discovered assets with filtering."""
    client = auth.client
    query = select(Asset).where(Asset.client_id == client.id)
    if status:
        query = query.where(Asset.status == status)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    query = query.offset(offset).limit(limit)

    result = await db.execute(query)
    assets = result.scalars().all()

    # v1.6.3.2: single GROUP BY instead of one COUNT() per asset.
    # Eliminates 101 round-trips for a 100-asset page (now: 2).
    # v1.7.2: GROUP BY also on severity so critical/high/total are all
    # available per asset from this one round trip — needed for the
    # service_weighted_v1 vuln_term below (still just 1 query, not 3).
    asset_ids = [a.id for a in assets]
    vuln_stats: dict[str, dict[str, int]] = {}
    if asset_ids:
        agg = await db.execute(
            select(
                Vulnerability.asset_id,
                Vulnerability.severity,
                func.count(Vulnerability.id).label("cnt"),
            )
            .where(
                Vulnerability.asset_id.in_(asset_ids),
                Vulnerability.status == "open",
            )
            .group_by(Vulnerability.asset_id, Vulnerability.severity)
        )
        for row in agg.all():
            asset_id, severity, cnt = row[0], row[1], int(row[2] or 0)
            stats = vuln_stats.setdefault(asset_id, {"critical": 0, "high": 0, "total": 0})
            stats["total"] += cnt
            if severity == "critical":
                stats["critical"] += cnt
            elif severity == "high":
                stats["high"] += cnt

    # v1.7.2: one extra lightweight query for the fleet-wide port index used
    # to damp host-wide port noise (see asset_risk.build_host_index) — the
    # scanner merges whole-host nmap results into every asset sharing an IP,
    # so without this an internal dev box's 80 loopback assets all score as
    # if each one individually exposed SMB+VNC+Postgres.
    fleet_result = await db.execute(
        select(Asset.id, Asset.ip_address, Asset.hostname, Asset.ports)
        .where(Asset.client_id == client.id)
    )
    host_index = asset_risk.build_host_index(fleet_result.all())

    out = []
    for a in assets:
        stats = vuln_stats.get(a.id, {"critical": 0, "high": 0, "total": 0})
        res = asset_risk.score_asset(
            ports=a.ports or [],
            ip_address=a.ip_address,
            hostname=a.hostname,
            critical_vulns=stats["critical"],
            high_vulns=stats["high"],
            total_vulns=stats["total"],
            host_index=host_index,
        )
        out.append(AssetOut(
            id=a.id,
            hostname=a.hostname,
            ip_address=a.ip_address,
            asset_type=a.asset_type,
            ports=a.ports or [],
            technologies=a.technologies or [],
            status=a.status,
            # Freshly computed — never a.risk_score. This is what guarantees
            # the dashboard is correct without waiting for the next scan and
            # makes drift between stored/displayed values structurally
            # impossible.
            risk_score=res["risk_score"],
            risk_band=res["risk_band"],
            risk_method=res["risk_method"],
            risk_ai_used=res["risk_ai_used"],
            exposure=res["exposure"],
            exposure_multiplier=res["exposure_multiplier"],
            base_score=res["base_score"],
            vuln_term=res["vuln_term"],
            risk_drivers=res["drivers"],
            service_classes=res["service_classes"],
            host_wide_count=res["host_wide_count"],
            owned_count=res["owned_count"],
            last_scan_at=a.last_scan_at.isoformat() if a.last_scan_at else None,
            vulnerability_count=stats["total"],
        ))
    return out


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get asset details with vulnerabilities."""
    client = auth.client
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.client_id == client.id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vuln_agg = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id).label("cnt"))
        .where(
            Vulnerability.asset_id == asset.id,
            Vulnerability.status == "open",
        )
        .group_by(Vulnerability.severity)
    )
    critical_count = high_count = total_count = 0
    for severity, cnt in vuln_agg.all():
        cnt = int(cnt or 0)
        total_count += cnt
        if severity == "critical":
            critical_count += cnt
        elif severity == "high":
            high_count += cnt

    # Same host index treatment as list_assets — damping needs fleet context.
    fleet_result = await db.execute(
        select(Asset.id, Asset.ip_address, Asset.hostname, Asset.ports)
        .where(Asset.client_id == client.id)
    )
    host_index = asset_risk.build_host_index(fleet_result.all())

    res = asset_risk.score_asset(
        ports=asset.ports or [],
        ip_address=asset.ip_address,
        hostname=asset.hostname,
        critical_vulns=critical_count,
        high_vulns=high_count,
        total_vulns=total_count,
        host_index=host_index,
    )

    return AssetOut(
        id=asset.id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        asset_type=asset.asset_type,
        ports=asset.ports or [],
        technologies=asset.technologies or [],
        status=asset.status,
        risk_score=res["risk_score"],
        risk_band=res["risk_band"],
        risk_method=res["risk_method"],
        risk_ai_used=res["risk_ai_used"],
        exposure=res["exposure"],
        exposure_multiplier=res["exposure_multiplier"],
        base_score=res["base_score"],
        vuln_term=res["vuln_term"],
        risk_drivers=res["drivers"],
        service_classes=res["service_classes"],
        host_wide_count=res["host_wide_count"],
        owned_count=res["owned_count"],
        last_scan_at=asset.last_scan_at.isoformat() if asset.last_scan_at else None,
        vulnerability_count=total_count,
    )


@router.get("/vulnerabilities", response_model=list[VulnOut])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerabilities with filtering by severity."""
    client = auth.client
    query = select(Vulnerability).where(Vulnerability.client_id == client.id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    query = query.order_by(Vulnerability.found_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    vulns = result.scalars().all()

    return [
        VulnOut(
            id=v.id,
            asset_id=v.asset_id,
            title=v.title,
            description=v.description,
            severity=v.severity,
            cvss_score=v.cvss_score,
            cve_id=v.cve_id,
            status=v.status,
            ai_risk_score=v.ai_risk_score,
            remediation=v.remediation,
            found_at=v.found_at.isoformat() if v.found_at else None,
        )
        for v in vulns
    ]


@router.patch("/vulnerabilities/{vuln_id}", response_model=VulnOut)
async def update_vulnerability(
    vuln_id: str,
    body: VulnUpdate,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update vulnerability status. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.id == vuln_id,
            Vulnerability.client_id == client.id,
        )
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = body.status
    if body.status == "remediated":
        from datetime import datetime
        vuln.remediated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(vuln)

    return VulnOut(
        id=vuln.id,
        asset_id=vuln.asset_id,
        title=vuln.title,
        description=vuln.description,
        severity=vuln.severity,
        cvss_score=vuln.cvss_score,
        cve_id=vuln.cve_id,
        status=vuln.status,
        ai_risk_score=vuln.ai_risk_score,
        remediation=vuln.remediation,
        found_at=vuln.found_at.isoformat() if vuln.found_at else None,
    )


@router.post("/harden")
async def run_hardening(
    body: HardenRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Get auto-hardening recommendations for a target. Analyst or admin only."""
    recommendations = await hardening_engine.get_recommendations({
        "hostname": body.target,
        "asset_type": body.asset_type,
    })
    checklist = hardening_engine.generate_hardening_checklist(body.asset_type)
    return {
        "target": body.target,
        "asset_type": body.asset_type,
        "ai_recommendations": recommendations,
        "checklist": checklist,
    }
