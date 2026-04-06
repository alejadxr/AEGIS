"""
SBOM (Software Bill of Materials) API endpoints for AEGIS.

Provides endpoints to trigger SBOM scans, retrieve results, list CVEs,
and export in CycloneDX format.

Router: /api/v1/sbom/*
"""

from fastapi import APIRouter, Depends, BackgroundTasks
from fastapi.responses import JSONResponse

from app.core.auth import AuthContext, require_analyst, require_viewer
from app.modules.surface.sbom import sbom_scanner

router = APIRouter(prefix="/sbom", tags=["sbom"])


# --- Routes ---


@router.get("/scan")
async def trigger_sbom_scan(
    background_tasks: BackgroundTasks,
    check_cves: bool = True,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Trigger an SBOM scan of the server.
    Detects Python (pip), Node (npm), and system packages,
    then optionally checks each against the NVD CVE database.
    """
    if sbom_scanner.is_scanning:
        return {"status": "already_running", "message": "An SBOM scan is already in progress."}

    # Run in background so the API responds immediately
    background_tasks.add_task(sbom_scanner.full_scan, check_cves)

    return {
        "status": "started",
        "message": "SBOM scan started in background. Poll /api/v1/sbom/results for updates.",
        "check_cves": check_cves,
    }


@router.get("/results")
async def get_sbom_results(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return the latest SBOM scan results.
    Includes package counts, CVE summary, and per-package details.
    """
    results = sbom_scanner.latest_results
    if results is None:
        return {
            "status": "no_scan",
            "message": "No SBOM scan has been run yet. Trigger one via GET /api/v1/sbom/scan.",
            "is_scanning": sbom_scanner.is_scanning,
        }

    # Return a summary without the full package list (which can be large)
    summary = {
        "scan_id": results.get("scan_id"),
        "scanned_at": results.get("scanned_at"),
        "total_packages": results.get("total_packages", 0),
        "packages_with_cves": results.get("packages_with_cves", 0),
        "total_cves": results.get("total_cves", 0),
        "critical_cves": results.get("critical_cves", 0),
        "high_cves": results.get("high_cves", 0),
        "is_scanning": sbom_scanner.is_scanning,
        "packages": [
            {
                "name": p["name"],
                "version": p.get("version", "unknown"),
                "source": p.get("source", "unknown"),
                "cve_count": len(p.get("cves", [])),
            }
            for p in results.get("packages", [])
        ],
    }
    return summary


@router.get("/cves")
async def get_sbom_cves(
    severity: str | None = None,
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return CVEs found in the latest SBOM scan.
    Optionally filter by severity (critical, high, medium, low).
    """
    cves = sbom_scanner.latest_cves
    if not cves:
        return {
            "total": 0,
            "cves": [],
            "message": "No CVEs found or no scan has been run.",
        }

    if severity:
        cves = [c for c in cves if c.get("severity") == severity.lower()]

    return {
        "total": len(cves),
        "cves": cves,
    }


@router.get("/export")
async def export_sbom(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Export the latest SBOM in CycloneDX JSON format.
    Returns a downloadable JSON document.
    """
    results = sbom_scanner.latest_results
    if results is None or "sbom" not in results:
        return JSONResponse(
            status_code=404,
            content={"detail": "No SBOM data available. Run a scan first."},
        )

    return JSONResponse(
        content=results["sbom"],
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="aegis-sbom.cdx.json"',
        },
    )
