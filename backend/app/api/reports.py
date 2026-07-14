"""
AEGIS Report API Routes
GET/POST endpoints for generating and managing PDF security reports.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_viewer, require_admin
from app.services.report_generator import pdf_report_generator

logger = logging.getLogger("aegis.api.reports")

router = APIRouter(prefix="/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScheduleConfig(BaseModel):
    weekly_enabled: bool = True
    monthly_enabled: bool = True
    weekly_day: int = Field(default=0, ge=0, le=6, description="Day of week (0=Monday)")
    weekly_hour: int = Field(default=6, ge=0, le=23)
    monthly_day: int = Field(default=1, ge=1, le=28)
    monthly_hour: int = Field(default=6, ge=0, le=23)
    email_recipients: list[str] = Field(default_factory=list)
    save_to_disk: bool = True


class ScheduleResponse(BaseModel):
    status: str
    config: ScheduleConfig


class ReportHistoryEntry(BaseModel):
    id: str
    report_type: str
    generated_at: str
    filename: str
    size_bytes: int


class ReportHistoryResponse(BaseModel):
    reports: list[ReportHistoryEntry]
    total: int


# In-memory schedule config and report history (persists for the lifetime of the process).
# In production this would be stored in the database.
_schedule_config: Optional[ScheduleConfig] = None
_report_history: list[dict] = []


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _pdf_streaming_response(pdf_bytes: bytes, filename: str) -> StreamingResponse:
    """Wrap raw PDF bytes into a StreamingResponse."""
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


def _record_history(report_type: str, filename: str, size: int):
    """Track generated reports in memory."""
    import uuid

    _report_history.insert(0, {
        "id": str(uuid.uuid4()),
        "report_type": report_type,
        "generated_at": datetime.utcnow().isoformat(),
        "filename": filename,
        "size_bytes": size,
    })
    # Keep last 100 entries
    if len(_report_history) > 100:
        _report_history.pop()


class GenerateReportRequest(BaseModel):
    report_type: str = Field(
        ...,
        description="Type of report: weekly, monthly, assessment",
        pattern="^(weekly|monthly|assessment)$",
    )


class ReportTypeInfo(BaseModel):
    type: str
    name: str
    description: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/types", response_model=list[ReportTypeInfo])
async def list_report_types(
    auth: AuthContext = Depends(require_viewer),
):
    """List available report types."""
    return [
        ReportTypeInfo(
            type="weekly",
            name="Weekly Security Report",
            description="7-day summary with executive overview, vulnerabilities, incidents, and AI recommendations",
        ),
        ReportTypeInfo(
            type="monthly",
            name="Monthly Security Report",
            description="30-day comprehensive report with trend analysis and threat intelligence",
        ),
        ReportTypeInfo(
            type="assessment",
            name="Security Assessment",
            description="Full all-time security posture assessment with asset inventory and risk analysis",
        ),
    ]


@router.post("/generate")
async def generate_report(
    body: GenerateReportRequest,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate a PDF report by type. Returns the PDF as a download."""
    try:
        now = datetime.utcnow()
        if body.report_type == "weekly":
            pdf_bytes = await pdf_report_generator.generate_weekly_report(auth.client_id, db)
            filename = f"aegis_weekly_report_{now.strftime('%Y%m%d')}.pdf"
        elif body.report_type == "monthly":
            pdf_bytes = await pdf_report_generator.generate_monthly_report(auth.client_id, db)
            filename = f"aegis_monthly_report_{now.strftime('%Y%m')}.pdf"
        else:
            pdf_bytes = await pdf_report_generator.generate_assessment_report(auth.client_id, db)
            filename = f"aegis_assessment_{now.strftime('%Y%m%d')}.pdf"

        _record_history(body.report_type, filename, len(pdf_bytes))
        logger.info(f"{body.report_type.title()} report generated for client {auth.client_id}")
        return _pdf_streaming_response(pdf_bytes, filename)
    except Exception as e:
        logger.exception(f"Failed to generate {body.report_type} report: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/weekly")
async def generate_weekly_report(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate and return a weekly security report as PDF."""
    try:
        pdf_bytes = await pdf_report_generator.generate_weekly_report(
            auth.client_id, db
        )
        now = datetime.utcnow().strftime("%Y%m%d")
        filename = f"aegis_weekly_report_{now}.pdf"
        _record_history("weekly", filename, len(pdf_bytes))
        logger.info(f"Weekly report generated for client {auth.client_id}")
        return _pdf_streaming_response(pdf_bytes, filename)
    except Exception as e:
        logger.exception(f"Failed to generate weekly report: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/monthly")
async def generate_monthly_report(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate and return a monthly security report as PDF."""
    try:
        pdf_bytes = await pdf_report_generator.generate_monthly_report(
            auth.client_id, db
        )
        now = datetime.utcnow().strftime("%Y%m")
        filename = f"aegis_monthly_report_{now}.pdf"
        _record_history("monthly", filename, len(pdf_bytes))
        logger.info(f"Monthly report generated for client {auth.client_id}")
        return _pdf_streaming_response(pdf_bytes, filename)
    except Exception as e:
        logger.exception(f"Failed to generate monthly report: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/incident/{incident_id}")
async def generate_incident_report(
    incident_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate and return a PDF report for a specific incident."""
    try:
        pdf_bytes = await pdf_report_generator.generate_incident_report(
            incident_id, db, client_id=auth.client_id
        )
        filename = f"aegis_incident_{incident_id[:8]}.pdf"
        _record_history("incident", filename, len(pdf_bytes))
        logger.info(f"Incident report generated for {incident_id}")
        return _pdf_streaming_response(pdf_bytes, filename)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception(f"Failed to generate incident report: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.get("/assessment")
async def generate_assessment_report(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Generate and return a full security assessment PDF (all-time data)."""
    try:
        pdf_bytes = await pdf_report_generator.generate_assessment_report(
            auth.client_id, db
        )
        now = datetime.utcnow().strftime("%Y%m%d")
        filename = f"aegis_assessment_{now}.pdf"
        _record_history("assessment", filename, len(pdf_bytes))
        logger.info(f"Assessment report generated for client {auth.client_id}")
        return _pdf_streaming_response(pdf_bytes, filename)
    except Exception as e:
        logger.exception(f"Failed to generate assessment report: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/schedule", response_model=ScheduleResponse)
async def configure_schedule(
    config: ScheduleConfig,
    auth: AuthContext = Depends(require_admin),
):
    """
    Configure automatic report generation schedule.
    Requires admin role. The scheduler picks up this config on next tick.
    """
    global _schedule_config
    _schedule_config = config
    logger.info(
        f"Report schedule updated by {auth.email or 'api-key'}: "
        f"weekly={config.weekly_enabled}, monthly={config.monthly_enabled}"
    )
    return ScheduleResponse(status="configured", config=config)


@router.get("/schedule", response_model=ScheduleResponse)
async def get_schedule(
    auth: AuthContext = Depends(require_viewer),
):
    """Get the current report generation schedule configuration."""
    config = _schedule_config or ScheduleConfig()
    return ScheduleResponse(status="active" if _schedule_config else "default", config=config)


@router.get("/history", response_model=ReportHistoryResponse)
async def get_report_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    report_type: Optional[str] = Query(default=None),
    auth: AuthContext = Depends(require_viewer),
):
    """List previously generated reports (in-memory tracking)."""
    filtered = _report_history
    if report_type:
        filtered = [r for r in filtered if r["report_type"] == report_type]

    total = len(filtered)
    page = filtered[offset : offset + limit]

    return ReportHistoryResponse(
        reports=[ReportHistoryEntry(**r) for r in page],
        total=total,
    )
