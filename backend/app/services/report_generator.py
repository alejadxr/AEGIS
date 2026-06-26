"""
AEGIS PDF Report Generator
Generates professional security reports with branded styling, tables, charts,
and AI-generated recommendations via OpenRouter.
"""

import io
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String as DrawingString, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.core.ai_mode import degrade_or_call
from app.models.asset import Asset
from app.models.client import Client
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.action import Action
from app.models.honeypot import Honeypot, HoneypotInteraction
from app.models.threat_intel import ThreatIntel
from app.models.attacker_profile import AttackerProfile

logger = logging.getLogger("aegis.report_generator")

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
AEGIS_DARK = colors.HexColor("#0A0E1A")
AEGIS_CYAN = colors.HexColor("#00F0FF")
AEGIS_BLUE = colors.HexColor("#1E40AF")
AEGIS_GREY = colors.HexColor("#1F2937")
AEGIS_LIGHT = colors.HexColor("#F9FAFB")
AEGIS_WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}

STATUS_COLORS = {
    "open": colors.HexColor("#DC2626"),
    "investigating": colors.HexColor("#D97706"),
    "contained": colors.HexColor("#2563EB"),
    "resolved": colors.HexColor("#16A34A"),
    "closed": colors.HexColor("#6B7280"),
}


# ---------------------------------------------------------------------------
# Custom styles
# ---------------------------------------------------------------------------

def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=36,
        leading=42,
        textColor=AEGIS_CYAN,
        alignment=TA_CENTER,
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontSize=16,
        leading=20,
        textColor=AEGIS_LIGHT,
        alignment=TA_CENTER,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=AEGIS_CYAN,
        spaceBefore=20,
        spaceAfter=10,
        borderWidth=1,
        borderColor=AEGIS_CYAN,
        borderPadding=4,
    ))
    styles.add(ParagraphStyle(
        "SubSection",
        parent=styles["Heading2"],
        fontSize=14,
        leading=17,
        textColor=AEGIS_BLUE,
        spaceBefore=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#374151"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SmallGrey",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#9CA3AF"),
    ))
    styles.add(ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#111827"),
    ))
    styles.add(ParagraphStyle(
        "Metric",
        parent=styles["Normal"],
        fontSize=24,
        leading=28,
        textColor=AEGIS_CYAN,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "MetricLabel",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#6B7280"),
        alignment=TA_CENTER,
    ))

    return styles


# ---------------------------------------------------------------------------
# Helper: severity pie chart as Drawing
# ---------------------------------------------------------------------------

def _severity_pie_chart(severity_counts: dict, width=280, height=200) -> Drawing:
    """Return a Drawing with a severity distribution pie chart."""
    d = Drawing(width, height)
    pie = Pie()
    pie.x = 60
    pie.y = 20
    pie.width = 140
    pie.height = 140

    labels = []
    data = []
    slice_colors = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count > 0:
            labels.append(f"{sev.title()} ({count})")
            data.append(count)
            slice_colors.append(SEVERITY_COLORS.get(sev, colors.grey))

    if not data:
        data = [1]
        labels = ["No Data"]
        slice_colors = [colors.grey]

    pie.data = data
    pie.labels = labels
    pie.sideLabels = True
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white

    for i, c in enumerate(slice_colors):
        pie.slices[i].fillColor = c

    d.add(pie)
    return d


def _bar_chart(categories: list, values: list, width=400, height=180) -> Drawing:
    """Return a Drawing with a vertical bar chart."""
    d = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x = 50
    bc.y = 30
    bc.height = height - 60
    bc.width = width - 80
    bc.data = [values]
    bc.categoryAxis.categoryNames = categories
    bc.categoryAxis.labels.angle = 30
    bc.categoryAxis.labels.fontSize = 7
    bc.valueAxis.valueMin = 0
    bc.bars[0].fillColor = AEGIS_CYAN
    bc.bars[0].strokeColor = None
    d.add(bc)
    return d


# ---------------------------------------------------------------------------
# Page decoration callbacks
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc):
    """Draw header line and footer with page number on every page."""
    canvas.saveState()
    w, h = letter

    # Header line
    canvas.setStrokeColor(AEGIS_CYAN)
    canvas.setLineWidth(0.5)
    canvas.line(40, h - 40, w - 40, h - 40)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#6B7280"))
    canvas.drawString(40, h - 36, "AEGIS DEFENSE PLATFORM")
    canvas.drawRightString(w - 40, h - 36, "CONFIDENTIAL")

    # Footer
    canvas.setStrokeColor(AEGIS_CYAN)
    canvas.line(40, 40, w - 40, 40)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#9CA3AF"))
    canvas.drawString(40, 28, f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawRightString(w - 40, 28, f"Page {doc.page}")

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Data fetching helpers
# ---------------------------------------------------------------------------

async def _fetch_client(client_id: str, db: AsyncSession) -> Optional[Client]:
    result = await db.execute(select(Client).where(Client.id == client_id))
    return result.scalar_one_or_none()


async def _fetch_assets(client_id: str, db: AsyncSession) -> list[Asset]:
    result = await db.execute(
        select(Asset).where(Asset.client_id == client_id).order_by(Asset.risk_score.desc())
    )
    return list(result.scalars().all())


async def _fetch_vulns(
    client_id: str, db: AsyncSession, since: Optional[datetime] = None
) -> list[Vulnerability]:
    q = select(Vulnerability).where(Vulnerability.client_id == client_id)
    if since:
        q = q.where(Vulnerability.found_at >= since)
    q = q.order_by(Vulnerability.found_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


async def _fetch_incidents(
    client_id: str, db: AsyncSession, since: Optional[datetime] = None
) -> list[Incident]:
    q = select(Incident).where(Incident.client_id == client_id)
    if since:
        q = q.where(Incident.detected_at >= since)
    q = q.order_by(Incident.detected_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


async def _fetch_actions(
    client_id: str, db: AsyncSession, since: Optional[datetime] = None
) -> list[Action]:
    q = select(Action).where(Action.client_id == client_id)
    if since:
        q = q.where(Action.created_at >= since)
    q = q.order_by(Action.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


async def _fetch_honeypot_interactions(
    client_id: str, db: AsyncSession, since: Optional[datetime] = None
) -> list[HoneypotInteraction]:
    q = select(HoneypotInteraction).where(HoneypotInteraction.client_id == client_id)
    if since:
        q = q.where(HoneypotInteraction.timestamp >= since)
    q = q.order_by(HoneypotInteraction.timestamp.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


async def _fetch_attacker_profiles(
    client_id: str, db: AsyncSession
) -> list[AttackerProfile]:
    result = await db.execute(
        select(AttackerProfile)
        .where(AttackerProfile.client_id == client_id)
        .order_by(AttackerProfile.total_interactions.desc())
    )
    return list(result.scalars().all())


async def _fetch_threat_intel(db: AsyncSession, limit: int = 100) -> list[ThreatIntel]:
    result = await db.execute(
        select(ThreatIntel).order_by(ThreatIntel.last_seen.desc()).limit(limit)
    )
    return list(result.scalars().all())


def _calculate_risk_level(critical_vulns: int, active_incidents: int) -> str:
    score = critical_vulns * 10 + active_incidents * 5
    if score >= 50:
        return "CRITICAL"
    elif score >= 20:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


# ---------------------------------------------------------------------------
# Table builder helpers
# ---------------------------------------------------------------------------

def _make_table(headers: list[str], rows: list[list], col_widths=None) -> Table:
    """Build a styled Table with alternating row colors."""
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)

    style_commands = [
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), AEGIS_GREY),
        ("TEXTCOLOR", (0, 0), (-1, 0), AEGIS_CYAN),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        # Body
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        # Grid
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    # Alternating row colors
    for i in range(1, len(data)):
        bg = colors.HexColor("#F9FAFB") if i % 2 == 0 else colors.white
        style_commands.append(("BACKGROUND", (0, i), (-1, i), bg))

    t.setStyle(TableStyle(style_commands))
    return t


def _severity_badge(severity: str) -> str:
    """Return colored text markup for severity."""
    color_map = {
        "critical": "#DC2626",
        "high": "#EA580C",
        "medium": "#D97706",
        "low": "#2563EB",
        "info": "#6B7280",
    }
    c = color_map.get(severity, "#6B7280")
    return f'<font color="{c}"><b>{severity.upper()}</b></font>'


def _truncate(text: str, max_len: int = 80) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ---------------------------------------------------------------------------
# AI recommendation helper
# ---------------------------------------------------------------------------

async def _get_ai_recommendations(context: dict) -> str:
    """Return prioritized recommendations; AI-assisted when available."""

    async def _ai_recs(_ctx: dict) -> str:
        prompt = (
            "Based on the following security data, provide 5-8 prioritized recommendations "
            "for improving the organization's security posture. Each recommendation should have: "
            "priority (P1-P4), title, and a 1-2 sentence description. Format as plain text, "
            "numbered list.\n\n"
            f"{json.dumps(_ctx, default=str)}"
        )
        response = await openrouter_client.query(
            [{"role": "user", "content": prompt}], "report"
        )
        return response.get("content", "")

    def _static_recs(_ctx: dict) -> str:
        critical = _ctx.get("critical_vulns", 0)
        open_vulns = _ctx.get("open_vulns", 0)
        incidents = _ctx.get("active_incidents", 0)
        recs = []
        if critical > 0:
            recs.append(f"P1. Patch {critical} critical vulnerabilities immediately — highest remediation priority.")
        if open_vulns > 0:
            recs.append(f"P2. Remediate {open_vulns} open vulnerabilities within 30 days using a risk-based schedule.")
        if incidents > 0:
            recs.append(f"P2. Investigate and close {incidents} active incidents — review root cause and apply permanent fixes.")
        recs.append("P3. Review firewall rules and remove unnecessary inbound access.")
        recs.append("P3. Enable MFA for all privileged accounts.")
        recs.append("P4. Schedule quarterly penetration test to validate defensive controls.")
        recs.append("P4. Review and update incident response playbooks annually.")
        return "\n".join(f"{i+1}. {r}" for i, r in enumerate(recs))

    try:
        return await degrade_or_call(_ai_recs, _static_recs, context)
    except Exception as e:
        logger.warning(f"Recommendations generation failed: {e}")
        return "Recommendations unavailable — review vulnerabilities and incidents manually."


# ---------------------------------------------------------------------------
# PDF Report Generator class
# ---------------------------------------------------------------------------

class PDFReportGenerator:
    """Generates branded PDF security reports for AEGIS."""

    def __init__(self):
        self.styles = _build_styles()

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _build_cover_page(
        self, client_name: str, report_title: str, period: str
    ) -> list:
        """Return flowable elements for the cover page."""
        elements = []
        elements.append(Spacer(1, 2 * inch))

        # Logo / brand text
        elements.append(Paragraph("AEGIS", self.styles["CoverTitle"]))
        elements.append(Paragraph("DEFENSE PLATFORM", self.styles["CoverSubtitle"]))
        elements.append(Spacer(1, 0.5 * inch))

        # Decorative line
        d = Drawing(400, 4)
        d.add(Line(0, 2, 400, 2, strokeColor=AEGIS_CYAN, strokeWidth=2))
        elements.append(d)
        elements.append(Spacer(1, 0.5 * inch))

        elements.append(Paragraph(report_title, ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Title"],
            fontSize=22,
            textColor=colors.HexColor("#111827"),
            alignment=TA_CENTER,
        )))
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(f"Client: {client_name}", self.styles["CoverSubtitle"]))
        elements.append(Paragraph(f"Period: {period}", ParagraphStyle(
            "Period",
            parent=self.styles["CoverSubtitle"],
            textColor=colors.HexColor("#6B7280"),
        )))
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
            ParagraphStyle(
                "GenDate",
                parent=self.styles["CoverSubtitle"],
                fontSize=11,
                textColor=colors.HexColor("#9CA3AF"),
            ),
        ))
        elements.append(PageBreak())
        return elements

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_executive_summary(
        self,
        total_assets: int,
        open_vulns: int,
        critical_vulns: int,
        high_vulns: int,
        active_incidents: int,
        actions_count: int,
        honeypot_count: int,
        risk_level: str,
        narrative: str,
    ) -> list:
        elements = []
        elements.append(Paragraph("1. Executive Summary", self.styles["SectionTitle"]))

        # Metric cards as a table
        metrics = [
            [
                Paragraph(str(total_assets), self.styles["Metric"]),
                Paragraph(str(open_vulns), self.styles["Metric"]),
                Paragraph(str(critical_vulns), self.styles["Metric"]),
                Paragraph(str(active_incidents), self.styles["Metric"]),
            ],
            [
                Paragraph("Total Assets", self.styles["MetricLabel"]),
                Paragraph("Open Vulns", self.styles["MetricLabel"]),
                Paragraph("Critical Vulns", self.styles["MetricLabel"]),
                Paragraph("Active Incidents", self.styles["MetricLabel"]),
            ],
        ]
        mt = Table(metrics, colWidths=[1.4 * inch] * 4)
        mt.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.5, AEGIS_GREY),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E5E7EB")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(mt)
        elements.append(Spacer(1, 12))

        # Risk level badge
        rl_color = {
            "CRITICAL": "#DC2626", "HIGH": "#EA580C",
            "MEDIUM": "#D97706", "LOW": "#16A34A",
        }.get(risk_level, "#6B7280")
        elements.append(Paragraph(
            f'Overall Risk Level: <font color="{rl_color}"><b>{risk_level}</b></font>',
            self.styles["BodyText2"],
        ))
        elements.append(Spacer(1, 8))

        # Narrative
        if narrative:
            for line in narrative.split("\n"):
                line = line.strip()
                if line:
                    elements.append(Paragraph(line, self.styles["BodyText2"]))
        elements.append(Spacer(1, 6))
        return elements

    def _build_asset_inventory(self, assets: list[Asset]) -> list:
        elements = []
        elements.append(Paragraph("2. Asset Inventory", self.styles["SectionTitle"]))

        if not assets:
            elements.append(Paragraph("No assets discovered.", self.styles["BodyText2"]))
            return elements

        elements.append(Paragraph(
            f"{len(assets)} assets monitored.", self.styles["BodyText2"]
        ))

        headers = ["Hostname / IP", "Type", "Status", "Risk Score", "Last Scan"]
        rows = []
        for a in assets[:50]:  # cap at 50 for readability
            rows.append([
                _truncate(a.hostname or a.ip_address or "N/A", 40),
                (a.asset_type or "unknown").title(),
                a.status.title(),
                f"{a.risk_score:.1f}",
                a.last_scan_at.strftime("%Y-%m-%d") if a.last_scan_at else "Never",
            ])

        t = _make_table(headers, rows, col_widths=[2 * inch, 0.9 * inch, 0.8 * inch, 0.8 * inch, 1 * inch])
        elements.append(t)
        if len(assets) > 50:
            elements.append(Paragraph(
                f"... and {len(assets) - 50} more assets (see appendix).",
                self.styles["SmallGrey"],
            ))
        elements.append(Spacer(1, 6))
        return elements

    def _build_vulnerability_analysis(self, vulns: list[Vulnerability]) -> list:
        elements = []
        elements.append(Paragraph("3. Vulnerability Analysis", self.styles["SectionTitle"]))

        if not vulns:
            elements.append(Paragraph("No vulnerabilities found in this period.", self.styles["BodyText2"]))
            return elements

        # Severity distribution
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1

        elements.append(Paragraph("Severity Distribution", self.styles["SubSection"]))
        chart = _severity_pie_chart(sev_counts)
        elements.append(chart)
        elements.append(Spacer(1, 8))

        # Group by severity
        sorted_vulns = sorted(vulns, key=lambda v: _severity_order(v.severity))

        current_sev = None
        for v in sorted_vulns[:60]:  # cap
            if v.severity != current_sev:
                current_sev = v.severity
                elements.append(Paragraph(
                    f"{_severity_badge(current_sev)} ({sev_counts.get(current_sev, 0)} found)",
                    self.styles["SubSection"],
                ))

            cvss_str = f"CVSS {v.cvss_score:.1f}" if v.cvss_score else "No CVSS"
            cve_str = v.cve_id or ""
            elements.append(Paragraph(
                f"<b>{_truncate(v.title, 100)}</b> | {cvss_str} | {cve_str}",
                self.styles["BodyText2"],
            ))
            if v.remediation:
                elements.append(Paragraph(
                    f"<i>Remediation:</i> {_truncate(v.remediation, 200)}",
                    self.styles["SmallGrey"],
                ))

        if len(vulns) > 60:
            elements.append(Paragraph(
                f"... {len(vulns) - 60} additional vulnerabilities listed in appendix.",
                self.styles["SmallGrey"],
            ))
        elements.append(Spacer(1, 6))
        return elements

    def _build_incident_timeline(self, incidents: list[Incident]) -> list:
        elements = []
        elements.append(Paragraph("4. Incident Timeline", self.styles["SectionTitle"]))

        if not incidents:
            elements.append(Paragraph("No incidents recorded in this period.", self.styles["BodyText2"]))
            return elements

        elements.append(Paragraph(
            f"{len(incidents)} incidents detected.", self.styles["BodyText2"]
        ))

        headers = ["Time", "Severity", "Title", "Status", "Source IP", "MITRE"]
        rows = []
        for inc in incidents[:40]:
            rows.append([
                inc.detected_at.strftime("%Y-%m-%d %H:%M") if inc.detected_at else "",
                inc.severity.upper(),
                _truncate(inc.title, 50),
                inc.status.title(),
                inc.source_ip or "",
                inc.mitre_technique or "",
            ])

        t = _make_table(
            headers, rows,
            col_widths=[1 * inch, 0.7 * inch, 2 * inch, 0.7 * inch, 0.8 * inch, 0.6 * inch],
        )
        elements.append(t)

        # AI analysis summaries for critical/high incidents
        critical_high = [i for i in incidents if i.severity in ("critical", "high")]
        if critical_high:
            elements.append(Paragraph("AI Analysis Highlights", self.styles["SubSection"]))
            for inc in critical_high[:10]:
                analysis = inc.ai_analysis or {}
                triage = analysis.get("triage", {})
                summary = triage.get("summary", inc.description or "No analysis available.")
                elements.append(Paragraph(
                    f"<b>[{inc.severity.upper()}]</b> {_truncate(inc.title, 60)}: "
                    f"{_truncate(summary, 200)}",
                    self.styles["BodyText2"],
                ))

        elements.append(Spacer(1, 6))
        return elements

    def _build_response_actions(self, actions: list[Action]) -> list:
        elements = []
        elements.append(Paragraph("5. Response Actions", self.styles["SectionTitle"]))

        if not actions:
            elements.append(Paragraph("No response actions in this period.", self.styles["BodyText2"]))
            return elements

        auto_count = sum(1 for a in actions if a.status == "executed" and not a.requires_approval)
        approval_count = sum(1 for a in actions if a.requires_approval)
        pending_count = sum(1 for a in actions if a.status == "pending")

        elements.append(Paragraph(
            f"Total: {len(actions)} | Auto-executed: {auto_count} | "
            f"Required Approval: {approval_count} | Pending: {pending_count}",
            self.styles["BodyText2"],
        ))

        headers = ["Time", "Action", "Target", "Status", "Approval"]
        rows = []
        for a in actions[:30]:
            rows.append([
                a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "",
                a.action_type,
                _truncate(a.target or "", 30),
                a.status.title(),
                "Manual" if a.requires_approval else "Auto",
            ])

        t = _make_table(
            headers, rows,
            col_widths=[1 * inch, 1 * inch, 1.5 * inch, 0.8 * inch, 0.7 * inch],
        )
        elements.append(t)
        elements.append(Spacer(1, 6))
        return elements

    def _build_honeypot_intel(
        self,
        interactions: list[HoneypotInteraction],
        profiles: list[AttackerProfile],
    ) -> list:
        elements = []
        elements.append(Paragraph("6. Honeypot Intelligence", self.styles["SectionTitle"]))

        if not interactions:
            elements.append(Paragraph("No honeypot interactions captured.", self.styles["BodyText2"]))
            return elements

        elements.append(Paragraph(
            f"{len(interactions)} interactions captured from honeypots.",
            self.styles["BodyText2"],
        ))

        # Top source IPs
        ip_counts: dict[str, int] = {}
        for hi in interactions:
            ip_counts[hi.source_ip] = ip_counts.get(hi.source_ip, 0) + 1

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        if top_ips:
            elements.append(Paragraph("Top Attacking IPs", self.styles["SubSection"]))
            headers = ["Source IP", "Interactions"]
            rows = [[ip, str(count)] for ip, count in top_ips]
            t = _make_table(headers, rows, col_widths=[2.5 * inch, 1.5 * inch])
            elements.append(t)

        # Attacker profiles
        if profiles:
            elements.append(Paragraph("Attacker Profiles", self.styles["SubSection"]))
            for p in profiles[:10]:
                sophistication = (p.sophistication or "unknown").title()
                tools = ", ".join(p.tools_used[:5]) if isinstance(p.tools_used, list) else ""
                techniques = ", ".join(p.techniques[:5]) if isinstance(p.techniques, list) else ""
                elements.append(Paragraph(
                    f"<b>{p.source_ip or 'Unknown'}</b> | Sophistication: {sophistication} | "
                    f"Interactions: {p.total_interactions}",
                    self.styles["BodyText2"],
                ))
                if tools:
                    elements.append(Paragraph(
                        f"  Tools: {_truncate(tools, 100)}",
                        self.styles["SmallGrey"],
                    ))
                if techniques:
                    elements.append(Paragraph(
                        f"  TTPs: {_truncate(techniques, 100)}",
                        self.styles["SmallGrey"],
                    ))

        elements.append(Spacer(1, 6))
        return elements

    def _build_threat_intel_section(self, intel: list[ThreatIntel]) -> list:
        elements = []
        elements.append(Paragraph("7. Threat Intelligence", self.styles["SectionTitle"]))

        if not intel:
            elements.append(Paragraph("No threat intelligence data available.", self.styles["BodyText2"]))
            return elements

        elements.append(Paragraph(
            f"{len(intel)} IOCs tracked.", self.styles["BodyText2"]
        ))

        # IOC type distribution
        type_counts: dict[str, int] = {}
        for t in intel:
            type_counts[t.ioc_type] = type_counts.get(t.ioc_type, 0) + 1

        if type_counts:
            categories = list(type_counts.keys())
            values = [type_counts[c] for c in categories]
            chart = _bar_chart(categories, values, width=380, height=150)
            elements.append(chart)
            elements.append(Spacer(1, 8))

        headers = ["Type", "Value", "Threat", "Confidence", "Source", "Last Seen"]
        rows = []
        for t in intel[:30]:
            rows.append([
                t.ioc_type,
                _truncate(t.ioc_value, 40),
                t.threat_type or "",
                f"{t.confidence:.0%}" if t.confidence else "",
                t.source or "",
                t.last_seen.strftime("%Y-%m-%d") if t.last_seen else "",
            ])

        tbl = _make_table(
            headers, rows,
            col_widths=[0.7 * inch, 1.5 * inch, 0.8 * inch, 0.7 * inch, 0.7 * inch, 0.8 * inch],
        )
        elements.append(tbl)
        elements.append(Spacer(1, 6))
        return elements

    def _build_recommendations(self, recommendations_text: str) -> list:
        elements = []
        elements.append(Paragraph("8. AI-Generated Recommendations", self.styles["SectionTitle"]))

        if not recommendations_text:
            elements.append(Paragraph(
                "Recommendations are currently unavailable.",
                self.styles["BodyText2"],
            ))
            return elements

        for line in recommendations_text.split("\n"):
            line = line.strip()
            if line:
                elements.append(Paragraph(line, self.styles["BodyText2"]))

        elements.append(Spacer(1, 6))
        return elements

    def _build_appendix(
        self,
        vulns: list[Vulnerability],
        incidents: list[Incident],
    ) -> list:
        elements = []
        elements.append(Paragraph("9. Appendix", self.styles["SectionTitle"]))

        # MITRE ATT&CK mapping
        mitre_map: dict[str, int] = {}
        for inc in incidents:
            if inc.mitre_technique:
                key = f"{inc.mitre_technique} ({inc.mitre_tactic or 'N/A'})"
                mitre_map[key] = mitre_map.get(key, 0) + 1

        if mitre_map:
            elements.append(Paragraph("MITRE ATT&CK Mapping", self.styles["SubSection"]))
            headers = ["Technique / Tactic", "Occurrences"]
            rows = [
                [k, str(v)]
                for k, v in sorted(mitre_map.items(), key=lambda x: x[1], reverse=True)
            ]
            t = _make_table(headers, rows, col_widths=[3.5 * inch, 1.5 * inch])
            elements.append(t)
            elements.append(Spacer(1, 8))

        # Detailed scan results for vulns beyond the cap
        if len(vulns) > 60:
            elements.append(Paragraph("Additional Vulnerabilities", self.styles["SubSection"]))
            headers = ["Title", "Severity", "CVSS", "CVE", "Found"]
            rows = []
            for v in vulns[60:]:
                rows.append([
                    _truncate(v.title, 60),
                    v.severity.upper(),
                    f"{v.cvss_score:.1f}" if v.cvss_score else "",
                    v.cve_id or "",
                    v.found_at.strftime("%Y-%m-%d") if v.found_at else "",
                ])
            t = _make_table(
                headers, rows,
                col_widths=[2.2 * inch, 0.7 * inch, 0.6 * inch, 0.8 * inch, 0.8 * inch],
            )
            elements.append(t)

        elements.append(Spacer(1, 12))
        elements.append(Paragraph(
            "--- End of Report ---",
            ParagraphStyle("EndMark", parent=self.styles["SmallGrey"], alignment=TA_CENTER),
        ))
        return elements

    # ------------------------------------------------------------------
    # Full report assembly
    # ------------------------------------------------------------------

    async def _build_full_report(
        self,
        client_id: str,
        db: AsyncSession,
        report_title: str,
        period_label: str,
        since: Optional[datetime] = None,
    ) -> bytes:
        """Core method: fetch all data, build all sections, render PDF to bytes."""
        client = await _fetch_client(client_id, db)
        client_name = client.name if client else "Unknown Client"

        # Fetch data
        assets = await _fetch_assets(client_id, db)
        vulns = await _fetch_vulns(client_id, db, since)
        incidents = await _fetch_incidents(client_id, db, since)
        actions = await _fetch_actions(client_id, db, since)
        interactions = await _fetch_honeypot_interactions(client_id, db, since)
        profiles = await _fetch_attacker_profiles(client_id, db)
        intel = await _fetch_threat_intel(db)

        # Compute stats
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulns:
            if v.status == "open":
                sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1

        open_vulns = sum(1 for v in vulns if v.status == "open")
        critical_vulns = sev_counts.get("critical", 0)
        high_vulns = sev_counts.get("high", 0)
        active_incidents = sum(1 for i in incidents if i.status in ("open", "investigating"))
        risk_level = _calculate_risk_level(critical_vulns, active_incidents)

        # Get AI recommendations
        ai_context = {
            "total_assets": len(assets),
            "open_vulnerabilities": open_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "active_incidents": active_incidents,
            "response_actions": len(actions),
            "honeypot_interactions": len(interactions),
            "risk_level": risk_level,
            "top_vuln_types": [v.title for v in vulns[:10]],
            "mitre_techniques": list({i.mitre_technique for i in incidents if i.mitre_technique}),
        }
        recommendations = await _get_ai_recommendations(ai_context)

        # Get executive narrative
        async def _ai_narrative(_ctx: dict) -> str:
            narrative_resp = await openrouter_client.query(
                [{"role": "user", "content": (
                    "Write a 3-4 paragraph executive summary for a security report. "
                    "Be concise and professional. Data:\n"
                    f"{json.dumps(_ctx, default=str)}"
                )}],
                "report",
            )
            return narrative_resp.get("content", "")

        def _template_narrative(_ctx: dict) -> str:
            return (
                f"During the reporting period, AEGIS monitored {_ctx.get('total_assets', 0)} assets "
                f"and detected {_ctx.get('total_incidents', 0)} security incidents. "
                f"Risk level is assessed as {_ctx.get('risk_level', 'moderate')}. "
                f"Critical vulnerabilities requiring immediate attention: {_ctx.get('critical_vulns', 0)}."
            )

        try:
            narrative = await degrade_or_call(_ai_narrative, _template_narrative, ai_context)
        except Exception:
            narrative = ""

        # Build PDF
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=55,
            bottomMargin=55,
            title=report_title,
            author="AEGIS Defense Platform",
        )

        elements = []
        elements.extend(self._build_cover_page(client_name, report_title, period_label))
        elements.extend(self._build_executive_summary(
            total_assets=len(assets),
            open_vulns=open_vulns,
            critical_vulns=critical_vulns,
            high_vulns=high_vulns,
            active_incidents=active_incidents,
            actions_count=len(actions),
            honeypot_count=len(interactions),
            risk_level=risk_level,
            narrative=narrative,
        ))
        elements.append(PageBreak())
        elements.extend(self._build_asset_inventory(assets))
        elements.append(PageBreak())
        elements.extend(self._build_vulnerability_analysis(vulns))
        elements.append(PageBreak())
        elements.extend(self._build_incident_timeline(incidents))
        elements.append(PageBreak())
        elements.extend(self._build_response_actions(actions))
        elements.extend(self._build_honeypot_intel(interactions, profiles))
        elements.append(PageBreak())
        elements.extend(self._build_threat_intel_section(intel))
        elements.extend(self._build_recommendations(recommendations))
        elements.append(PageBreak())
        elements.extend(self._build_appendix(vulns, incidents))

        doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)
        pdf_bytes = buf.getvalue()
        buf.close()

        logger.info(
            f"Generated report '{report_title}' for client {client_id} "
            f"({len(pdf_bytes)} bytes, {len(vulns)} vulns, {len(incidents)} incidents)"
        )
        return pdf_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_weekly_report(self, client_id: str, db: AsyncSession) -> bytes:
        """Generate a weekly security report PDF."""
        now = datetime.utcnow()
        since = now - timedelta(days=7)
        period = f"{since.strftime('%b %d')} - {now.strftime('%b %d, %Y')}"
        return await self._build_full_report(
            client_id, db,
            report_title="Weekly Security Report",
            period_label=period,
            since=since,
        )

    async def generate_monthly_report(self, client_id: str, db: AsyncSession) -> bytes:
        """Generate a monthly security report PDF."""
        now = datetime.utcnow()
        since = now - timedelta(days=30)
        period = f"{since.strftime('%b %d')} - {now.strftime('%b %d, %Y')}"
        return await self._build_full_report(
            client_id, db,
            report_title="Monthly Security Report",
            period_label=period,
            since=since,
        )

    async def generate_incident_report(
        self, incident_id: str, db: AsyncSession, client_id: Optional[str] = None
    ) -> bytes:
        """Generate a PDF report for a single incident. Enforces tenant isolation."""
        query = select(Incident).where(Incident.id == incident_id)
        if client_id:
            query = query.where(Incident.client_id == client_id)
        result = await db.execute(query)
        incident = result.scalar_one_or_none()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        client = await _fetch_client(incident.client_id, db)
        client_name = client.name if client else "Unknown"

        # Fetch related actions
        action_result = await db.execute(
            select(Action).where(Action.incident_id == incident_id)
            .order_by(Action.created_at)
        )
        actions = list(action_result.scalars().all())

        # Get deep analysis (AI-assisted or deterministic)
        incident_data = {
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "source_ip": incident.source_ip,
            "mitre_technique": incident.mitre_technique,
            "mitre_tactic": incident.mitre_tactic,
            "ai_analysis": incident.ai_analysis,
        }

        async def _ai_deep_analysis(_data: dict) -> str:
            resp = await openrouter_client.query(
                [{"role": "user", "content": (
                    "Provide a detailed incident analysis report covering: root cause, "
                    "attack chain, impact assessment, and remediation steps.\n"
                    f"Incident: {json.dumps(_data, default=str)}"
                )}],
                "investigation",
            )
            return resp.get("content", "")

        def _template_deep_analysis(_data: dict) -> str:
            technique = _data.get("mitre_technique") or "unknown"
            tactic = _data.get("mitre_tactic") or "unknown"
            return (
                f"**Root Cause:** {_data.get('description', 'No description available.')}\n\n"
                f"**MITRE ATT&CK:** {tactic} / {technique}\n\n"
                f"**Source:** {_data.get('source_ip', 'Unknown IP')}\n\n"
                f"**Severity:** {_data.get('severity', 'unknown').upper()}\n\n"
                f"**Remediation:** Apply standard remediation procedures for {tactic} attacks. "
                f"Block the source IP, patch affected systems, and review access controls."
            )

        try:
            deep_analysis = await degrade_or_call(_ai_deep_analysis, _template_deep_analysis, incident_data)
        except Exception:
            deep_analysis = ""

        # Build PDF
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            leftMargin=40, rightMargin=40, topMargin=55, bottomMargin=55,
            title=f"Incident Report - {incident.title}",
            author="AEGIS Defense Platform",
        )

        elements = []
        detected_str = incident.detected_at.strftime("%Y-%m-%d %H:%M UTC") if incident.detected_at else "Unknown"
        elements.extend(self._build_cover_page(
            client_name,
            "Incident Report",
            f"Detected: {detected_str}",
        ))

        # Incident details
        elements.append(Paragraph("1. Incident Details", self.styles["SectionTitle"]))

        details = [
            ["Field", "Value"],
            ["Title", incident.title],
            ["Severity", incident.severity.upper()],
            ["Status", incident.status.title()],
            ["Source", incident.source or "N/A"],
            ["Source IP", incident.source_ip or "N/A"],
            ["MITRE Technique", incident.mitre_technique or "N/A"],
            ["MITRE Tactic", incident.mitre_tactic or "N/A"],
            ["Detected At", detected_str],
            ["Contained At", incident.contained_at.strftime("%Y-%m-%d %H:%M UTC") if incident.contained_at else "Not yet"],
            ["Resolved At", incident.resolved_at.strftime("%Y-%m-%d %H:%M UTC") if incident.resolved_at else "Not yet"],
        ]
        t = Table(details, colWidths=[1.5 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AEGIS_GREY),
            ("TEXTCOLOR", (0, 0), (-1, 0), AEGIS_CYAN),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D1D5DB")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        # Description
        if incident.description:
            elements.append(Paragraph("Description", self.styles["SubSection"]))
            elements.append(Paragraph(incident.description, self.styles["BodyText2"]))

        # AI Analysis
        if deep_analysis:
            elements.append(PageBreak())
            elements.append(Paragraph("2. AI Analysis", self.styles["SectionTitle"]))
            for line in deep_analysis.split("\n"):
                line = line.strip()
                if line:
                    elements.append(Paragraph(line, self.styles["BodyText2"]))

        # Actions taken
        if actions:
            elements.append(PageBreak())
            elements.append(Paragraph("3. Response Actions", self.styles["SectionTitle"]))
            headers = ["Time", "Action", "Target", "Status", "Reasoning"]
            rows = []
            for a in actions:
                rows.append([
                    a.created_at.strftime("%H:%M:%S") if a.created_at else "",
                    a.action_type,
                    _truncate(a.target or "", 25),
                    a.status.title(),
                    _truncate(a.ai_reasoning or "", 40),
                ])
            tbl = _make_table(
                headers, rows,
                col_widths=[0.7 * inch, 0.9 * inch, 1.2 * inch, 0.7 * inch, 2 * inch],
            )
            elements.append(tbl)

        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            "--- End of Incident Report ---",
            ParagraphStyle("EndMark", parent=self.styles["SmallGrey"], alignment=TA_CENTER),
        ))

        doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)
        pdf_bytes = buf.getvalue()
        buf.close()

        logger.info(f"Generated incident report for {incident_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    async def generate_assessment_report(self, client_id: str, db: AsyncSession) -> bytes:
        """Generate a full security assessment PDF (all-time data, no date filter)."""
        return await self._build_full_report(
            client_id, db,
            report_title="Security Assessment Report",
            period_label="Full Assessment (All Time)",
            since=None,
        )


# Singleton
pdf_report_generator = PDFReportGenerator()
