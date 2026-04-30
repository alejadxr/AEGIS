import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.core.ai_mode import degrade_or_call
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.action import Action
from app.models.honeypot import HoneypotInteraction

logger = logging.getLogger("aegis.reporter")


class ReportGenerator:
    """Generate security reports in JSON and HTML formats."""

    async def generate_executive_summary(
        self, client_id: str, db: AsyncSession
    ) -> dict:
        """Generate an executive summary report."""
        # Gather stats
        asset_count = await db.scalar(
            select(func.count(Asset.id)).where(Asset.client_id == client_id)
        )
        vuln_count = await db.scalar(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.client_id == client_id,
                Vulnerability.status == "open",
            )
        )
        critical_vulns = await db.scalar(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.client_id == client_id,
                Vulnerability.severity == "critical",
                Vulnerability.status == "open",
            )
        )
        incident_count = await db.scalar(
            select(func.count(Incident.id)).where(
                Incident.client_id == client_id,
                Incident.status.in_(["open", "investigating"]),
            )
        )
        action_count = await db.scalar(
            select(func.count(Action.id)).where(Action.client_id == client_id)
        )
        interaction_count = await db.scalar(
            select(func.count(HoneypotInteraction.id)).where(
                HoneypotInteraction.client_id == client_id
            )
        )

        report = {
            "title": "AEGIS Security Report",
            "generated_at": datetime.utcnow().isoformat(),
            "client_id": client_id,
            "summary": {
                "total_assets": asset_count or 0,
                "open_vulnerabilities": vuln_count or 0,
                "critical_vulnerabilities": critical_vulns or 0,
                "active_incidents": incident_count or 0,
                "total_response_actions": action_count or 0,
                "honeypot_interactions": interaction_count or 0,
            },
            "risk_level": self._calculate_risk_level(
                critical_vulns or 0, incident_count or 0
            ),
        }

        summary = report["summary"]
        risk_level = report["risk_level"]

        async def _ai_narrative(_summary: dict, _risk: str) -> str:
            messages = [{
                "role": "user",
                "content": (
                    f"Generate a professional executive summary for this security report:\n"
                    f"{json.dumps(_summary, indent=2)}\n"
                    f"Risk level: {_risk}"
                ),
            }]
            ai_response = await openrouter_client.query(messages, "report")
            return ai_response.get("content", "")

        def _template_narrative(_summary: dict, _risk: str) -> str:
            return (
                f"Security assessment for the reporting period shows a {_risk} risk posture. "
                f"AEGIS monitored {_summary.get('total_assets', 0)} assets and identified "
                f"{_summary.get('open_vulnerabilities', 0)} open vulnerabilities "
                f"({_summary.get('critical_vulnerabilities', 0)} critical). "
                f"Active incidents: {_summary.get('active_incidents', 0)}. "
                f"Response actions executed: {_summary.get('total_response_actions', 0)}. "
                f"Honeypot interactions: {_summary.get('honeypot_interactions', 0)}."
            )

        report["narrative"] = await degrade_or_call(_ai_narrative, _template_narrative, summary, risk_level)

        return report

    async def generate_vulnerability_report(
        self, client_id: str, db: AsyncSession
    ) -> dict:
        """Generate detailed vulnerability report."""
        result = await db.execute(
            select(Vulnerability)
            .where(Vulnerability.client_id == client_id)
            .order_by(Vulnerability.severity, Vulnerability.found_at.desc())
        )
        vulns = result.scalars().all()

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_list = []
        for v in vulns:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
            vuln_list.append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "cve_id": v.cve_id,
                "status": v.status,
                "asset_id": v.asset_id,
                "found_at": v.found_at.isoformat() if v.found_at else None,
                "remediation": v.remediation,
            })

        return {
            "title": "Vulnerability Report",
            "generated_at": datetime.utcnow().isoformat(),
            "severity_distribution": severity_counts,
            "total": len(vuln_list),
            "vulnerabilities": vuln_list,
        }

    def generate_html_report(self, report_data: dict) -> str:
        """Convert a JSON report to HTML."""
        title = report_data.get("title", "Security Report")
        generated = report_data.get("generated_at", "")
        summary = report_data.get("summary", {})
        narrative = report_data.get("narrative", "")

        stats_html = ""
        for key, val in summary.items():
            label = key.replace("_", " ").title()
            stats_html += f"<tr><td>{label}</td><td><strong>{val}</strong></td></tr>"

        return f"""<!DOCTYPE html>
<html><head><title>{title}</title>
<style>
body {{ font-family: 'Inter', sans-serif; background: #0A0E1A; color: #F9FAFB; padding: 40px; }}
h1 {{ color: #00F0FF; }}
table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
td, th {{ padding: 12px; border: 1px solid #1F2937; text-align: left; }}
th {{ background: #111827; color: #00F0FF; }}
.narrative {{ background: #111827; padding: 20px; border-radius: 8px; margin: 20px 0; line-height: 1.6; }}
</style></head><body>
<h1>{title}</h1>
<p>Generated: {generated}</p>
<table><tr><th>Metric</th><th>Value</th></tr>{stats_html}</table>
<div class="narrative"><h2>Executive Summary</h2><p>{narrative}</p></div>
</body></html>"""

    def _calculate_risk_level(self, critical_vulns: int, active_incidents: int) -> str:
        score = critical_vulns * 10 + active_incidents * 5
        if score >= 50:
            return "critical"
        elif score >= 20:
            return "high"
        elif score >= 5:
            return "medium"
        return "low"


reporter = ReportGenerator()
