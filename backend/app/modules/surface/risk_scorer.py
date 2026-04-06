import logging
from typing import Optional

from app.core.openrouter import openrouter_client
from app.services.ai_engine import ai_engine

logger = logging.getLogger("aegis.risk_scorer")


class RiskScorer:
    """AI-powered contextual risk scoring for assets and vulnerabilities."""

    async def score_asset(self, asset_data: dict) -> dict:
        """Score risk for an asset considering context."""
        context = {
            "type": "asset_risk",
            "hostname": asset_data.get("hostname", ""),
            "asset_type": asset_data.get("asset_type", ""),
            "ports": asset_data.get("ports", []),
            "technologies": asset_data.get("technologies", []),
            "vulnerability_count": asset_data.get("vulnerability_count", 0),
            "critical_vulns": asset_data.get("critical_vulns", 0),
            "internet_facing": asset_data.get("internet_facing", True),
        }
        return await ai_engine.score_risk(context)

    async def score_vulnerability(self, vuln_data: dict) -> dict:
        """Score contextual risk for a vulnerability."""
        context = {
            "type": "vulnerability_risk",
            "title": vuln_data.get("title", ""),
            "severity": vuln_data.get("severity", ""),
            "cvss_base": vuln_data.get("cvss_score", 0),
            "cve_id": vuln_data.get("cve_id"),
            "asset_type": vuln_data.get("asset_type", ""),
            "internet_facing": vuln_data.get("internet_facing", True),
            "exploit_available": vuln_data.get("exploit_available", False),
        }
        return await ai_engine.score_risk(context)

    def calculate_composite_score(
        self,
        cvss_base: float,
        internet_facing: bool = True,
        exploit_available: bool = False,
        asset_criticality: float = 5.0,
    ) -> float:
        """Calculate a composite risk score from multiple factors."""
        score = cvss_base * 10  # Base: 0-100

        if internet_facing:
            score *= 1.3
        if exploit_available:
            score *= 1.5

        # Asset criticality factor (1-10 scale)
        score *= (asset_criticality / 10.0 + 0.5)

        return min(100.0, max(0.0, score))


risk_scorer = RiskScorer()
