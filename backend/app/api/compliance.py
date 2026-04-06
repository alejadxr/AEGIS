"""
Compliance framework mapping API for AEGIS.

Maps AEGIS controls to ISO 27001, NIS2, and SOC2 frameworks.
Shows coverage percentages and gap analysis.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.auth import AuthContext, require_viewer

router = APIRouter(prefix="/compliance", tags=["compliance"])


# ---------------------------------------------------------------------------
# Control definitions — maps AEGIS modules to framework controls
# ---------------------------------------------------------------------------

_CONTROLS = {
    "iso27001": {
        "name": "ISO 27001:2022",
        "short_name": "ISO 27001",
        "description": "Information security management systems",
        "controls": [
            {"id": "A.5", "name": "Information Security Policies", "module": "Settings / Guardrails", "status": "met", "evidence": "AI guardrails system with auto_approve / require_approval / never_auto policies configured"},
            {"id": "A.6", "name": "Organization of Information Security", "module": "Auth / RBAC", "status": "met", "evidence": "Multi-tenant architecture with API key auth, JWT tokens, and role-based access control"},
            {"id": "A.7", "name": "Human Resource Security", "module": "-", "status": "not_met", "evidence": "HR security controls are outside AEGIS scope"},
            {"id": "A.8", "name": "Asset Management", "module": "Surface Scanner", "status": "met", "evidence": "Automated asset discovery via nmap, continuous scanning (full 2h, quick 30min, discovery 1h)"},
            {"id": "A.9", "name": "Access Control", "module": "Auth / RBAC", "status": "met", "evidence": "API key authentication, JWT sessions, middleware-level enforcement"},
            {"id": "A.10", "name": "Cryptography", "module": "Quantum Module", "status": "met", "evidence": "Post-quantum cryptography assessment, algorithm vulnerability timeline tracking"},
            {"id": "A.11", "name": "Physical Security", "module": "-", "status": "not_met", "evidence": "Physical security controls are outside AEGIS scope"},
            {"id": "A.12", "name": "Operations Security", "module": "Log Watcher / Scanner", "status": "met", "evidence": "PM2 log tailing for SQLi, XSS, brute force patterns; scheduled vulnerability scanning"},
            {"id": "A.13", "name": "Communications Security", "module": "NDR / DNS Monitor", "status": "met", "evidence": "Network traffic analysis, DNS monitoring, threat intelligence correlation"},
            {"id": "A.14", "name": "System Development Security", "module": "Surface / SBOM", "status": "met", "evidence": "SBOM scanning, technology fingerprinting, vulnerability assessment with nuclei"},
            {"id": "A.15", "name": "Supplier Relationships", "module": "-", "status": "not_met", "evidence": "Supplier management is outside AEGIS scope"},
            {"id": "A.16", "name": "Incident Management", "module": "Response Module", "status": "met", "evidence": "Autonomous AI-driven triage, classification, decision, execution, verification, and audit pipeline"},
            {"id": "A.17", "name": "Business Continuity", "module": "Infra / PM2", "status": "partial", "evidence": "PM2 process management with auto-restart, but no full DR/BCP implementation"},
            {"id": "A.18", "name": "Compliance", "module": "Compliance Dashboard", "status": "met", "evidence": "Compliance dashboard providing framework mapping and gap analysis"},
        ],
    },
    "nis2": {
        "name": "NIS2 Directive",
        "short_name": "NIS2",
        "description": "EU Network and Information Security directive",
        "controls": [
            {"id": "Art.21.a", "name": "Risk Analysis & IS Policies", "module": "Surface / Guardrails", "status": "met", "evidence": "AI risk scoring on assets, configurable security policies via guardrails"},
            {"id": "Art.21.b", "name": "Incident Handling", "module": "Response Module", "status": "met", "evidence": "Automated incident detection, AI analysis, response actions with dual-layer IP blocking"},
            {"id": "Art.21.c", "name": "Business Continuity & Crisis Mgmt", "module": "Infra", "status": "partial", "evidence": "PM2 auto-restart and monitoring, but limited crisis management capabilities"},
            {"id": "Art.21.d", "name": "Supply Chain Security", "module": "Surface / SBOM", "status": "partial", "evidence": "SBOM scanning and technology fingerprinting cover some supply chain risks"},
            {"id": "Art.21.e", "name": "Network & IS Acquisition/Dev", "module": "Surface Scanner", "status": "met", "evidence": "Vulnerability scanning with nuclei, asset discovery, port analysis"},
            {"id": "Art.21.f", "name": "Effectiveness Assessment", "module": "Phantom / Honeypots", "status": "met", "evidence": "Honeypot deception system validates detection capabilities against real attackers"},
            {"id": "Art.21.g", "name": "Cybersecurity Hygiene & Training", "module": "-", "status": "not_met", "evidence": "Training and hygiene programs are outside AEGIS scope"},
            {"id": "Art.21.h", "name": "Cryptography Policies", "module": "Quantum Module", "status": "met", "evidence": "Quantum readiness assessment, crypto algorithm timeline, PQC recommendations"},
            {"id": "Art.21.i", "name": "HR Security & Access Control", "module": "Auth / RBAC", "status": "met", "evidence": "Role-based access control, API key management, multi-tenant isolation"},
            {"id": "Art.21.j", "name": "Multi-factor Authentication", "module": "Auth", "status": "partial", "evidence": "API key + JWT auth implemented, MFA not yet enforced"},
            {"id": "Art.23", "name": "Incident Reporting (24h/72h)", "module": "Response / Notifications", "status": "met", "evidence": "Real-time Telegram and webhook notifications for incidents, configurable thresholds"},
        ],
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "short_name": "SOC2",
        "description": "Service Organization Control - Trust Services Criteria",
        "controls": [
            {"id": "CC1", "name": "Control Environment", "module": "Settings / Guardrails", "status": "met", "evidence": "Configurable guardrails, AI decision audit trail, client settings management"},
            {"id": "CC2", "name": "Communication & Information", "module": "Notifications", "status": "met", "evidence": "Telegram, webhook, and email notification channels for security events"},
            {"id": "CC3", "name": "Risk Assessment", "module": "Surface Scanner", "status": "met", "evidence": "Automated risk scoring, vulnerability assessment, adaptive scanning frequency"},
            {"id": "CC4", "name": "Monitoring Activities", "module": "Log Watcher / Phantom", "status": "met", "evidence": "Continuous log monitoring, honeypot interaction tracking, anomaly detection"},
            {"id": "CC5", "name": "Control Activities", "module": "Response Module", "status": "met", "evidence": "Automated response actions, approval workflows, dual-layer IP blocking"},
            {"id": "CC6", "name": "Logical & Physical Access", "module": "Auth / RBAC", "status": "met", "evidence": "API key auth, JWT sessions, role-based access, middleware enforcement"},
            {"id": "CC7", "name": "System Operations", "module": "Infra / Scheduled Scanner", "status": "met", "evidence": "PM2 process management, scheduled scanning, system health monitoring"},
            {"id": "CC8", "name": "Change Management", "module": "-", "status": "not_met", "evidence": "Formal change management process not implemented in AEGIS"},
            {"id": "CC9", "name": "Risk Mitigation", "module": "Response / Rasputin", "status": "met", "evidence": "Automated IP blocking via Rasputin firewall + local blocklist, AI-driven remediation"},
            {"id": "A1", "name": "Availability", "module": "Infra / PM2", "status": "partial", "evidence": "PM2 auto-restart, health checks, but no formal SLA or redundancy"},
            {"id": "PI1", "name": "Processing Integrity", "module": "AI Engine", "status": "met", "evidence": "Multi-step AI pipeline with verification step, audit logging for all actions"},
            {"id": "C1", "name": "Confidentiality", "module": "Auth / Multi-tenant", "status": "met", "evidence": "Tenant isolation, encrypted API keys, JWT-based session management"},
        ],
    },
}

STATUS_WEIGHTS = {"met": 1.0, "partial": 0.5, "not_met": 0.0}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ControlOut(BaseModel):
    id: str
    name: str
    module: str
    status: str
    evidence: str


class FrameworkOut(BaseModel):
    key: str
    name: str
    short_name: str
    description: str
    score: int
    met: int
    partial: int
    not_met: int
    controls: list[ControlOut]


class ComplianceOverview(BaseModel):
    frameworks: list[FrameworkOut]
    overall_score: int
    total_controls: int
    total_met: int
    total_partial: int
    total_not_met: int
    gaps: list[dict]
    assessed_at: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/frameworks", response_model=ComplianceOverview)
async def get_compliance_overview(
    auth: AuthContext = Depends(require_viewer),
):
    """Return compliance posture across all frameworks with coverage percentages."""
    frameworks_out: list[FrameworkOut] = []
    all_gaps: list[dict] = []
    t_met = t_partial = t_not_met = 0

    for key, fw in _CONTROLS.items():
        controls = fw["controls"]
        met = sum(1 for c in controls if c["status"] == "met")
        partial = sum(1 for c in controls if c["status"] == "partial")
        not_met = sum(1 for c in controls if c["status"] == "not_met")

        weighted = sum(STATUS_WEIGHTS[c["status"]] for c in controls)
        score = round((weighted / len(controls)) * 100) if controls else 0

        t_met += met
        t_partial += partial
        t_not_met += not_met

        for c in controls:
            if c["status"] == "not_met":
                all_gaps.append({
                    "framework": fw["short_name"],
                    "control_id": c["id"],
                    "control_name": c["name"],
                    "evidence": c["evidence"],
                })

        frameworks_out.append(FrameworkOut(
            key=key,
            name=fw["name"],
            short_name=fw["short_name"],
            description=fw["description"],
            score=score,
            met=met,
            partial=partial,
            not_met=not_met,
            controls=[ControlOut(**c) for c in controls],
        ))

    total_controls = t_met + t_partial + t_not_met
    total_weighted = t_met + t_partial * 0.5
    overall = round((total_weighted / total_controls) * 100) if total_controls else 0

    return ComplianceOverview(
        frameworks=frameworks_out,
        overall_score=overall,
        total_controls=total_controls,
        total_met=t_met,
        total_partial=t_partial,
        total_not_met=t_not_met,
        gaps=all_gaps,
        assessed_at=datetime.utcnow().isoformat(),
    )
