from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_admin, require_analyst, require_viewer
from app.core.guardrails import guardrail_engine, DEFAULT_GUARDRAILS
from app.models.client import Client
from app.models.incident import Incident
from app.models.action import Action
from app.services.ai_engine import ai_engine
from app.services.counter_attack import counter_attack_engine, COUNTER_ATTACK_ACTIONS
from app.modules.response.ingestion import alert_ingestion
from app.modules.response.responder import active_responder

router = APIRouter(prefix="/response", tags=["response"])


# --- Schemas ---

class AlertIn(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    source: str | None = None
    source_ip: str | None = None
    target: str | None = None
    raw: dict = {}


class IncidentOut(BaseModel):
    id: str
    title: str
    description: str | None = None
    severity: str
    status: str
    source: str | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    source_ip: str | None = None
    ai_analysis: dict | None = None
    detected_at: str | None = None
    contained_at: str | None = None
    resolved_at: str | None = None


class ActionOut(BaseModel):
    id: str
    incident_id: str
    action_type: str
    target: str | None = None
    status: str
    requires_approval: bool
    approved_by: str | None = None
    ai_reasoning: str | None = None
    result: dict | None = None
    executed_at: str | None = None
    created_at: str | None = None


class GuardrailConfig(BaseModel):
    guardrails: dict


# --- Routes ---

@router.post("/alerts")
async def ingest_alert(
    body: AlertIn,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Ingest an alert and trigger AI analysis pipeline. Analyst or admin only."""
    client = auth.client
    alert_data = body.model_dump()
    alert_data.update(body.raw)

    result = await ai_engine.process_alert(alert_data, client, db)
    return {
        "status": "processed",
        "incident_id": result.get("incident_id"),
        "actions": result.get("actions_taken", []),
        "stage": result.get("stage"),
    }


@router.get("/incidents", response_model=list[IncidentOut])
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List incidents."""
    client = auth.client
    query = select(Incident).where(Incident.client_id == client.id)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    query = query.order_by(Incident.detected_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    incidents = result.scalars().all()

    return [
        IncidentOut(
            id=i.id,
            title=i.title,
            description=i.description,
            severity=i.severity,
            status=i.status,
            source=i.source,
            mitre_technique=i.mitre_technique,
            mitre_tactic=i.mitre_tactic,
            source_ip=i.source_ip,
            ai_analysis=i.ai_analysis,
            detected_at=i.detected_at.isoformat() if i.detected_at else None,
            contained_at=i.contained_at.isoformat() if i.contained_at else None,
            resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
        )
        for i in incidents
    ]


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
async def get_incident(
    incident_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get incident details with actions."""
    client = auth.client
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.client_id == client.id,
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return IncidentOut(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        source=incident.source,
        mitre_technique=incident.mitre_technique,
        mitre_tactic=incident.mitre_tactic,
        source_ip=incident.source_ip,
        ai_analysis=incident.ai_analysis,
        detected_at=incident.detected_at.isoformat() if incident.detected_at else None,
        contained_at=incident.contained_at.isoformat() if incident.contained_at else None,
        resolved_at=incident.resolved_at.isoformat() if incident.resolved_at else None,
    )


@router.post("/incidents/{incident_id}/analyze")
async def analyze_incident(
    incident_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Trigger deep AI analysis on an incident. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.client_id == client.id,
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    analysis = await ai_engine.analyze_incident(incident, db)
    return {"incident_id": incident_id, "analysis": analysis}


@router.get("/actions", response_model=list[ActionOut])
async def list_actions(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List response actions."""
    client = auth.client
    query = select(Action).where(Action.client_id == client.id)
    if status:
        query = query.where(Action.status == status)
    query = query.order_by(Action.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    actions = result.scalars().all()

    return [
        ActionOut(
            id=a.id,
            incident_id=a.incident_id,
            action_type=a.action_type,
            target=a.target,
            status=a.status,
            requires_approval=a.requires_approval,
            approved_by=a.approved_by,
            ai_reasoning=a.ai_reasoning,
            result=a.result,
            executed_at=a.executed_at.isoformat() if a.executed_at else None,
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in actions
    ]


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending action and execute it. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Action).where(
            Action.id == action_id,
            Action.client_id == client.id,
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    if action.status != "pending":
        raise HTTPException(status_code=400, detail=f"Action is already {action.status}")

    approved_by = auth.email or auth.client.name
    action = await guardrail_engine.approve_action(action, approved_by, db)

    exec_result = await active_responder.execute_action(action, db)
    return {"action_id": action_id, "status": action.status, "result": exec_result}


@router.post("/actions/{action_id}/rollback")
async def rollback_action(
    action_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Rollback an executed action. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Action).where(
            Action.id == action_id,
            Action.client_id == client.id,
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    rollback_result = await active_responder.rollback_action(action, db)
    return {"action_id": action_id, "status": action.status, "result": rollback_result}


@router.get("/guardrails", response_model=GuardrailConfig)
async def get_guardrails(auth: AuthContext = Depends(require_viewer)):
    """Get guardrail configuration."""
    return GuardrailConfig(guardrails=auth.client.guardrails or DEFAULT_GUARDRAILS)


@router.put("/guardrails", response_model=GuardrailConfig)
async def update_guardrails(
    body: GuardrailConfig,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update guardrail configuration. Admin only."""
    auth.client.guardrails = body.guardrails
    await db.commit()
    return GuardrailConfig(guardrails=auth.client.guardrails)


# --- Counter-Attack Endpoints ---


class CounterAttackRequest(BaseModel):
    action_type: str | None = None  # recon_attacker, intel_lookup, deception, report_abuse, tarpit


@router.post("/counter-attack/{incident_id}")
async def trigger_counter_attack(
    incident_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Trigger AI counter-attack analysis for an incident. Analyst or admin only.

    Uses dolphin-mistral uncensored model to analyze the attacker and
    recommend counter-measures (recon, intel, deception, reporting, tarpit).
    """
    client = auth.client
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.client_id == client.id,
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    analysis = await counter_attack_engine.analyze(
        incident_id=incident.id,
        source_ip=incident.source_ip or "unknown",
        attack_type=incident.title,
        details=incident.description or "",
        severity=incident.severity,
    )

    return {
        "incident_id": incident_id,
        "source_ip": incident.source_ip,
        "analysis": analysis,
    }


@router.get("/counter-attack/{incident_id}")
async def get_counter_attack_analysis(
    incident_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get cached counter-attack AI analysis for an incident."""
    analysis = await counter_attack_engine.get_analysis(incident_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="No counter-attack analysis found for this incident")
    return analysis


@router.post("/counter-attack/{incident_id}/execute")
async def execute_counter_attack(
    incident_id: str,
    body: CounterAttackRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Execute a specific counter-attack action. Admin only.

    Requires guardrail approval. Available actions:
    - recon_attacker: Scan attacker IP with nmap
    - intel_lookup: Threat intel feed lookup
    - deception: Deploy fake data/honeypot redirect
    - report_abuse: Report to AbuseIPDB
    - tarpit: Throttle attacker connections
    """
    client = auth.client

    # Get incident
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.client_id == client.id,
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_type = body.action_type
    if not action_type:
        raise HTTPException(status_code=400, detail="action_type is required")
    if action_type not in COUNTER_ATTACK_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action_type. Must be one of: {list(COUNTER_ATTACK_ACTIONS.keys())}",
        )

    # Check guardrails
    action = await guardrail_engine.evaluate_action(
        client=client,
        action_type=action_type,
        target=incident.source_ip or "unknown",
        ai_reasoning=f"Counter-attack {action_type} against attacker {incident.source_ip}",
        db=db,
        incident_id=incident_id,
    )

    if action.status == "approved":
        # Execute immediately (auto-approved actions like intel_lookup)
        exec_result = await counter_attack_engine.execute_action(
            incident_id=incident_id,
            action_type=action_type,
            target_ip=incident.source_ip or "unknown",
            db=db,
        )
        return {
            "action_id": action.id,
            "status": "executed",
            "result": exec_result,
        }
    else:
        return {
            "action_id": action.id,
            "status": "pending_approval",
            "message": f"Counter-attack '{action_type}' requires approval before execution.",
        }


@router.get("/counter-attack-stats")
async def counter_attack_stats(
    auth: AuthContext = Depends(require_viewer),
):
    """Get counter-attack engine statistics."""
    return counter_attack_engine.stats()
