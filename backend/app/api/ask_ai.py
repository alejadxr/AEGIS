import logging
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.database import get_db
from app.core.auth import AuthContext, get_auth_context
from app.core.openrouter import openrouter_client
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.honeypot import Honeypot
from app.models.audit_log import AuditLog
from app.services.rag_service import rag_service
from app.services import assistant_actions
from app.api.rag import router as _rag_router

logger = logging.getLogger("aegis.ask_ai")

router = APIRouter(prefix="/ask", tags=["ask-ai"])

# Mount RAG endpoints under /ask/rag/* without modifying main.py
router.include_router(_rag_router)


class AskRequest(BaseModel):
    message: str
    context: Optional[str] = None


class AskResponse(BaseModel):
    answer: str
    # Things the assistant actually did (a block the operator asked for, a rule
    # dry run) or was refused. See app/services/assistant_actions.py.
    actions_taken: list[dict] = []
    # Things it wants done that need a human: each carries the exact request the
    # operator's own session sends to confirm. Never applied by the assistant.
    proposals: list[dict] = []
    suggestions: list[str] = []
    model_used: str = ""
    rag_context_used: bool = False


@router.post("", response_model=AskResponse)
async def ask_ai(
    req: AskRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    client = auth.client
    assets_count = (await db.execute(
        select(func.count(Asset.id)).where(Asset.client_id == client.id)
    )).scalar() or 0

    vulns_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.client_id == client.id,
            Vulnerability.status == "open",
        )
    )).scalar() or 0

    incidents_count = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.client_id == client.id,
            Incident.status.in_(["open", "investigating"]),
        )
    )).scalar() or 0

    honeypots_count = (await db.execute(
        select(func.count(Honeypot.id)).where(Honeypot.client_id == client.id)
    )).scalar() or 0

    recent_incidents = (await db.execute(
        select(Incident)
        .where(Incident.client_id == client.id)
        .order_by(Incident.detected_at.desc())
        .limit(5)
    )).scalars().all()

    # Titles are built from request data (paths, user agents, rule names with the
    # matched string), so they are attacker-controlled: fenced as data, with the id
    # the model needs to refer to the incident. Severity/status/source are ours.
    recent_text = "\n".join([
        f"- id={i.id} [{i.severity}] {assistant_actions.fence('incident_title', i.title, 200)} "
        f"(status: {i.status}, source: {i.source})"
        for i in recent_incidents
    ]) if recent_incidents else "No recent incidents"

    settings_json = json.dumps(client.settings) if client.settings else "{}"
    guardrails_json = json.dumps(client.guardrails) if client.guardrails else "{}"

    # --- RAG context injection (graceful degradation) ---
    rag_context = ""
    try:
        await rag_service.ensure_started()
        if rag_service.enabled:
            rag_context = assistant_actions.fence(
                "knowledge_base", await rag_service.query_with_context(req.message, top_k=5), 4000)
    except Exception as exc:
        logger.debug("RAG query failed (non-fatal): %s", exc)

    context_prompt = f"""IMPORTANT CONTEXT - You are answering a user question as AEGIS security AI assistant.
Do NOT respond in JSON format. Respond in clear, natural language with markdown formatting.

{assistant_actions.PROTOCOL}

{rag_context}

PROTECTED SERVICES:
- AEGIS API on port 8000
- AEGIS frontend on port 3007
- PostgreSQL on port 5432
- AEGIS SSH honeypot on port 2222
- AEGIS HTTP honeypot on port 8888

SECURITY STATUS:
- Total Assets: {assets_count}
- Open Vulnerabilities: {vulns_count}
- Active Incidents: {incidents_count}
- Active Honeypots: {honeypots_count}

RECENT INCIDENTS:
{recent_text}

SETTINGS: {settings_json}
GUARDRAILS: {guardrails_json}

User is viewing: {req.context or 'general'} module.

USER QUESTION: {req.message}"""

    messages = [{"role": "user", "content": context_prompt}]

    try:
        result = await openrouter_client.query(
            messages=messages,
            task_type="investigation",
        )

        answer = result.get("content", "I couldn't process that request.")
        # Whatever the model asks for is re-validated and policy-checked in code;
        # only the first aegis-actions block is read and it is removed from the text.
        answer, raw_items = assistant_actions.extract(answer)
        actions_taken, proposals = await assistant_actions.process(
            db, auth=auth, message=req.message, items=raw_items)
        model_used = result.get("model_used", "unknown")

        log = AuditLog(
            client_id=client.id,
            action="ask_ai",
            model_used=model_used,
            input_summary=req.message[:200],
            ai_reasoning=answer[:500],
            decision="responded" + (f"; actions={[(a.get('kind'), a.get('status')) for a in actions_taken]}"
                                    f" proposals={len(proposals)}" if actions_taken or proposals else ""),
            confidence=0.9,
            tokens_used=result.get("tokens_used", 0),
            cost_usd=result.get("cost_usd", 0.0),
            latency_ms=result.get("latency_ms", 0),
        )
        db.add(log)
        await db.commit()

        return AskResponse(
            answer=answer,
            actions_taken=actions_taken,
            proposals=proposals,
            suggestions=[],
            model_used=model_used,
            rag_context_used=bool(rag_context),
        )
    except Exception as e:
        return AskResponse(
            answer=f"Error connecting to AI: {str(e)}. Check OpenRouter API key and connectivity.",
            model_used="error",
        )
