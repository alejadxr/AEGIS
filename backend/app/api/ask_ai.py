import logging
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.database import get_db
from app.core.auth import get_current_client
from app.core.openrouter import openrouter_client
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.honeypot import Honeypot
from app.models.audit_log import AuditLog
from app.services.rag_service import rag_service
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
    actions_taken: list[dict] = []
    suggestions: list[str] = []
    model_used: str = ""
    rag_context_used: bool = False


@router.post("", response_model=AskResponse)
async def ask_ai(
    req: AskRequest,
    client: Client = Depends(get_current_client),
    db: AsyncSession = Depends(get_db),
):
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

    recent_text = "\n".join([
        f"- [{i.severity}] {i.title} (status: {i.status}, source: {i.source})"
        for i in recent_incidents
    ]) if recent_incidents else "No recent incidents"

    settings_json = json.dumps(client.settings) if client.settings else "{}"
    guardrails_json = json.dumps(client.guardrails) if client.guardrails else "{}"

    # --- RAG context injection (graceful degradation) ---
    rag_context = ""
    try:
        await rag_service.ensure_started()
        if rag_service.enabled:
            rag_context = await rag_service.query_with_context(req.message, top_k=5)
    except Exception as exc:
        logger.debug("RAG query failed (non-fatal): %s", exc)

    context_prompt = f"""IMPORTANT CONTEXT - You are answering a user question as AEGIS security AI assistant.
Do NOT respond in JSON format. Respond in clear, natural language with markdown formatting.

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
        model_used = result.get("model_used", "unknown")

        log = AuditLog(
            client_id=client.id,
            action="ask_ai",
            model_used=model_used,
            input_summary=req.message[:200],
            ai_reasoning=answer[:500],
            decision="responded",
            confidence=0.9,
            tokens_used=result.get("tokens_used", 0),
            cost_usd=result.get("cost_usd", 0.0),
            latency_ms=result.get("latency_ms", 0),
        )
        db.add(log)
        await db.commit()

        return AskResponse(
            answer=answer,
            actions_taken=[],
            suggestions=[],
            model_used=model_used,
            rag_context_used=bool(rag_context),
        )
    except Exception as e:
        return AskResponse(
            answer=f"Error connecting to AI: {str(e)}. Check OpenRouter API key and connectivity.",
            model_used="error",
        )
