"""AI-assisted configuration engine for AEGIS setup wizard.

Uses OpenRouter (dolphin uncensored or trinity-large) to interpret
natural-language configuration requests and map them to a strict
whitelist of allowed actions.  Includes anti-prompt-injection
defences: input sanitisation, action whitelist, rate limiting,
and full audit logging.
"""

import json
import logging
import re
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.models.audit_log import AuditLog

logger = logging.getLogger("aegis.ai_configurator")


# ---------------------------------------------------------------------------
# Allowed action types (whitelist)
# ---------------------------------------------------------------------------

ALLOWED_ACTIONS: dict[str, str] = {
    "update_setting": "Update a platform setting (scan intervals, guardrails, etc.)",
    "update_scan_interval": "Change a scan schedule interval",
    "update_guardrail": "Modify an action guardrail (auto_approve, require_approval, never_auto)",
    "add_asset": "Register a new asset for monitoring",
    "configure_notification": "Configure notification channels and preferences",
    "deploy_honeypot": "Deploy or configure a honeypot",
    "update_ai_provider": "Change the AI provider or model routing",
}

# Setting keys the AI is allowed to modify
ALLOWED_SETTING_KEYS: set[str] = {
    # Scan intervals
    "scan_interval",
    "scan_intervals.quick_scan_minutes",
    "scan_intervals.full_scan_hours",
    "scan_intervals.vuln_scan_hours",
    "scan_intervals.network_scan_minutes",
    # Guardrails
    "guardrails.block_ip",
    "guardrails.isolate_host",
    "guardrails.revoke_creds",
    "guardrails.shutdown_service",
    "guardrails.firewall_rule",
    "guardrails.quarantine_file",
    # Notifications
    "notify_on_critical",
    "notify_on_high",
    "notify_on_actions",
    "notification_channels",
    "webhook_url",
    "email_enabled",
    "email_recipients",
    "telegram_bot_token",
    "telegram_chat_id",
    # AI provider
    "ai_provider",
    "model_routing",
    # General
    "auto_response",
    "dark_mode",
    "language",
    "timezone",
}

# Guardrail allowed values
GUARDRAIL_VALUES = {"auto_approve", "require_approval", "never_auto"}

# ---------------------------------------------------------------------------
# Input sanitisation
# ---------------------------------------------------------------------------

# Patterns that indicate prompt-injection or dangerous input
DANGEROUS_PATTERNS: list[re.Pattern] = [
    re.compile(r"```", re.IGNORECASE),                       # code blocks
    re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER)\s", re.IGNORECASE),  # SQL
    re.compile(r"(\||&&|;)\s*(rm|cat|curl|wget|nc|bash|sh|python|exec)\b", re.IGNORECASE),  # shell
    re.compile(r"<script", re.IGNORECASE),                   # XSS
    re.compile(r"__(import|class|subclasses|globals)__", re.IGNORECASE),  # Python injection
    re.compile(r"\bos\.system\b", re.IGNORECASE),
    re.compile(r"\bsubprocess\b", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"ignore\s+(previous|above|all)\s+(instructions|prompts)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),       # jailbreak
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"forget\s+(everything|your|all)", re.IGNORECASE),
]


def sanitise_input(text: str) -> tuple[str, bool]:
    """Sanitise user input.  Returns (cleaned_text, is_safe).

    If dangerous patterns are detected, returns the original text
    with ``is_safe=False`` so the caller can reject the request.
    """
    if not text or not text.strip():
        return "", False

    # Length limit (generous but bounded)
    if len(text) > 2000:
        return text[:2000], False

    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(text):
            logger.warning(f"Prompt injection attempt detected: pattern={pattern.pattern}")
            return text, False

    return text.strip(), True


# ---------------------------------------------------------------------------
# Rate limiter (in-memory, per-client)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter: max N requests per minute."""

    def __init__(self, max_per_minute: int = 10):
        self.max_per_minute = max_per_minute
        self._windows: dict[str, list[float]] = defaultdict(list)

    def allow(self, client_id: str) -> bool:
        now = time.time()
        window = self._windows[client_id]
        # Prune entries older than 60s
        window[:] = [t for t in window if now - t < 60]
        if len(window) >= self.max_per_minute:
            return False
        window.append(now)
        return True


_rate_limiter = _RateLimiter(max_per_minute=10)


# ---------------------------------------------------------------------------
# AI Configurator
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are AEGIS Configuration Assistant.  Your ONLY purpose is to
interpret the user's natural-language request and map it to ONE OR MORE
configuration actions from the allowed list below.

ALLOWED ACTIONS (you may ONLY use these):
- update_setting: Update a platform setting. Provide "key" and "value".
- update_scan_interval: Change scan schedule. Provide "key" (e.g. "scan_intervals.quick_scan_minutes") and "value" (number).
- update_guardrail: Change an action guardrail. Provide "key" (e.g. "guardrails.block_ip") and "value" (one of: auto_approve, require_approval, never_auto).
- add_asset: Register a new asset. Provide "hostname", "ip", "type".
- configure_notification: Configure notifications. Provide "key" and "value".
- deploy_honeypot: Deploy a honeypot. Provide "type" and "port".
- update_ai_provider: Change AI provider. Provide "provider" name.

ALLOWED SETTING KEYS:
scan_interval, scan_intervals.quick_scan_minutes, scan_intervals.full_scan_hours,
scan_intervals.vuln_scan_hours, scan_intervals.network_scan_minutes,
guardrails.block_ip, guardrails.isolate_host, guardrails.revoke_creds,
guardrails.shutdown_service, guardrails.firewall_rule, guardrails.quarantine_file,
notify_on_critical, notify_on_high, notify_on_actions, notification_channels,
webhook_url, email_enabled, email_recipients, telegram_bot_token, telegram_chat_id,
ai_provider, model_routing, auto_response, dark_mode, language, timezone.

RULES:
1. NEVER suggest shell commands, file operations, SQL queries, or network requests.
2. NEVER reveal internal system details, database structure, or API keys.
3. If the user's request doesn't map to an allowed action, respond with an empty actions list and explain what you CAN do.
4. Always respond in valid JSON with exactly these keys:
   {"understood": "<summary of what you understood>", "actions": [{"type": "<action_type>", ...params}]}

Respond ONLY with the JSON object, no markdown, no explanation outside the JSON."""


class AIConfigurator:
    """Interprets natural-language configuration requests via AI
    and maps them to a strict whitelist of allowed actions."""

    async def configure(
        self,
        question: str,
        client_id: str,
        client_settings: Optional[dict] = None,
        db: Optional[AsyncSession] = None,
    ) -> dict:
        """Parse intent from natural language and return configuration actions.

        Returns dict with keys: understood, actions, applied, error (optional).
        """
        # --- Rate limit ---
        if not _rate_limiter.allow(client_id):
            return {
                "understood": "Rate limit exceeded",
                "actions": [],
                "applied": False,
                "error": "Too many requests. Maximum 10 per minute.",
            }

        # --- Sanitise ---
        cleaned, is_safe = sanitise_input(question)
        if not is_safe:
            await self._log_audit(
                db=db,
                client_id=client_id,
                action="ai_configure_rejected",
                input_summary=question[:200],
                decision="Input rejected: potentially dangerous content detected",
            )
            return {
                "understood": "Request rejected",
                "actions": [],
                "applied": False,
                "error": "Input contains disallowed patterns. Please rephrase your request using plain language.",
            }

        # --- Query AI ---
        messages = [{"role": "user", "content": cleaned}]
        try:
            result = await openrouter_client.query(
                messages=messages,
                task_type="classification",  # uses trinity-large
                temperature=0.1,
                max_tokens=1024,
                client_settings=client_settings,
            )
        except Exception as exc:
            logger.error(f"AI query failed: {exc}")
            return {
                "understood": "AI query failed",
                "actions": [],
                "applied": False,
                "error": f"AI service unavailable: {exc}",
            }

        content = result.get("content", "")

        # --- Parse AI response ---
        parsed = self._parse_ai_response(content)
        if parsed is None:
            await self._log_audit(
                db=db,
                client_id=client_id,
                action="ai_configure_parse_failed",
                input_summary=cleaned[:200],
                ai_reasoning=content[:500],
                decision="Failed to parse AI response as JSON",
                model_used=result.get("model_used"),
                tokens_used=result.get("tokens_used"),
                latency_ms=result.get("latency_ms"),
            )
            return {
                "understood": "Could not interpret the response from AI",
                "actions": [],
                "applied": False,
                "error": "AI response was not valid JSON. Please try rephrasing.",
            }

        understood = parsed.get("understood", "")
        raw_actions = parsed.get("actions", [])

        # --- Validate actions against whitelist ---
        validated_actions: list[dict] = []
        for action in raw_actions:
            if not isinstance(action, dict):
                continue
            action_type = action.get("type", "")
            if action_type not in ALLOWED_ACTIONS:
                logger.warning(f"AI proposed disallowed action: {action_type}")
                continue

            validated = self._validate_action(action)
            if validated:
                validated_actions.append(validated)

        # --- Apply actions to client settings ---
        applied = False
        if validated_actions and db and client_id:
            applied = await self._apply_actions(validated_actions, client_id, db)

        # --- Audit log ---
        await self._log_audit(
            db=db,
            client_id=client_id,
            action="ai_configure",
            input_summary=cleaned[:200],
            ai_reasoning=content[:500],
            decision=json.dumps(validated_actions)[:500],
            model_used=result.get("model_used"),
            tokens_used=result.get("tokens_used"),
            latency_ms=result.get("latency_ms"),
        )

        return {
            "understood": understood,
            "actions": validated_actions,
            "applied": applied,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_ai_response(self, content: str) -> Optional[dict]:
        """Extract JSON from AI response, handling markdown fences."""
        if not content:
            return None

        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            # Remove first and last fence lines
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            content = "\n".join(lines)

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to find JSON object in the string
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            return None

    def _validate_action(self, action: dict) -> Optional[dict]:
        """Validate a single action against the whitelist.

        Returns the sanitised action dict, or None if invalid.
        """
        action_type = action.get("type", "")

        if action_type in ("update_setting", "update_scan_interval", "configure_notification"):
            key = action.get("key", "")
            value = action.get("value")
            if key not in ALLOWED_SETTING_KEYS:
                logger.warning(f"Disallowed setting key: {key}")
                return None
            return {"type": action_type, "key": key, "value": value}

        elif action_type == "update_guardrail":
            key = action.get("key", "")
            value = action.get("value", "")
            if key not in ALLOWED_SETTING_KEYS:
                logger.warning(f"Disallowed guardrail key: {key}")
                return None
            if value not in GUARDRAIL_VALUES:
                logger.warning(f"Invalid guardrail value: {value}")
                return None
            return {"type": action_type, "key": key, "value": value}

        elif action_type == "add_asset":
            hostname = str(action.get("hostname", ""))[:255]
            ip = str(action.get("ip", ""))[:45]
            asset_type = str(action.get("type", "server"))[:50]
            if not hostname and not ip:
                return None
            return {"type": action_type, "hostname": hostname, "ip": ip, "asset_type": asset_type}

        elif action_type == "deploy_honeypot":
            hp_type = str(action.get("type", "http"))[:50]
            port = action.get("port")
            if isinstance(port, (int, float)):
                port = int(port)
            else:
                port = None
            return {"type": action_type, "honeypot_type": hp_type, "port": port}

        elif action_type == "update_ai_provider":
            provider = str(action.get("provider", ""))[:100]
            if not provider:
                return None
            return {"type": action_type, "provider": provider}

        return None

    async def _apply_actions(
        self,
        actions: list[dict],
        client_id: str,
        db: AsyncSession,
    ) -> bool:
        """Apply validated actions to the client's settings in the database."""
        from app.models.client import Client
        from sqlalchemy import select

        result = await db.execute(select(Client).where(Client.id == client_id))
        client = result.scalar_one_or_none()
        if not client:
            logger.error(f"Client {client_id} not found for applying configuration")
            return False

        settings_dict: dict = dict(client.settings or {})
        guardrails_dict: dict = dict(client.guardrails or {})
        modified = False

        for action in actions:
            action_type = action["type"]

            if action_type in ("update_setting", "update_scan_interval", "configure_notification"):
                key = action["key"]
                value = action["value"]

                if key.startswith("guardrails."):
                    # Redirect to guardrails dict
                    g_key = key.split(".", 1)[1]
                    guardrails_dict[g_key] = value
                elif key.startswith("scan_intervals."):
                    intervals = settings_dict.get("scan_intervals", {})
                    i_key = key.split(".", 1)[1]
                    intervals[i_key] = value
                    settings_dict["scan_intervals"] = intervals
                else:
                    settings_dict[key] = value
                modified = True

            elif action_type == "update_guardrail":
                key = action["key"]
                value = action["value"]
                if key.startswith("guardrails."):
                    g_key = key.split(".", 1)[1]
                    guardrails_dict[g_key] = value
                else:
                    guardrails_dict[key] = value
                modified = True

            elif action_type == "update_ai_provider":
                settings_dict["ai_provider"] = action["provider"]
                modified = True

            # add_asset and deploy_honeypot are logged but not applied here
            # (they require separate service calls)

        if modified:
            client.settings = settings_dict
            client.guardrails = guardrails_dict
            await db.commit()
            logger.info(f"Applied {len(actions)} configuration actions for client {client_id}")

        return modified

    async def _log_audit(
        self,
        db: Optional[AsyncSession],
        client_id: str,
        action: str,
        input_summary: str = "",
        ai_reasoning: str = "",
        decision: str = "",
        model_used: Optional[str] = None,
        tokens_used: Optional[int] = None,
        latency_ms: Optional[int] = None,
        confidence: Optional[float] = None,
    ) -> None:
        """Write an entry to the audit log."""
        if not db:
            logger.info(f"Audit (no db): action={action} input={input_summary[:80]}")
            return

        try:
            entry = AuditLog(
                client_id=client_id,
                action=action,
                input_summary=input_summary,
                ai_reasoning=ai_reasoning,
                decision=decision,
                model_used=model_used,
                tokens_used=tokens_used,
                latency_ms=latency_ms,
                confidence=confidence,
                timestamp=datetime.utcnow(),
            )
            db.add(entry)
            await db.commit()
        except Exception as exc:
            logger.error(f"Failed to write audit log: {exc}")


# Singleton
ai_configurator = AIConfigurator()
