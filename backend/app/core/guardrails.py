import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Client
from app.models.action import Action
from app.core.events import event_bus

logger = logging.getLogger("aegis.guardrails")

# Default guardrail policies — AEGIS runs fully autonomous by default.
# Users can override any of these in client.guardrails to require manual approval.
DEFAULT_GUARDRAILS = {
    "block_ip": "auto_approve",
    "isolate_host": "auto_approve",
    "revoke_creds": "auto_approve",
    "shutdown_service": "auto_approve",
    "firewall_rule": "auto_approve",
    "quarantine_file": "auto_approve",
    "kill_process": "auto_approve",
    "disable_account": "auto_approve",
    "network_segment": "auto_approve",
    "custom": "auto_approve",
    # Counter-attack actions (active defense)
    "counter_attack": "auto_approve",
    "recon_attacker": "auto_approve",
    "intel_lookup": "auto_approve",
    "deception": "auto_approve",
    "report_abuse": "auto_approve",
    "tarpit": "auto_approve",
}

# Valid approval levels
APPROVAL_LEVELS = {"auto_approve", "require_approval", "never_auto"}


class GuardrailEngine:
    """Action approval system that classifies and gates response actions."""

    def get_policy(self, client: Client, action_type: str) -> str:
        client_guardrails = client.guardrails or {}
        return client_guardrails.get(
            action_type,
            DEFAULT_GUARDRAILS.get(action_type, "auto_approve"),
        )

    async def evaluate_action(
        self,
        client: Client,
        action_type: str,
        target: str,
        ai_reasoning: str,
        db: AsyncSession,
        incident_id: Optional[str] = None,
    ) -> Action:
        """Evaluate an action against guardrail policies and create an Action record."""
        policy = self.get_policy(client, action_type)

        if policy == "never_auto":
            status = "pending"
            requires_approval = True
            logger.warning(
                f"Action '{action_type}' on '{target}' blocked by never_auto policy"
            )
        elif policy == "require_approval":
            status = "pending"
            requires_approval = True
            logger.info(
                f"Action '{action_type}' on '{target}' requires approval"
            )
        else:  # auto_approve
            status = "approved"
            requires_approval = False
            logger.info(
                f"Action '{action_type}' on '{target}' auto-approved"
            )

        action = Action(
            incident_id=incident_id or "",
            client_id=client.id,
            action_type=action_type,
            target=target,
            parameters={},
            status=status,
            requires_approval=requires_approval,
            ai_reasoning=ai_reasoning,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)

        if requires_approval:
            await event_bus.publish("action_requires_approval", {
                "action_id": action.id,
                "client_id": action.client_id,
                "incident_id": action.incident_id,
                "action_type": action.action_type,
                "target": action.target,
            })
        else:
            await event_bus.publish("action_auto_approved", {
                "action_id": str(action.id),
                "action_type": action_type,
                "target": target,
                "incident_id": str(incident_id) if incident_id else "",
            })
        return action

    async def approve_action(self, action: Action, approved_by: str, db: AsyncSession) -> Action:
        action.status = "approved"
        action.approved_by = approved_by
        await db.commit()
        await db.refresh(action)
        return action

    async def reject_action(self, action: Action, db: AsyncSession) -> Action:
        action.status = "failed"
        await db.commit()
        await db.refresh(action)
        return action


guardrail_engine = GuardrailEngine()
