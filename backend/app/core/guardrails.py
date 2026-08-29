import ipaddress
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Client
from app.models.action import Action
from app.core.events import event_bus
from app.core.attack_detector import _is_safe_ip

logger = logging.getLogger("aegis.guardrails")

# Action types whose target is an IP — guard against blocking safe IPs.
_IP_TARGET_ACTIONS = frozenset({"block_ip", "firewall_rule", "isolate_host", "network_segment"})

# Action types for which an IP address can never be a valid target: an address
# is not a process, a file, an account or a service name. Callers that fall
# back to the alert's source_ip produced targets like kill_process on
# "185.177.72.8", which can only fail. ai_engine now resolves targets per
# action type (see resolve_action_target); this is the chokepoint guard that
# covers every other caller. isolate_host and network_segment are deliberately
# excluded — an IP is a plausible identifier for an internal host.
_NON_IP_TARGET_ACTIONS = frozenset({
    "kill_process", "quarantine_file", "revoke_creds",
    "disable_account", "shutdown_service",
})


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False

# Default guardrail policies.
# Low-impact / reversible actions (blocking an IP, adding a firewall rule,
# read-only intel lookups, abuse reporting) are auto-approved. Destructive or
# legally-sensitive actions (host isolation, credential revocation, service
# shutdown, network segmentation, process/file destructive ops, active
# counter-attack/recon against third-party infrastructure, deception,
# tarpitting) default to require_approval so a human signs off before AEGIS
# acts. Users can still override any of these per-client in client.guardrails.
DEFAULT_GUARDRAILS = {
    "block_ip": "auto_approve",
    "isolate_host": "require_approval",
    "revoke_creds": "require_approval",
    "shutdown_service": "require_approval",
    "firewall_rule": "auto_approve",
    "quarantine_file": "require_approval",
    "kill_process": "require_approval",
    "disable_account": "require_approval",
    "network_segment": "require_approval",
    "custom": "auto_approve",
    # Counter-attack actions (active defense) — require_approval: recon touches
    # third-party infrastructure and carries legal risk; counter_attack/
    # deception/tarpit are similarly consequential and must be human-gated.
    "counter_attack": "require_approval",
    "recon_attacker": "require_approval",
    "intel_lookup": "auto_approve",
    "deception": "require_approval",
    "report_abuse": "auto_approve",
    "tarpit": "require_approval",
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
        # SAFE-IP guard: short-circuit IP-targeted actions for safe IPs.
        # This runs BEFORE policy evaluation so even auto_approve cannot bypass it.
        if action_type in _IP_TARGET_ACTIONS and target and _is_safe_ip(target):
            logger.warning(
                f"GUARDRAIL: Refusing {action_type} on safe IP {target} "
                f"(AEGIS_SAFE_IPS). Creating skipped Action."
            )
            action = Action(
                incident_id=incident_id or "",
                client_id=client.id,
                action_type=action_type,
                target=target,
                parameters={},
                status="skipped_safe_ip",
                requires_approval=False,
                ai_reasoning=f"BLOCKED by safe-IP guardrail. AI reasoning: {ai_reasoning}",
            )
            db.add(action)
            await db.commit()
            await db.refresh(action)
            await event_bus.publish("action_skipped_safe_ip", {
                "action_id": str(action.id),
                "action_type": action_type,
                "target": target,
                "incident_id": str(incident_id) if incident_id else "",
            })
            return action

        # An IP is never a process / file / account / service. A caller that
        # fell back to the source IP would dispatch an action that can only
        # fail and surface as a red error the operator cannot act on.
        if action_type in _NON_IP_TARGET_ACTIONS and target and _looks_like_ip(target):
            reason = (
                f"target {target} is an IP address; {action_type} needs a local "
                f"process/file/account/service entity"
            )
            logger.warning(f"GUARDRAIL: Refusing {action_type} — {reason}")
            action = Action(
                incident_id=incident_id or "",
                client_id=client.id,
                action_type=action_type,
                target=target,
                parameters={"not_applicable": True, "reason": reason},
                status="skipped_not_applicable",
                requires_approval=False,
                ai_reasoning=(
                    f"Not applicable: {reason}. No system change was attempted. "
                    f"AI reasoning: {ai_reasoning}"
                ),
            )
            db.add(action)
            await db.commit()
            await db.refresh(action)
            await event_bus.publish("action_not_applicable", {
                "action_id": str(action.id),
                "action_type": action_type,
                "target": target,
                "incident_id": str(incident_id) if incident_id else "",
                "reason": reason,
            })
            return action

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
