import ipaddress
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Client
from app.models.action import Action
from app.core.events import event_bus
from app.core.attack_detector import _is_safe_ip, is_shared_egress
from app.services import authored_rules_registry as authored_rules

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
def validate_guardrail_config(config) -> dict:
    """Return a clean {action_type: policy} dict or raise ValueError."""
    if not isinstance(config, dict):
        raise ValueError("guardrails must be an object")
    if len(config) > 64:
        raise ValueError("too many guardrail entries")
    clean: dict = {}
    for action_type, policy in config.items():
        if not isinstance(action_type, str) or not action_type or len(action_type) > 64:
            raise ValueError("invalid guardrail action type")
        if policy not in APPROVAL_LEVELS:
            raise ValueError(
                f"invalid policy {policy!r} for '{action_type}': use one of {sorted(APPROVAL_LEVELS)}"
            )
        clean[action_type] = policy
    return clean


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
    # Record-only step the engine recommends for honeypot recon: it changes
    # nothing on any system, so it needs no approval. Declared here because an
    # UNDECLARED action type is now held for approval.
    "collect_evidence": "auto_approve",
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


async def _alert_only_reason(db: AsyncSession, incident_id: Optional[str], alert_data: Optional[dict]) -> Optional[str]:
    """Why this block must wait for a human because an alert-only rule raised it.

    Fast path: no authored rules on disk -> nothing to look up, so the common
    case costs one directory scan and no query. Fails CLOSED: if authored rules
    exist and the incident cannot be read, the block waits for approval.
    """
    if not authored_rules.states():
        return None
    from app.services.block_ttl import collect_rule_ids
    try:
        alert = alert_data
        if alert is None and incident_id:
            from app.models.incident import Incident
            inc = await db.get(Incident, incident_id)
            alert = inc.raw_alert if inc is not None and isinstance(inc.raw_alert, dict) else {}
        hit = authored_rules.blocking_held_by(collect_rule_ids(alert or {}))
    except Exception as exc:
        logger.warning(f"GUARDRAIL: could not verify rule provenance ({exc}); holding block for approval")
        return "Rule provenance could not be verified while authored rules exist; holding for approval."
    if hit:
        logger.warning(f"GUARDRAIL: block held for approval, raised by alert-only authored rule(s) {hit}")
        return f"Raised by alert-only authored rule(s) {', '.join(hit)}: not auto-blocked until an operator approves."
    return None


def endpoint_reported_peer(alert_data: Optional[dict], target: Optional[str]) -> bool:
    """True when `target` is an address that only an endpoint agent vouches for.

    EDR network events put the remote peer of a connection in source_ip, on the
    agent's say-so. AEGIS never saw that traffic. One node (compromised, or just
    wrong) must not be able to have an arbitrary external address blocked, so
    these blocks are held for approval unless AEGIS_EDR_NETWORK_AUTOBLOCK is on.
    """
    if not target or not isinstance(alert_data, dict):
        return False
    try:
        from app.config import settings as _settings
        if _settings.AEGIS_EDR_NETWORK_AUTOBLOCK:
            return False
    except Exception:
        pass
    event = alert_data.get("triggering_event")
    event = event if isinstance(event, dict) else alert_data
    if not (event.get("agent_id") or alert_data.get("agent_id")):
        return False
    named = {str(event.get(k)) for k in ("_gate_ip", "remote_ip", "destination_ip") if event.get(k)}
    return str(target) in named


class GuardrailEngine:
    """Action approval system that classifies and gates response actions."""

    def get_policy(self, client: Client, action_type: str) -> str:
        """Policy for `action_type`, failing CLOSED.

        An action type nobody declared and a stored value that is not one of
        the three policies both used to mean "auto_approve": a typo in the
        settings, or a new action type, silently became fully automatic.
        """
        client_guardrails = client.guardrails or {}
        policy = client_guardrails.get(action_type, DEFAULT_GUARDRAILS.get(action_type))
        if policy not in APPROVAL_LEVELS:
            if policy is not None:
                logger.warning(
                    f"GUARDRAIL: invalid policy {policy!r} for '{action_type}'; holding for approval"
                )
            return "require_approval"
        return policy

    async def evaluate_action(
        self,
        client: Client,
        action_type: str,
        target: str,
        ai_reasoning: str,
        db: AsyncSession,
        incident_id: Optional[str] = None,
        alert_data: Optional[dict] = None,
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

        # An address named only by an endpoint agent (see endpoint_reported_peer).
        if (
            action_type in _IP_TARGET_ACTIONS
            and policy == "auto_approve"
            and endpoint_reported_peer(alert_data, target)
        ):
            policy = "require_approval"
            ai_reasoning = (
                f"{target} was reported by an endpoint agent, not observed by AEGIS itself: "
                f"not auto-blocked, awaiting operator approval. AI reasoning: {ai_reasoning}"
            )

        # Shared consumer egress (WARP / Private Relay): thousands of real users
        # sit behind one address, so a block is never safe to automate. The
        # incident still exists; only the block waits for a human. never_auto
        # is already stricter, so it is left alone.
        if (
            action_type in _IP_TARGET_ACTIONS
            and policy == "auto_approve"
            and target
            and is_shared_egress(target)
        ):
            policy = "require_approval"
            ai_reasoning = (
                f"{target} is shared consumer egress (WARP / iCloud Private Relay): "
                f"not auto-blocked, awaiting operator approval. AI reasoning: {ai_reasoning}"
            )

        # An alert-only rule (every AI-authored rule until an operator approves
        # it) may raise incidents but never block by itself. Same lever as the
        # shared-egress rule above: the incident stands, the block waits.
        if action_type in _IP_TARGET_ACTIONS and policy == "auto_approve":
            held = await _alert_only_reason(db, incident_id, alert_data)
            if held:
                policy = "require_approval"
                ai_reasoning = f"{held} AI reasoning: {ai_reasoning}"

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
