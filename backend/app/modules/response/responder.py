import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.attack_detector import _is_safe_ip
from app.core.events import event_bus
from app.core.ip_blocker import ip_blocker_service
from app.core.firewall_client import firewall_client
from app.models.action import Action
import app.services.firewall_local as firewall_local

logger = logging.getLogger("cayde6.responder")
fw_logger = logging.getLogger("aegis.responder.fw")

# Action types whose target is an IP and which must be guarded by AEGIS_SAFE_IPS.
_IP_TARGET_ACTIONS = frozenset({"block_ip", "firewall_rule", "isolate_host", "network_segment"})


class ActiveResponder:
    """Execute response actions (block IP, isolate host, etc.)."""

    async def execute_action(self, action: Action, db: AsyncSession) -> dict:
        """Execute an approved response action."""
        if action.status not in ("approved",):
            return {"success": False, "error": "Action not approved"}

        # SAFE-IP GUARD: never execute IP-targeted actions against safe IPs
        # (Googlebot ranges, Tailscale CGNAT, RFC1918, etc.). Even auto-approved
        # actions go through this check. See AEGIS_SAFE_IPS env var.
        if action.action_type in _IP_TARGET_ACTIONS and action.target and _is_safe_ip(action.target):
            logger.warning(
                f"RESPONDER: Refusing to execute {action.action_type} on safe IP "
                f"{action.target} (matches AEGIS_SAFE_IPS). action_id={action.id}"
            )
            action.status = "skipped_safe_ip"
            action.result = {"success": False, "skipped": "safe_ip", "target": action.target}
            action.executed_at = datetime.utcnow()
            if action.client_id:
                await log_audit(
                    db, f"action_{action.action_type}_skipped",
                    f"{action.action_type} on {action.target} SKIPPED (safe IP)",
                    client_id=action.client_id,
                )
            await db.commit()
            await event_bus.publish("action_skipped_safe_ip", {
                "action_id": action.id,
                "client_id": action.client_id,
                "action_type": action.action_type,
                "target": action.target,
            })
            return action.result

        executor = self._get_executor(action.action_type)
        result = await executor(action.target, action.parameters)

        action.status = "executed" if result["success"] else "failed"
        action.result = result
        action.executed_at = datetime.utcnow()

        # Audit log for security-relevant actions (especially IP blocks)
        if action.client_id:
            await log_audit(
                db, f"action_{action.action_type}",
                f"{action.action_type} on {action.target} — {'success' if result['success'] else 'failed'}",
                client_id=action.client_id,
            )

        await db.commit()

        await event_bus.publish("action_executed", {
            "action_id": action.id,
            "client_id": action.client_id,
            "incident_id": action.incident_id,
            "action_type": action.action_type,
            "target": action.target,
            "success": result["success"],
        })

        logger.info(
            f"Action {action.action_type} on {action.target}: "
            f"{'success' if result['success'] else 'failed'}"
        )
        return result

    async def rollback_action(self, action: Action, db: AsyncSession) -> dict:
        """Rollback a previously executed action."""
        if action.status != "executed":
            return {"success": False, "error": "Action not in executed state"}

        rollback_fn = self._get_rollback(action.action_type)
        result = await rollback_fn(action.target, action.parameters)

        if result["success"]:
            action.status = "rolled_back"
            action.result = {**(action.result or {}), "rollback": result}
            await db.commit()

        return result

    def _get_executor(self, action_type: str):
        executors = {
            "block_ip": self._block_ip,
            "firewall_rule": self._add_firewall_rule,
            "isolate_host": self._isolate_host,
            "kill_process": self._kill_process,
            "quarantine_file": self._quarantine_file,
            "revoke_creds": self._revoke_credentials,
            "disable_account": self._disable_account,
            "shutdown_service": self._shutdown_service,
            "network_segment": self._network_segment,
        }
        return executors.get(action_type, self._generic_action)

    def _get_rollback(self, action_type: str):
        rollbacks = {
            "block_ip": self._unblock_ip,
            "firewall_rule": self._remove_firewall_rule,
            "isolate_host": self._unisolate_host,
        }
        return rollbacks.get(action_type, self._generic_rollback)

    # Action executors -- these produce structured results.
    # In production, these would call iptables/firewalld/API.
    # For safety, they log intent rather than making system changes directly.

    async def _block_ip(self, target: str, params: dict) -> dict:
        if not target:
            logger.warning("RESPONSE: block_ip called with empty target, skipping")
            return {"success": False, "action": "block_ip", "target": target, "error": "No target IP"}

        # Defense in depth: even if a caller bypasses execute_action() guard,
        # never block a safe IP at the _block_ip level.
        if _is_safe_ip(target):
            logger.warning(f"RESPONSE: Refusing to block safe IP {target} (AEGIS_SAFE_IPS)")
            return {"success": False, "action": "block_ip", "target": target, "skipped": "safe_ip"}

        logger.warning(f"RESPONSE: Blocking IP {target} — executing real block")

        # 1. Block via external firewall (if AEGIS_FIREWALL_URL is configured)
        firewall_result = await firewall_client.block_ip(target)
        logger.info(f"Firewall block result for {target}: {firewall_result}")

        # 2. Block locally via ip_blocker_service (blocked_ips.txt + in-memory set → 403 middleware)
        local_result = ip_blocker_service.block_ip(target)
        logger.info(f"Local block result for {target}: {local_result}")

        # 3. System-level firewall (pfctl / iptables) — gated by AEGIS_REAL_FW=1
        try:
            fw_ok = firewall_local.get_firewall().block(target)
            if fw_ok:
                fw_logger.info(f"System firewall blocked {target} successfully")
            else:
                fw_logger.warning(f"System firewall block returned False for {target} (non-fatal)")
        except Exception as e:
            fw_logger.error(f"System firewall block raised for {target}: {e} (non-fatal, continuing)")
            fw_ok = False

        return {
            "success": True,
            "action": "block_ip",
            "target": target,
            "firewall": firewall_result,
            "local": local_result,
            "system_fw": fw_ok,
        }

    async def _unblock_ip(self, target: str, params: dict) -> dict:
        logger.info(f"ROLLBACK: Unblocking IP {target}")

        # System-level unblock — gated by AEGIS_REAL_FW=1
        try:
            fw_ok = firewall_local.get_firewall().unblock(target)
            if fw_ok:
                fw_logger.info(f"System firewall unblocked {target} successfully")
            else:
                fw_logger.warning(f"System firewall unblock returned False for {target} (non-fatal)")
        except Exception as e:
            fw_logger.error(f"System firewall unblock raised for {target}: {e} (non-fatal)")
            fw_ok = False

        return {
            "success": True,
            "action": "unblock_ip",
            "target": target,
            "system_fw": fw_ok,
        }

    async def _add_firewall_rule(self, target: str, params: dict) -> dict:
        logger.info(f"RESPONSE: Adding firewall rule for {target}")
        return {"success": True, "action": "firewall_rule", "target": target}

    async def _remove_firewall_rule(self, target: str, params: dict) -> dict:
        return {"success": True, "action": "remove_firewall_rule", "target": target}

    async def _isolate_host(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: isolate_host requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "isolate_host", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _unisolate_host(self, target: str, params: dict) -> dict:
        return {"success": True, "action": "unisolate_host", "target": target}

    async def _kill_process(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: kill_process requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "kill_process", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _quarantine_file(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: quarantine_file requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "quarantine_file", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _revoke_credentials(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: revoke_creds requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "revoke_creds", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _disable_account(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: disable_account requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "disable_account", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _shutdown_service(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: shutdown_service requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "shutdown_service", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _network_segment(self, target: str, params: dict) -> dict:
        logger.info("RESPONSE: network_segment requested for %s (not implemented)", target)
        return {"success": False, "status": "not_implemented",
                "action": "network_segment", "target": target,
                "detail": "This response action is not yet implemented; no system change was made."}

    async def _generic_action(self, target: str, params: dict) -> dict:
        logger.info(f"RESPONSE: Generic action on {target}")
        return {"success": True, "action": "generic", "target": target}

    async def _generic_rollback(self, target: str, params: dict) -> dict:
        return {"success": False, "error": "No rollback available for this action type"}


active_responder = ActiveResponder()
