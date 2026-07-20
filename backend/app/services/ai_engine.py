"""
Agentic AI decision engine with sub-300ms fast path.

Two processing modes:
  1. fast_triage() — deterministic, no AI, <300ms total:
       Event → Sigma check → IOC cache → Playbook auto-action → WS push
  2. process_alert() — full AI chain for complex/unknown threats:
       Event → AI triage → AI classify → Incident → Actions → Audit

For 80%+ of attacks, fast_triage handles everything. AI enrichment
runs async in background to supplement the already-created incident.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client, MODEL_ROUTING
from app.core.ai_mode import degrade_or_call, ai_available, MODE, AIMode
from app.core.guardrails import guardrail_engine
from app.core.events import event_bus
from app.models.client import Client
from app.models.incident import Incident
from app.models.audit_log import AuditLog

logger = logging.getLogger("aegis.ai_engine")

# MITRE ATT&CK common mappings
MITRE_MAPPINGS = {
    "brute_force": {"technique": "T1110", "tactic": "Credential Access"},
    "port_scan": {"technique": "T1046", "tactic": "Discovery"},
    "sql_injection": {"technique": "T1190", "tactic": "Initial Access"},
    "xss": {"technique": "T1059.007", "tactic": "Execution"},
    "rce": {"technique": "T1059", "tactic": "Execution"},
    "phishing": {"technique": "T1566", "tactic": "Initial Access"},
    "lateral_movement": {"technique": "T1021", "tactic": "Lateral Movement"},
    "data_exfiltration": {"technique": "T1041", "tactic": "Exfiltration"},
    "privilege_escalation": {"technique": "T1068", "tactic": "Privilege Escalation"},
    "malware": {"technique": "T1204", "tactic": "Execution"},
    "c2_communication": {"technique": "T1071", "tactic": "Command and Control"},
    "credential_dumping": {"technique": "T1003", "tactic": "Credential Access"},
    "dns_tunneling": {"technique": "T1071.004", "tactic": "Command and Control"},
    "web_shell": {"technique": "T1505.003", "tactic": "Persistence"},
    "ransomware": {"technique": "T1486", "tactic": "Impact"},
}

# Response action recommendations per threat type
RESPONSE_ACTIONS = {
    "brute_force": ["block_ip", "disable_account"],
    "port_scan": ["block_ip", "firewall_rule"],
    "sql_injection": ["block_ip", "firewall_rule"],
    "xss": ["firewall_rule"],
    "rce": ["block_ip", "isolate_host", "kill_process"],
    "phishing": ["block_ip", "disable_account", "revoke_creds"],
    "lateral_movement": ["isolate_host", "network_segment"],
    "data_exfiltration": ["block_ip", "isolate_host", "network_segment"],
    "privilege_escalation": ["isolate_host", "revoke_creds", "kill_process"],
    "malware": ["isolate_host", "quarantine_file", "kill_process"],
    "c2_communication": ["block_ip", "isolate_host"],
    "credential_dumping": ["isolate_host", "revoke_creds"],
    "web_shell": ["quarantine_file", "isolate_host"],
    "ransomware": ["isolate_host", "network_segment", "shutdown_service"],
    "honeypot_recon": ["block_ip", "collect_evidence"],
}

# Map sigma rule IDs to threat types for fast path
SIGMA_TO_THREAT_TYPE = {
    "brute_force_ssh": "brute_force",
    "rdp_brute_force": "brute_force",
    "credential_stuffing": "brute_force",
    "lateral_movement": "lateral_movement",
    "data_exfiltration": "data_exfiltration",
    "port_scan": "port_scan",
    "sql_injection_chain": "sql_injection",
    "dns_tunneling": "dns_tunneling",
    "c2_beacon": "c2_communication",
    "web_shell_activity": "web_shell",
    "privilege_escalation": "privilege_escalation",
    "xss_attack_chain": "xss",
    "http_auth_brute_force": "brute_force",
    "ssh_honeypot_attempt": "honeypot_recon",
    "generic_credential_attack": "brute_force",
}


class AIDecisionEngine:
    """Agentic AI decision engine with deterministic fast path."""

    def __init__(self):
        self._fast_triage_stats = {
            "total": 0,
            "avg_ms": 0.0,
            "total_ms": 0.0,
            "playbook_hits": 0,
            "ai_enrichments_queued": 0,
        }

    # ------------------------------------------------------------------
    # FAST PATH: sub-300ms deterministic triage
    # ------------------------------------------------------------------

    async def fast_triage(
        self,
        event: dict,
        sigma_matches: list[dict],
        ioc_check: Optional[dict] = None,
    ) -> dict:
        """
        Deterministic fast triage. No AI calls. Target: <300ms total.

        Flow:
          1. Event arrives (<5ms)
          2. Sigma correlation check (already done by caller, <50ms)
          3. IOC cache check (already done by caller, <5ms)
          4. If Sigma matches + bad IOC -> auto-action via playbook (<50ms)
          5. AI called async in background to enrich (800ms but non-blocking)
          6. WebSocket push to dashboard (<10ms)
          7. Total: <300ms
        """
        start_ns = time.monotonic_ns()
        self._fast_triage_stats["total"] += 1

        # Resolve the safelist gate ONCE, up front, so every decision below
        # (incident creation, AI enrichment, the WS payload itself) reflects
        # it consistently. Cheap: O(1) set lookup + small CIDR loop.
        source_ip = event.get("source_ip")
        is_safe_source = False
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                is_safe_source = _is_safe_ip(source_ip)
            except Exception:
                is_safe_source = False

        result = {
            "triage_id": str(uuid.uuid4()),
            "triage_type": "fast",
            "event": event,
            "sigma_matches": sigma_matches,
            "ioc_check": ioc_check,
            "playbook_results": [],
            "actions_taken": [],
            "incident_created": False,
            "ai_enrichment_queued": False,
            "safelisted": is_safe_source,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Determine threat type from sigma matches
        threat_type = "unknown"
        severity = "medium"
        for match in sigma_matches:
            rule_id = match.get("id", match.get("rule_id", ""))
            if rule_id in SIGMA_TO_THREAT_TYPE:
                threat_type = SIGMA_TO_THREAT_TYPE[rule_id]
            match_sev = match.get("severity", "medium")
            if _severity_order(match_sev) > _severity_order(severity):
                severity = match_sev

        result["threat_type"] = threat_type
        result["severity"] = severity

        # Boost severity if IOC is malicious
        if ioc_check and ioc_check.get("verdict") == "malicious":
            if _severity_order(severity) < _severity_order("high"):
                severity = "high"
                result["severity"] = severity
                result["severity_boosted"] = True

        # Execute playbooks if we have sigma matches
        if sigma_matches:
            from app.services.playbook_engine import playbook_engine
            matched_playbooks = playbook_engine.evaluate(event, sigma_matches, ioc_check)

            for playbook in matched_playbooks:
                pb_result = await playbook_engine.execute_playbook(playbook, event)
                result["playbook_results"].append(pb_result)
                result["actions_taken"].extend(pb_result.get("actions", []))
                self._fast_triage_stats["playbook_hits"] += 1

        # Build a human-readable title for the incident
        rule_titles = [m.get("title", m.get("rule_title", "")) for m in sigma_matches]
        incident_title = f"{severity.upper()}: {', '.join(filter(None, rule_titles)) or threat_type.replace('_', ' ').title()}"
        result["incident_title"] = incident_title
        result["incident_severity"] = severity
        result["source_ip"] = source_ip

        # Always create an incident record when we have sigma matches --
        # UNLESS the source IP is safelisted (AEGIS_SAFE_IPS/AEGIS_INTERNAL_IPS,
        # private ranges, or a published crawler CIDR). Checked up front so
        # the WS payload's `incident_created` flag is never a lie: previously
        # this was set True unconditionally and only the fire-and-forget
        # `_create_fast_incident` task (running after this function had
        # already returned) decided whether to actually skip the DB write.
        if is_safe_source:
            if sigma_matches or result["actions_taken"]:
                logger.debug(
                    f"fast_triage: suppressing incident for safelisted IP "
                    f"{source_ip} (threat={threat_type})"
                )
        elif sigma_matches or result["actions_taken"]:
            result["incident_created"] = True
            asyncio.create_task(
                self._create_fast_incident(event, threat_type, severity, sigma_matches, result)
            )

        # Queue async AI enrichment for complex analysis (non-blocking).
        # Skipped for safelisted IPs too -- no incident will exist for it to
        # enrich, so this would just be a wasted AI call.
        if not is_safe_source and (sigma_matches or (ioc_check and ioc_check.get("verdict") != "clean")):
            result["ai_enrichment_queued"] = True
            self._fast_triage_stats["ai_enrichments_queued"] += 1
            asyncio.create_task(
                self._async_ai_enrich(event, threat_type, severity, sigma_matches, ioc_check)
            )

        # Timing
        elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000
        result["elapsed_ms"] = round(elapsed_ms, 2)

        self._fast_triage_stats["total_ms"] += elapsed_ms
        self._fast_triage_stats["avg_ms"] = (
            self._fast_triage_stats["total_ms"] / self._fast_triage_stats["total"]
        )

        # Publish to event bus for WS push (<10ms)
        await event_bus.publish("fast_triage_completed", result)

        logger.info(
            f"[FAST_TRIAGE] {elapsed_ms:.1f}ms | threat={threat_type} | "
            f"severity={severity} | sigma={len(sigma_matches)} | "
            f"playbooks={len(result['playbook_results'])} | "
            f"actions={len(result['actions_taken'])}"
        )

        return result

    async def _create_fast_incident(
        self,
        event: dict,
        threat_type: str,
        severity: str,
        sigma_matches: list[dict],
        triage_result: dict,
    ):
        """Create an incident record in the DB (async, non-blocking)."""
        source_ip = event.get("source_ip")
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                if _is_safe_ip(source_ip):
                    logger.debug(f"fast_triage: skipping incident for safe IP {source_ip} (threat={threat_type})")
                    return
            except Exception:
                pass
        try:
            from app.database import async_session
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(
                    select(Client).order_by(Client.created_at.asc()).limit(1)
                )
                client = result.scalar_one_or_none()
                if not client:
                    logger.error("Fast triage: no client found for incident creation")
                    return

                mitre = MITRE_MAPPINGS.get(threat_type, {})
                rule_titles = [m.get("title", m.get("rule_title", "")) for m in sigma_matches]

                sigma_rule_ids = [m.get("id", m.get("rule_id")) for m in sigma_matches]
                incident = Incident(
                    client_id=client.id,
                    title=f"{severity.upper()}: {', '.join(rule_titles) or 'Fast triage detection'}",
                    description=f"Auto-detected via fast triage pipeline. Threat type: {threat_type}.",
                    severity=severity,
                    status="auto_responded",
                    source="fast_triage",
                    mitre_technique=mitre.get("technique"),
                    mitre_tactic=mitre.get("tactic"),
                    source_ip=event.get("source_ip"),
                    ai_analysis={
                        "triage_type": "fast",
                        "threat_type": threat_type,
                        "sigma_matches": sigma_rule_ids,
                        "actions_taken": len(triage_result.get("actions_taken", [])),
                        "elapsed_ms": triage_result.get("elapsed_ms"),
                        "_origin": {
                            "kind": "algorithm",
                            "source": "fast_triage",
                            "rules": sigma_rule_ids,
                            "ts": datetime.utcnow().isoformat(),
                        },
                    },
                    raw_alert=event,
                )
                db.add(incident)
                await db.commit()

                logger.info(f"Fast triage incident created: {incident.id}")

        except Exception as e:
            logger.error(f"Failed to create fast triage incident: {e}")

    async def _async_ai_enrich(
        self,
        event: dict,
        threat_type: str,
        severity: str,
        sigma_matches: list[dict],
        ioc_check: Optional[dict],
    ):
        """
        Background AI enrichment. Runs after fast triage has already taken action.
        Non-blocking, typically 800-1200ms. Enriches the incident with AI insights.
        Skipped entirely when AI mode is disabled.
        """
        if not ai_available():
            logger.debug("AI enrichment skipped (AI mode disabled)")
            return

        try:
            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Enrich this security event with additional context:\n"
                        f"Event: {json.dumps(event, default=str)}\n"
                        f"Threat type: {threat_type}\n"
                        f"Severity: {severity}\n"
                        f"Sigma matches: {json.dumps([m.get('id', m.get('rule_id')) for m in sigma_matches], default=str)}\n"
                        f"IOC check: {json.dumps(ioc_check, default=str) if ioc_check else 'N/A'}\n"
                        f"Provide: kill chain stage, additional IOCs to check, lateral movement risk assessment."
                    ),
                }
            ]
            response = await openrouter_client.query(messages, "triage")
            enrichment = self._parse_json_response(response.get("content", "{}"), {
                "enrichment": "AI enrichment completed",
                "kill_chain_stage": "unknown",
                "lateral_risk": "unknown",
                "additional_iocs": [],
            })

            # Update the incident in DB with AI enrichment
            source_ip = event.get("source_ip")
            if source_ip:
                from app.database import async_session
                from sqlalchemy import select

                async with async_session() as db:
                    result = await db.execute(
                        select(Incident).where(
                            Incident.source_ip == source_ip,
                            Incident.source == "fast_triage",
                        ).order_by(Incident.created_at.desc()).limit(1)
                    )
                    incident = result.scalar_one_or_none()
                    if incident:
                        analysis = incident.ai_analysis or {}
                        analysis["ai_enrichment"] = enrichment
                        analysis["enriched_at"] = datetime.utcnow().isoformat()
                        incident.ai_analysis = analysis
                        await db.commit()
                        logger.info(f"AI enrichment applied to incident {incident.id}")

        except Exception as e:
            logger.debug(f"Async AI enrichment failed (non-fatal): {e}")

    # ------------------------------------------------------------------
    # FULL AI PATH: existing process_alert for complex cases
    # ------------------------------------------------------------------

    async def process_alert(
        self,
        alert_data: dict,
        client: Client,
        db: AsyncSession,
    ) -> dict:
        """Full decision chain: receive -> classify -> decide -> act -> verify -> log."""
        result = {
            "stage": "started",
            "classifications": {},
            "actions_taken": [],
            "incident_id": None,
        }

        # Stage 1: Triage (falls back to defaults if AI unavailable)
        try:
            triage = await self._triage(alert_data)
        except Exception as e:
            logger.warning(f"Triage failed, using defaults: {e}")
            triage = {
                "severity": alert_data.get("severity", "medium"),
                "threat_type": alert_data.get("threat_type", "unknown"),
                "mitre_technique": "",
                "mitre_tactic": "",
                "summary": alert_data.get("title", alert_data.get("description", "Security alert detected")),
                "confidence": 0.5,
            }
        result["classifications"]["triage"] = triage

        # Stage 2: Classify (falls back to defaults if AI unavailable)
        try:
            classification = await self._classify(alert_data, triage)
        except Exception as e:
            logger.warning(f"Classification failed, using defaults: {e}")
            classification = {
                "classification": triage.get("threat_type", "unknown"),
                "attack_vector": "unknown",
                "impact": "unknown",
                "recommended_actions": [],
                "confidence": 0.5,
            }
        result["classifications"]["classification"] = classification

        # Stage 3: Create incident
        incident = await self._create_incident(alert_data, triage, classification, client, db)
        if incident is None:
            source_ip = alert_data.get("source_ip")
            logger.info(f"process_alert: skipping safelisted source_ip={source_ip}")
            result["stage"] = "safelisted"
            result["source_ip"] = source_ip
            result["summary"] = triage.get("summary")
            return result
        result["incident_id"] = incident.id
        result["client_id"] = client.id
        result["incident_severity"] = incident.severity
        result["incident_title"] = incident.title
        result["incident_status"] = incident.status
        result["summary"] = triage.get("summary")
        result["source_ip"] = incident.source_ip
        result["stage"] = "incident_created"

        # Stage 4: Decide actions
        threat_type = triage.get("threat_type", "unknown")
        recommended = RESPONSE_ACTIONS.get(threat_type, ["block_ip"])

        # Auto-block confirmation gate (mirrors playbook_engine.is_confirmed_attack).
        # A lone MEDIUM/low-confidence auth-failure / brute-force alert must NOT
        # auto-block. When the threat is not a confirmed real attack, block_ip
        # (and other IP-blocking actions) are forced to require operator
        # approval instead of relying on the auto_approve default policy.
        block_confirmed, block_reason = self._alert_block_confirmed(
            alert_data, triage, threat_type
        )
        result["block_confirmed"] = block_confirmed
        result["block_confirmation_reason"] = block_reason

        actions = []
        for action_type in recommended:
            target = alert_data.get("source_ip", alert_data.get("target", "unknown"))
            reasoning = f"AI recommended {action_type} for {threat_type} threat. {triage.get('summary', '')}"

            # Gate IP-blocking actions on the confirmation verdict. Non-blocking
            # actions (firewall_rule for XSS, etc.) still follow their policy.
            if action_type == "block_ip" and not block_confirmed:
                logger.warning(
                    f"GUARDRAIL (ai_engine): withholding auto-block_ip on {target} "
                    f"— attack NOT confirmed (reason={block_reason}, "
                    f"threat={threat_type}). Requires operator approval."
                )
                action = await self._create_pending_block(
                    client=client,
                    target=target,
                    ai_reasoning=(
                        f"Auto-block WITHHELD (unconfirmed: {block_reason}). "
                        f"{reasoning}"
                    ),
                    db=db,
                    incident_id=incident.id,
                )
            else:
                action = await guardrail_engine.evaluate_action(
                    client=client,
                    action_type=action_type,
                    target=target,
                    ai_reasoning=reasoning,
                    db=db,
                    incident_id=incident.id,
                )
            actions.append({
                "id": action.id,
                "type": action.action_type,
                "status": action.status,
                "requires_approval": action.requires_approval,
            })
        result["actions_taken"] = actions
        result["stage"] = "actions_decided"

        # Stage 5: Log audit
        await self._log_audit(client, incident, triage, classification, db)
        result["stage"] = "completed"

        # Publish event
        await event_bus.publish("alert_processed", result)

        return result

    def _alert_block_confirmed(
        self, alert_data: dict, triage: dict, threat_type: str,
    ) -> tuple[bool, str]:
        """Decide whether an AI-path alert justifies an AUTO block_ip.

        Returns (confirmed, reason). Confirmed => block_ip may auto-execute.
        Not confirmed => block_ip is downgraded to require operator approval.

        A block is confirmed when ANY of the following holds:
          1. Known-bad IOC hit on the source IP.
          2. Threat is a non-auth exploit class (SQLi, RCE, XSS, web shell,
             priv-esc, C2, data exfil, DNS tunnel, port scan, honeypot).
          3. Repeated, high-confidence brute force: HIGH+ severity AND a
             confirmed event count at/above the brute-force floor.
        A lone MEDIUM auth-failure / brute-force (session-check 401, single
        bad login) never meets this bar.
        """
        # Reuse the single source of truth in the playbook engine so the AI
        # path and the deterministic path apply identical confirmation logic.
        from app.services.playbook_engine import (
            CONFIRMED_EXPLOIT_RULES,
            AUTH_BRUTE_FORCE_RULES,
            MIN_BRUTE_FORCE_COUNT,
        )

        # 1. Known-bad IOC hit.
        ioc = alert_data.get("ioc_check") or alert_data.get("ioc")
        if isinstance(ioc, dict) and ioc.get("verdict") == "malicious":
            return True, "known_bad_ioc"
        if alert_data.get("known_attacker") or alert_data.get("known_bad_ip"):
            return True, "known_bad_ioc"

        severity = (triage.get("severity") or alert_data.get("severity") or "medium").lower()
        sev_rank = _severity_order(severity)

        # Normalize confidence to a float (may arrive as "high"/"medium"/etc.).
        confidence = triage.get("confidence", 0.5)
        if isinstance(confidence, str):
            confidence = {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.3}.get(
                confidence.lower(), 0.5
            )
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = 0.5

        # 2. Non-auth exploit / high-signal threat class.
        # Map threat_type back to the exploit-rule vocabulary.
        exploit_threat_types = {
            "sql_injection", "rce", "xss", "web_shell", "privilege_escalation",
            "c2_communication", "data_exfiltration", "dns_tunneling", "port_scan",
            "lateral_movement", "malware", "ransomware", "credential_dumping",
            "honeypot_recon",
        }
        if threat_type in exploit_threat_types:
            return True, f"confirmed_exploit:{threat_type}"

        # Also honor explicit sigma rule ids carried on the alert.
        pattern = alert_data.get("pattern") or alert_data.get("rule_id") or ""
        if pattern in CONFIRMED_EXPLOIT_RULES:
            return True, f"confirmed_exploit:{pattern}"

        # 3. Repeated, high-confidence brute force.
        is_auth = (
            threat_type == "brute_force"
            or pattern in AUTH_BRUTE_FORCE_RULES
            or (alert_data.get("threat_type") or "") in ("brute_force", "auth_failure")
        )
        if is_auth:
            # Confirmed count from the correlation engine / behavioural detector.
            count = 0
            for key in ("event_count", "count", "match_count", "failure_count", "attempt_count"):
                try:
                    count = max(count, int(alert_data.get(key, 0) or 0))
                except (TypeError, ValueError):
                    continue
            if sev_rank >= _severity_order("high") and confidence >= 0.75 and count >= MIN_BRUTE_FORCE_COUNT:
                return True, f"confirmed_brute_force(sev={severity},conf={confidence:.2f},count={count})"
            return False, (
                f"unconfirmed_auth(sev={severity},conf={confidence:.2f},count={count})"
            )

        # 4. Any other CRITICAL/HIGH-severity, high-confidence signal is
        #    treated as confirmed. Medium/low unknown signals are withheld.
        if sev_rank >= _severity_order("high") and confidence >= 0.75:
            return True, f"confirmed_high_severity(sev={severity},conf={confidence:.2f})"

        return False, f"unconfirmed_low_signal(sev={severity},conf={confidence:.2f})"

    async def _create_pending_block(
        self,
        client: Client,
        target: str,
        ai_reasoning: str,
        db: AsyncSession,
        incident_id: Optional[str] = None,
    ):
        """Create a block_ip Action in PENDING (requires_approval) state.

        Used when the confirmation gate withholds an auto-block. The safe-IP
        guardrail is still honored by delegating to guardrail_engine when the
        target is a safe IP, so we never emit a pending block for a safe IP.
        The Action is created directly (bypassing the auto_approve default
        policy) so an operator can approve it from the dashboard.
        """
        from app.core.attack_detector import _is_safe_ip
        try:
            if target and _is_safe_ip(target):
                # Route safe IPs through the guardrail so the existing
                # skipped_safe_ip handling / event fires exactly as before.
                return await guardrail_engine.evaluate_action(
                    client=client,
                    action_type="block_ip",
                    target=target,
                    ai_reasoning=ai_reasoning,
                    db=db,
                    incident_id=incident_id,
                )
        except Exception:
            pass

        from app.models.action import Action

        action = Action(
            incident_id=incident_id or "",
            client_id=client.id,
            action_type="block_ip",
            target=target,
            parameters={},
            status="pending",
            requires_approval=True,
            ai_reasoning=ai_reasoning,
        )
        db.add(action)
        await db.commit()
        await db.refresh(action)

        await event_bus.publish("action_requires_approval", {
            "action_id": action.id,
            "client_id": action.client_id,
            "incident_id": action.incident_id,
            "action_type": action.action_type,
            "target": action.target,
        })
        return action

    async def _triage(self, alert_data: dict) -> dict:
        """Quick triage; uses MITRE heuristics when AI unavailable."""
        _default = {
            "severity": alert_data.get("severity", "medium"),
            "threat_type": alert_data.get("threat_type", "unknown"),
            "mitre_technique": "",
            "mitre_tactic": "",
            "summary": alert_data.get("title", "Security alert received"),
            "confidence": 0.5,
        }

        async def _ai_triage(_data: dict) -> dict:
            messages = [{"role": "user", "content": f"Triage this security event:\n{json.dumps(_data, default=str)}"}]
            response = await openrouter_client.query(messages, "triage")
            result = self._parse_json_response(response.get("content", "{}"), _default)
            raw_model = response.get("model_used", "unknown")
            # When AI Manager returns a provider name instead of model ID, fall back to the route
            resolved_model = raw_model if "/" in raw_model else MODEL_ROUTING.get("triage", raw_model)
            result["_provenance"] = {
                "kind": "agent",
                "source": f"openrouter:{resolved_model}",
                "model": resolved_model,
                "ts": datetime.utcnow().isoformat(),
            }
            return result

        def _heuristic_triage(_data: dict) -> dict:
            threat_type = _data.get("threat_type", "unknown")
            mitre = MITRE_MAPPINGS.get(threat_type, {})
            result = dict(_default)
            result["threat_type"] = threat_type
            result["mitre_technique"] = mitre.get("technique", "")
            result["mitre_tactic"] = mitre.get("tactic", "")
            result["_provenance"] = {
                "kind": "algorithm",
                "source": "offline_triage_template",
                "ts": datetime.utcnow().isoformat(),
            }
            return result

        return await degrade_or_call(_ai_triage, _heuristic_triage, alert_data)

    async def _classify(self, alert_data: dict, triage: dict) -> dict:
        """Deep classification; returns heuristic result when AI unavailable."""
        _default = {
            "classification": triage.get("threat_type", "unknown"),
            "attack_vector": "unknown",
            "impact": "unknown",
            "recommended_actions": [],
            "confidence": 0.5,
        }

        async def _ai_classify(_data: dict, _triage: dict) -> dict:
            messages = [{
                "role": "user",
                "content": (
                    f"Classify this threat in depth.\nAlert: {json.dumps(_data, default=str)}\n"
                    f"Initial triage: {json.dumps(_triage, default=str)}"
                ),
            }]
            response = await openrouter_client.query(messages, "classification")
            result = self._parse_json_response(response.get("content", "{}"), _default)
            raw_model = response.get("model_used", "unknown")
            # When AI Manager returns a provider name instead of model ID, fall back to the route
            resolved_model = raw_model if "/" in raw_model else MODEL_ROUTING.get("classification", raw_model)
            result["_provenance"] = {
                "kind": "agent",
                "source": f"openrouter:{resolved_model}",
                "model": resolved_model,
                "ts": datetime.utcnow().isoformat(),
            }
            return result

        def _heuristic_classify(_data: dict, _triage: dict) -> dict:
            result = dict(_default)
            result["_provenance"] = {
                "kind": "algorithm",
                "source": "offline_triage_template",
                "ts": datetime.utcnow().isoformat(),
            }
            return result

        return await degrade_or_call(_ai_classify, _heuristic_classify, alert_data, triage)

    async def _create_incident(
        self,
        alert_data: dict,
        triage: dict,
        classification: dict,
        client: Client,
        db: AsyncSession,
    ) -> Incident:
        source_ip = alert_data.get("source_ip")
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                if _is_safe_ip(source_ip):
                    logger.debug(f"ai_engine: skipping incident for safe IP {source_ip}")
                    return None
            except Exception:
                pass
        threat_type = triage.get("threat_type", "unknown")
        mitre = MITRE_MAPPINGS.get(threat_type, {})
        # Prefer the caller's explicit title (e.g. log_watcher passes
        # "MEDIUM: Auth Failure detected") over the AI triage summary. When
        # OpenRouter returns non-JSON, triage falls back to a default summary
        # of "Alert received" and the previous code built the incident title
        # from that fallback — silently overwriting meaningful titles with
        # "MEDIUM: Alert received" ghosts.
        caller_title = alert_data.get("title")
        fallback_title = (
            f"{triage.get('severity', 'medium').upper()}: "
            f"{triage.get('summary', 'Security Alert')}"
        )
        alert_source = alert_data.get("source", "webhook")
        _origin = {
            "kind": "algorithm" if alert_source in ("log_watcher", "correlation_engine", "fast_triage") else "agent",
            "source": alert_source,
            "ts": datetime.utcnow().isoformat(),
        }
        if alert_source in ("log_watcher", "correlation_engine") and alert_data.get("pattern"):
            _origin["rule"] = alert_data.get("pattern")
        incident = Incident(
            client_id=client.id,
            title=caller_title or fallback_title,
            description=triage.get("summary", "") or alert_data.get("description", ""),
            severity=triage.get("severity", "medium"),
            status="investigating",
            source=alert_source,
            mitre_technique=mitre.get("technique", triage.get("mitre_technique")),
            mitre_tactic=mitre.get("tactic", triage.get("mitre_tactic")),
            source_ip=alert_data.get("source_ip"),
            ai_analysis={"triage": triage, "classification": classification, "_origin": _origin},
            raw_alert=alert_data,
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        return incident

    async def _log_audit(
        self,
        client: Client,
        incident: Incident,
        triage: dict,
        classification: dict,
        db: AsyncSession,
    ):
        # Normalize confidence to float (AI may return string like "high")
        confidence_map = {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.3}
        confidence = triage.get("confidence", 0.5)
        if isinstance(confidence, str):
            confidence = confidence_map.get(confidence.lower(), 0.5)
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = 0.5

        audit = AuditLog(
            client_id=client.id,
            incident_id=incident.id,
            action="alert_processed",
            model_used="multi-model-chain",
            input_summary=f"Alert: {incident.title}",
            ai_reasoning=json.dumps({"triage": triage, "classification": classification}, default=str),
            decision=f"Created incident, recommended actions",
            confidence=confidence,
            tokens_used=0,
            cost_usd=0.0,
            latency_ms=0,
        )
        db.add(audit)
        await db.commit()

    async def analyze_incident(self, incident: Incident, db: AsyncSession) -> dict:
        """Deep investigation of an existing incident; deterministic fallback when AI unavailable."""
        _default = {
            "findings": "Deterministic analysis based on incident data",
            "kill_chain_stage": MITRE_MAPPINGS.get(
                incident.ai_analysis.get("triage", {}).get("threat_type", ""), {}
            ).get("tactic", "unknown") if incident.ai_analysis else "unknown",
            "iocs": [incident.source_ip] if incident.source_ip else [],
            "timeline": [],
            "recommendations": ["Block source IP", "Review incident timeline", "Apply standard remediation"],
            "confidence": 0.5,
        }

        async def _ai_investigate(_inc: Incident) -> dict:
            messages = [{
                "role": "user",
                "content": (
                    f"Investigate this security incident:\n"
                    f"Title: {_inc.title}\n"
                    f"Description: {_inc.description}\n"
                    f"Severity: {_inc.severity}\n"
                    f"Source IP: {_inc.source_ip}\n"
                    f"Raw alert: {json.dumps(_inc.raw_alert, default=str)}\n"
                    f"Previous analysis: {json.dumps(_inc.ai_analysis, default=str)}"
                ),
            }]
            response = await openrouter_client.query(messages, "investigation")
            return self._parse_json_response(response.get("content", "{}"), _default)

        def _heuristic_investigate(_inc: Incident) -> dict:
            return dict(_default)

        analysis = await degrade_or_call(_ai_investigate, _heuristic_investigate, incident)

        current = incident.ai_analysis or {}
        current["investigation"] = analysis
        incident.ai_analysis = current
        await db.commit()

        return analysis

    async def score_risk(self, context: dict) -> dict:
        """Contextual risk scoring; heuristic fallback when AI unavailable."""
        _default = {"risk_score": 50.0, "factors": [], "justification": "Default risk score"}

        async def _ai_score(_ctx: dict) -> dict:
            messages = [{"role": "user", "content": f"Score the risk for:\n{json.dumps(_ctx, default=str)}"}]
            response = await openrouter_client.query(messages, "risk_scoring")
            return self._parse_json_response(response.get("content", "{}"), _default)

        def _heuristic_score(_ctx: dict) -> dict:
            severity = _ctx.get("severity", "medium")
            score_map = {"critical": 90.0, "high": 70.0, "medium": 50.0, "low": 25.0, "info": 10.0}
            return {
                "risk_score": score_map.get(severity, 50.0),
                "factors": [f"severity={severity}"],
                "justification": f"Heuristic score based on severity={severity}",
            }

        return await degrade_or_call(_ai_score, _heuristic_score, context)

    async def get_remediation(self, context: dict) -> dict:
        """Get remediation guidance; static fallback when AI unavailable."""
        _default = {
            "remediation_steps": ["Review and patch affected systems", "Update firewall rules", "Rotate credentials"],
            "verification": ["Re-scan after patching", "Monitor for recurrence"],
            "estimated_effort": "medium",
            "priority": "high",
        }

        async def _ai_remediation(_ctx: dict) -> dict:
            messages = [{"role": "user", "content": f"Provide remediation for:\n{json.dumps(_ctx, default=str)}"}]
            response = await openrouter_client.query(messages, "healing")
            return self._parse_json_response(response.get("content", "{}"), _default)

        def _static_remediation(_ctx: dict) -> dict:
            return dict(_default)

        return await degrade_or_call(_ai_remediation, _static_remediation, context)

    def _parse_json_response(self, content: str, default: dict) -> dict:
        """Parse JSON from AI response, handling markdown code blocks."""
        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            logger.warning(f"Failed to parse AI JSON response, using defaults")
            return default

    def fast_triage_stats(self) -> dict:
        return dict(self._fast_triage_stats)


def _severity_order(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


ai_engine = AIDecisionEngine()
