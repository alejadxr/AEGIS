import asyncio
import logging
import os
import re
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.honeypot import HoneypotInteraction, Honeypot
from app.models.attacker_profile import AttackerProfile
from app.models.threat_intel import ThreatIntel
from app.core.events import event_bus

logger = logging.getLogger("cayde6.phantom.processor")

# Tool signatures detected from user-agents and commands
TOOL_SIGNATURES = {
    "nmap": [r"nmap", r"masscan", r"Nmap Scripting Engine"],
    "nikto": [r"nikto", r"Nikto"],
    "sqlmap": [r"sqlmap", r"SQL injection"],
    "dirbuster": [r"DirBuster", r"dirbuster", r"gobuster", r"dirb"],
    "metasploit": [r"Metasploit", r"msfconsole", r"exploit/"],
    "hydra": [r"hydra", r"Hydra"],
    "curl": [r"^curl/", r"libcurl"],
    "python": [r"python-requests", r"Python-urllib", r"aiohttp"],
    "masscan": [r"masscan"],
    "zgrab": [r"zgrab"],
    "wfuzz": [r"Wfuzz"],
}

# Sophistication scoring
SOPHISTICATION_THRESHOLDS = {
    "advanced": 3,        # Uses 3+ tools or complex techniques
    "intermediate": 1,    # Uses 1+ known tools
    "script_kiddie": 0,   # No recognizable tools
}


def _detect_tools(user_agent: str, commands: list[str], path: str = "") -> list[str]:
    """Detect tools used based on user-agent and commands."""
    detected = []
    combined = " ".join([user_agent] + commands + [path])
    for tool, patterns in TOOL_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.append(tool)
                break
    return list(set(detected))


def _classify_sophistication(tools: list[str], commands: list[str]) -> str:
    """Classify attacker sophistication."""
    if len(tools) >= SOPHISTICATION_THRESHOLDS["advanced"]:
        return "advanced"
    if len(tools) >= SOPHISTICATION_THRESHOLDS["intermediate"]:
        return "intermediate"
    # Check for sophisticated commands
    sophisticated_cmds = ["wget", "curl", "chmod", "python", "perl", "bash -c", "nc ", "netcat"]
    for cmd in commands:
        if any(s in cmd for s in sophisticated_cmds):
            return "intermediate"
    return "script_kiddie"


def _extract_techniques(path: str, commands: list[str]) -> list[str]:
    """Extract MITRE-style techniques from interactions."""
    techniques = []
    all_text = " ".join([path] + commands).lower()

    if any(p in all_text for p in ["/.env", "/config", "/backup"]):
        techniques.append("T1552 - Credentials in Files")
    if any(p in all_text for p in ["/wp-admin", "/phpmyadmin", "/admin"]):
        techniques.append("T1190 - Exploit Public-Facing Application")
    if any(p in all_text for p in ["ls", "id", "whoami", "uname"]):
        techniques.append("T1082 - System Information Discovery")
    if any(p in all_text for p in ["wget", "curl http", "curl https"]):
        techniques.append("T1105 - Ingress Tool Transfer")
    if any(p in all_text for p in ["chmod", "bash -c", "sh -c"]):
        techniques.append("T1059 - Command and Scripting Interpreter")
    if "cat /etc/passwd" in all_text or "cat /etc/shadow" in all_text:
        techniques.append("T1003 - OS Credential Dumping")

    return techniques


class InteractionProcessor:
    """Process raw honeypot interactions into structured data."""

    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self, interaction_queue: asyncio.Queue):
        """Start processing interactions from the queue."""
        self._running = True
        self._task = asyncio.create_task(self._process_loop(interaction_queue))
        logger.info("[Processor] Interaction processor started")

    async def stop(self):
        """Stop the processor."""
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("[Processor] Interaction processor stopped")

    async def _process_loop(self, queue: asyncio.Queue):
        """Continuously process interactions from the queue."""
        while self._running:
            try:
                interaction_data = await asyncio.wait_for(queue.get(), timeout=1.0)
                await self._process_interaction(interaction_data)
                queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Processor] Error processing interaction: {e}", exc_info=True)

    async def _get_or_create_demo_honeypot(self, db: AsyncSession, protocol: str) -> Optional[Honeypot]:
        """Get honeypot record by port number; fall back to first available client."""
        from app.models.client import Client
        port = 2222 if protocol == "ssh" else 8888
        # Try to find by port directly
        result = await db.execute(select(Honeypot).where(Honeypot.port == port))
        honeypot = result.scalar_one_or_none()
        if honeypot:
            return honeypot
        # Fall back: get any client
        result_c = await db.execute(select(Client).limit(1))
        client = result_c.scalar_one_or_none()
        if not client:
            return None
        honeypot = Honeypot(
            client_id=client.id,
            name=f"{protocol.upper()} Honeypot (port {port})",
            honeypot_type=protocol,
            config={},
            status="running",
            ip_address="0.0.0.0",
            port=port,
        )
        db.add(honeypot)
        await db.flush()
        return honeypot

    async def _process_interaction(self, data: dict):
        """Process a single interaction: save to DB, update profiles, add IOCs."""
        async with async_session() as db:
            try:
                protocol = data.get("protocol", "unknown")
                source_ip = data.get("source_ip", "unknown")
                user_agent = data.get("headers", {}).get("User-Agent", "") if data.get("headers") else ""
                commands = data.get("commands", [])
                path = data.get("path", "")
                credentials = data.get("credentials_tried", [])

                # Detect tools and techniques
                tools = _detect_tools(user_agent, commands, path)
                techniques = _extract_techniques(path, commands)

                # Smart honeypot enrichment: injection detection data
                injections = data.get("injections_detected", [])
                if injections:
                    injection_techniques = {
                        "sql_injection": "T1190 - SQL Injection",
                        "xss": "T1059.007 - Cross-Site Scripting",
                        "path_traversal": "T1083 - File and Directory Discovery",
                        "command_injection": "T1059 - Command Injection",
                        "template_injection": "T1221 - Template Injection",
                        "credential_stuffing": "T1110 - Brute Force",
                    }
                    for inj in injections:
                        mapped = injection_techniques.get(inj)
                        if mapped:
                            techniques.append(mapped)
                    techniques = list(set(techniques))

                sophistication = _classify_sophistication(tools, commands)

                # Get honeypot record
                honeypot = await self._get_or_create_demo_honeypot(db, protocol)
                if not honeypot:
                    logger.warning("[Processor] No demo client found, skipping")
                    return

                # Get or create attacker profile
                result = await db.execute(
                    select(AttackerProfile).where(
                        AttackerProfile.source_ip == source_ip,
                        AttackerProfile.client_id == honeypot.client_id,
                    )
                )
                profile = result.scalar_one_or_none()

                now = datetime.utcnow()
                if not profile:
                    profile = AttackerProfile(
                        client_id=honeypot.client_id,
                        source_ip=source_ip,
                        known_ips=[source_ip],
                        tools_used=tools,
                        techniques=techniques,
                        sophistication=sophistication,
                        first_seen=now,
                        last_seen=now,
                        total_interactions=1,
                    )
                    db.add(profile)
                    await db.flush()
                    logger.info(f"[Processor] New attacker profile: {source_ip} ({sophistication})")
                else:
                    # Update existing profile
                    profile.last_seen = now
                    profile.total_interactions = (profile.total_interactions or 0) + 1
                    existing_tools = profile.tools_used or []
                    profile.tools_used = list(set(existing_tools + tools))
                    existing_techniques = profile.techniques or []
                    profile.techniques = list(set(existing_techniques + techniques))
                    # Upgrade sophistication if needed
                    sophistication_rank = {"script_kiddie": 0, "intermediate": 1, "advanced": 2}
                    current_rank = sophistication_rank.get(profile.sophistication or "script_kiddie", 0)
                    new_rank = sophistication_rank.get(sophistication, 0)
                    if new_rank > current_rank:
                        profile.sophistication = sophistication
                    await db.flush()

                # Save interaction
                interaction = HoneypotInteraction(
                    honeypot_id=honeypot.id,
                    client_id=honeypot.client_id,
                    source_ip=source_ip,
                    source_port=data.get("source_port"),
                    protocol=protocol,
                    commands=commands,
                    credentials_tried=credentials,
                    session_duration=data.get("session_duration", 0),
                    attacker_profile_id=profile.id,
                    raw_log=str(data),
                    timestamp=now,
                )
                db.add(interaction)

                # Update honeypot interaction count
                honeypot.interactions_count = (honeypot.interactions_count or 0) + 1

                # Add IOC to threat_intel
                existing_ioc = await db.execute(
                    select(ThreatIntel).where(
                        ThreatIntel.ioc_value == source_ip,
                        ThreatIntel.ioc_type == "ip",
                    )
                )
                ioc = existing_ioc.scalar_one_or_none()
                if not ioc:
                    ioc = ThreatIntel(
                        ioc_type="ip",
                        ioc_value=source_ip,
                        threat_type="honeypot_interaction",
                        confidence=0.9 if sophistication == "advanced" else 0.7,
                        source=f"{protocol}_honeypot",
                        tags=tools + [sophistication],
                    )
                    db.add(ioc)
                else:
                    ioc.last_seen = now
                    ioc.confidence = min(1.0, (ioc.confidence or 0.7) + 0.05)

                await db.commit()

                # Publish event
                await event_bus.publish("honeypot_interaction", {
                    "source_ip": source_ip,
                    "protocol": protocol,
                    "sophistication": sophistication,
                    "tools": tools,
                    "honeypot_id": honeypot.id,
                })
                # Notify Rasputin about honeypot interaction from non-trusted IPs
                trusted_ips = {"127.0.0.1", "::1", "localhost"}
                if source_ip not in trusted_ips:
                    try:
                        import aiohttp
                        async with aiohttp.ClientSession() as _sess:
                            await _sess.post(
                                os.getenv("AEGIS_FIREWALL_URL", "http://localhost:8000") + "/api/rasputin/ai/analyze",
                                json={"ip": source_ip, "attack_type": "honeypot_interaction"},
                                timeout=aiohttp.ClientTimeout(total=3),
                            )
                            logger.info(f"[Processor] Notified Rasputin about {source_ip}")
                    except Exception as _re:
                        logger.debug(f"[Processor] Rasputin notification failed (non-fatal): {_re}")


                logger.info(
                    f"[Processor] Saved interaction: {source_ip} via {protocol}, "
                    f"sophistication={sophistication}, tools={tools}"
                )

                # Share to MongoDB aegis_threats collection
                try:
                    from app.services.threat_intel_hub import threat_intel_hub
                    await threat_intel_hub.share_ioc({
                        "ioc_type": "ip",
                        "ioc_value": source_ip,
                        "threat_type": "honeypot_interaction",
                        "confidence": 0.9 if sophistication == "advanced" else 0.7,
                        "mitre_techniques": techniques,
                        "detection_source": f"{protocol}_honeypot",
                    })
                    logger.info(f"[Processor] Shared {source_ip} to aegis_threats via MongoDB")
                except Exception as _me:
                    logger.debug(f"[Processor] MongoDB share failed (non-fatal): {_me}")

            except Exception as e:
                logger.error(f"[Processor] DB error: {e}", exc_info=True)
                await db.rollback()


interaction_processor = InteractionProcessor()
