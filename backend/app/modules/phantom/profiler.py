import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.models.honeypot import HoneypotInteraction
from app.models.attacker_profile import AttackerProfile

logger = logging.getLogger("aegis.phantom.profiler")


class AttackerProfiler:
    """Build and maintain attacker profiles from honeypot interactions."""

    async def record_interaction(
        self,
        honeypot_id: str,
        client_id: str,
        source_ip: str,
        interaction_data: dict,
        db: AsyncSession,
    ) -> HoneypotInteraction:
        """Record a new honeypot interaction and update attacker profile."""
        # Find or create attacker profile
        profile = await self._get_or_create_profile(client_id, source_ip, db)

        interaction = HoneypotInteraction(
            honeypot_id=honeypot_id,
            client_id=client_id,
            source_ip=source_ip,
            source_port=interaction_data.get("source_port"),
            protocol=interaction_data.get("protocol", "tcp"),
            commands=interaction_data.get("commands", []),
            credentials_tried=interaction_data.get("credentials_tried", []),
            payloads=interaction_data.get("payloads", []),
            session_duration=interaction_data.get("session_duration", 0),
            attacker_profile_id=profile.id,
            raw_log=interaction_data.get("raw_log", ""),
        )
        db.add(interaction)

        # Update profile
        profile.last_seen = datetime.utcnow()
        profile.total_interactions += 1

        # Merge tools and techniques
        new_tools = interaction_data.get("tools_detected", [])
        existing_tools = profile.tools_used or []
        profile.tools_used = list(set(existing_tools + new_tools))

        new_techniques = interaction_data.get("techniques", [])
        existing_techniques = profile.techniques or []
        profile.techniques = list(set(existing_techniques + new_techniques))

        # Update known IPs
        known = profile.known_ips or []
        if source_ip not in known:
            known.append(source_ip)
            profile.known_ips = known

        await db.commit()
        await db.refresh(interaction)
        return interaction

    async def assess_attacker(
        self, profile: AttackerProfile, db: AsyncSession
    ) -> AttackerProfile:
        """Use AI to assess an attacker's sophistication and intent."""
        context = {
            "source_ip": profile.source_ip,
            "known_ips": profile.known_ips,
            "tools_used": profile.tools_used,
            "techniques": profile.techniques,
            "total_interactions": profile.total_interactions,
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
        }

        messages = [
            {
                "role": "user",
                "content": (
                    f"Assess this attacker's profile from honeypot interactions:\n"
                    f"{json.dumps(context, default=str)}\n\n"
                    f"Classify sophistication as: script_kiddie, intermediate, advanced, or apt.\n"
                    f"Respond in JSON with keys: sophistication, assessment, likely_intent, "
                    f"threat_level, recommended_actions."
                ),
            }
        ]
        response = await openrouter_client.query(messages, "classification")
        content = response.get("content", "{}")

        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)
            assessment = json.loads(cleaned)
            profile.sophistication = assessment.get("sophistication", "intermediate")
            profile.ai_assessment = json.dumps(assessment, default=str)
        except (json.JSONDecodeError, ValueError):
            profile.sophistication = self._heuristic_sophistication(profile)
            profile.ai_assessment = content

        await db.commit()
        await db.refresh(profile)
        return profile

    async def _get_or_create_profile(
        self, client_id: str, source_ip: str, db: AsyncSession
    ) -> AttackerProfile:
        """Get existing profile or create new one for an IP."""
        result = await db.execute(
            select(AttackerProfile).where(
                AttackerProfile.client_id == client_id,
                AttackerProfile.source_ip == source_ip,
            )
        )
        profile = result.scalar_one_or_none()

        if not profile:
            profile = AttackerProfile(
                client_id=client_id,
                source_ip=source_ip,
                known_ips=[source_ip],
                tools_used=[],
                techniques=[],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                total_interactions=0,
            )
            db.add(profile)
            await db.flush()

        return profile

    def _heuristic_sophistication(self, profile: AttackerProfile) -> str:
        """Heuristic sophistication assessment when AI is unavailable."""
        tools = profile.tools_used or []
        techniques = profile.techniques or []

        advanced_tools = {"metasploit", "cobalt_strike", "mimikatz", "bloodhound", "empire"}
        if any(t.lower() in advanced_tools for t in tools):
            return "advanced"

        if len(techniques) > 5 or len(tools) > 3:
            return "intermediate"

        if profile.total_interactions > 100:
            return "intermediate"

        return "script_kiddie"


attacker_profiler = AttackerProfiler()
