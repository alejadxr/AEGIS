import asyncio
import logging
import random
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.core.ai_mode import degrade_or_call
from app.models.honeypot import Honeypot

logger = logging.getLogger("aegis.phantom.rotation")

_TEMPLATE_DETAILS = {
    "ssh": "SSH honeypot emulating Ubuntu OpenSSH server with password authentication enabled.",
    "http": "HTTP honeypot serving a fake web application with admin panels and debug endpoints.",
    "database": "Database honeypot exposing a fake production database with sample tables.",
    "smtp": "SMTP honeypot accepting connections and logging credential attempts.",
    "api": "REST API honeypot with fake endpoints returning plausible JSON responses.",
}


class RotationEngine:
    """Dynamic honeypot rotation to evade attacker fingerprinting."""

    def __init__(self):
        self._rotation_task: Optional[asyncio.Task] = None

    async def rotate(self, honeypot: Honeypot, db: AsyncSession) -> Honeypot:
        """Rotate a honeypot's configuration to appear different."""
        new_config = await self._generate_new_config(honeypot.honeypot_type, honeypot.config)

        honeypot.config = new_config
        honeypot.status = "running"
        honeypot.last_rotation = datetime.utcnow()
        await db.commit()
        await db.refresh(honeypot)

        logger.info(f"Rotated honeypot '{honeypot.name}' with new configuration")
        return honeypot

    async def _generate_new_config(self, honeypot_type: str, current_config: dict) -> dict:
        """Generate a new randomized configuration."""
        new_config = dict(current_config)

        if honeypot_type == "ssh":
            banners = [
                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                "SSH-2.0-OpenSSH_9.0p1 Debian-1+deb12u1",
                "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2",
                "SSH-2.0-dropbear_2022.83",
                "SSH-2.0-OpenSSH_9.3p1",
            ]
            new_config["banner"] = random.choice(banners)

        elif honeypot_type == "http":
            servers = [
                "Apache/2.4.52 (Ubuntu)",
                "nginx/1.22.1",
                "Microsoft-IIS/10.0",
                "Apache/2.4.57 (Debian)",
                "nginx/1.24.0",
            ]
            new_config["server_header"] = random.choice(servers)
            paths = [
                ["/admin", "/wp-admin", "/phpmyadmin", "/.env"],
                ["/manager", "/console", "/api/debug", "/swagger-ui.html"],
                ["/administrator", "/cpanel", "/wp-login.php", "/.git/config"],
                ["/dashboard", "/admin/config", "/api/v1/internal", "/backup"],
            ]
            new_config["fake_paths"] = random.choice(paths)

        elif honeypot_type == "database":
            engines = ["mysql", "postgresql", "mssql"]
            new_config["fake_engine"] = random.choice(engines)
            db_names = [
                ["production", "users", "billing"],
                ["app_data", "auth", "analytics"],
                ["main", "customers", "orders"],
            ]
            new_config["fake_databases"] = random.choice(db_names)

        elif honeypot_type == "smtp":
            banners_list = [
                "220 mail.internal.corp ESMTP Postfix",
                "220 smtp.company.local Microsoft ESMTP MAIL Service",
                "220 mx.internal.net ESMTP Exim 4.96",
            ]
            new_config["banner"] = random.choice(banners_list)

        # Enrich with AI-generated decoy detail; fall back to template-based description
        async def _ai_decoy(htype: str) -> str:
            messages = [{
                "role": "user",
                "content": (
                    f"Generate a realistic configuration detail for a {htype} honeypot. "
                    f"Make it look like a real service that would attract attackers. "
                    f"Respond with just a brief description or banner text, no JSON needed."
                ),
            }]
            response = await openrouter_client.query(messages, "decoy_content")
            return response.get("content", "")[:500]

        def _template_decoy(htype: str) -> str:
            return _TEMPLATE_DETAILS.get(htype, f"{htype} honeypot — realistic service emulation.")

        try:
            detail = await degrade_or_call(_ai_decoy, _template_decoy, honeypot_type)
            new_config["ai_decoy_detail"] = detail
        except Exception:
            pass

        return new_config

    async def schedule_rotation(
        self, honeypot: Honeypot, interval_seconds: int, db_factory
    ):
        """Schedule automatic periodic rotation."""
        async def _rotation_loop():
            while True:
                await asyncio.sleep(interval_seconds)
                async with db_factory() as db:
                    result = await db.execute(
                        select(Honeypot).where(Honeypot.id == honeypot.id)
                    )
                    hp = result.scalar_one_or_none()
                    if hp and hp.status == "running":
                        await self.rotate(hp, db)

        self._rotation_task = asyncio.create_task(_rotation_loop())

    def stop_scheduled_rotation(self):
        if self._rotation_task:
            self._rotation_task.cancel()
            self._rotation_task = None


rotation_engine = RotationEngine()
