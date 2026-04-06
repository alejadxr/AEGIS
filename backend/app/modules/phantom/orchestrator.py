import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import event_bus
from app.models.honeypot import Honeypot
from app.services.subscription import check_feature

logger = logging.getLogger("aegis.phantom.orchestrator")

# Default honeypot configurations
HONEYPOT_DEFAULTS = {
    "ssh": {
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        "port": 2222,
        "credentials_log": True,
        "max_sessions": 10,
        "session_timeout": 300,
    },
    "http": {
        "server_header": "Apache/2.4.52 (Ubuntu)",
        "port": 8080,
        "fake_paths": ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/api/v1/debug"],
        "capture_headers": True,
        "capture_body": True,
    },
    "smb": {
        "port": 445,
        "share_name": "internal-docs",
        "fake_files": ["credentials.xlsx", "vpn-config.ovpn", "backup.sql"],
    },
    "api": {
        "port": 9090,
        "endpoints": ["/api/v1/users", "/api/v1/admin", "/graphql"],
        "fake_auth": True,
        "rate_limit": 100,
    },
    "database": {
        "port": 3306,
        "fake_engine": "mysql",
        "fake_databases": ["production", "users", "billing"],
    },
    "smtp": {
        "port": 25,
        "banner": "220 mail.internal.corp ESMTP Postfix",
        "relay_test": True,
    },
    # Smart honeypots — Pro/Enterprise tier only
    "smart_http": {
        "port": 8081,
        "app_type": "nextjs",
        "ai_responses": True,
        "breadcrumb_env": True,
        "capture_uploads": True,
    },
    "smart_api": {
        "port": 9091,
        "fake_users": 50,
        "injection_detection": True,
        "api_key_tracking": True,
    },
    "smart_db": {
        "port": 3307,
        "fake_engine": "mysql",
        "fake_databases": ["production", "users", "billing"],
        "injection_detection": True,
    },
}

# Honeypot types that require the "smart_honeypots" feature
SMART_HONEYPOT_TYPES = {"smart_http", "smart_api", "smart_db"}


class HoneypotOrchestrator:
    """Manage honeypot lifecycle: deploy, configure, start, stop."""

    def __init__(self):
        self._running_honeypots: dict[str, dict] = {}

    async def deploy(
        self,
        honeypot_type: str,
        name: str,
        client_id: str,
        db: AsyncSession,
        custom_config: Optional[dict] = None,
        client=None,
    ) -> Honeypot:
        """Deploy a new honeypot.

        Smart honeypot types (smart_http, smart_api, smart_db) require the
        ``smart_honeypots`` feature which is only available on Pro and
        Enterprise tiers.
        """
        # Gate smart honeypots behind feature check
        if honeypot_type in SMART_HONEYPOT_TYPES:
            if client is None or not check_feature(client, "smart_honeypots"):
                raise ValueError(
                    f"Smart honeypot type '{honeypot_type}' requires Pro tier "
                    f"or higher (feature: smart_honeypots)"
                )

        defaults = HONEYPOT_DEFAULTS.get(honeypot_type, HONEYPOT_DEFAULTS["http"])
        config = {**defaults, **(custom_config or {})}

        honeypot = Honeypot(
            client_id=client_id,
            name=name,
            honeypot_type=honeypot_type,
            config=config,
            status="running",
            ip_address="0.0.0.0",
            port=config.get("port", 8080),
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)

        self._running_honeypots[honeypot.id] = {
            "id": honeypot.id,
            "type": honeypot_type,
            "started_at": datetime.utcnow().isoformat(),
        }

        await event_bus.publish("honeypot_deployed", {
            "honeypot_id": honeypot.id,
            "type": honeypot_type,
            "name": name,
        })

        logger.info(f"Deployed honeypot '{name}' (type={honeypot_type}, port={config.get('port')})")
        return honeypot

    async def stop(self, honeypot: Honeypot, db: AsyncSession) -> Honeypot:
        """Stop a running honeypot."""
        honeypot.status = "stopped"
        self._running_honeypots.pop(honeypot.id, None)
        await db.commit()
        logger.info(f"Stopped honeypot '{honeypot.name}'")
        return honeypot

    async def start(self, honeypot: Honeypot, db: AsyncSession) -> Honeypot:
        """Start a stopped honeypot."""
        honeypot.status = "running"
        self._running_honeypots[honeypot.id] = {
            "id": honeypot.id,
            "type": honeypot.honeypot_type,
            "started_at": datetime.utcnow().isoformat(),
        }
        await db.commit()
        logger.info(f"Started honeypot '{honeypot.name}'")
        return honeypot

    async def update_config(
        self, honeypot: Honeypot, new_config: dict, db: AsyncSession
    ) -> Honeypot:
        """Update honeypot configuration."""
        current = honeypot.config or {}
        current.update(new_config)
        honeypot.config = current
        await db.commit()
        await db.refresh(honeypot)
        return honeypot

    async def remove(self, honeypot: Honeypot, db: AsyncSession):
        """Remove a honeypot entirely."""
        self._running_honeypots.pop(honeypot.id, None)
        await db.delete(honeypot)
        await db.commit()
        logger.info(f"Removed honeypot '{honeypot.name}'")

    def get_running(self) -> list[dict]:
        return list(self._running_honeypots.values())

    def get_supported_types(self) -> list[str]:
        return list(HONEYPOT_DEFAULTS.keys())


honeypot_orchestrator = HoneypotOrchestrator()
