import logging

import httpx

from app.config import settings
from app.models.client import Client

logger = logging.getLogger("aegis.notifier")


class NotificationService:
    """Send notifications via webhook, Telegram, and email (stub)."""

    async def send_webhook(self, url: str, payload: dict) -> bool:
        """Send a webhook notification."""
        if not url:
            logger.debug("No webhook URL configured, skipping")
            return False

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code < 300:
                    logger.info(f"Webhook sent to {url}")
                    return True
                else:
                    logger.warning(f"Webhook failed: {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False

    async def send_telegram(self, token: str, chat_id: str, text: str) -> bool:
        """Send a Telegram notification via bot API."""
        if not token or not chat_id:
            logger.debug("Telegram token/chat_id not configured, skipping")
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code < 300:
                    logger.info("Telegram notification sent")
                    return True
                logger.warning(f"Telegram failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Telegram error: {e}")
            return False

    async def send_email(self, recipients: list[str], subject: str, body: str) -> bool:
        """Email notifications are not wired yet; log intent."""
        if not recipients:
            return False
        logger.info(f"Email notification stub to {recipients}: {subject}")
        return True

    def _build_telegram_text(self, payload: dict) -> str:
        title = payload.get("title") or payload.get("event_type", "AEGIS Alert")
        severity = payload.get("severity")
        lines = [f"*{title}*"]
        if severity:
            lines.append(f"Severity: *{severity.upper()}*")
        if payload.get("message"):
            lines.append(payload["message"])
        if payload.get("incident_id"):
            lines.append(f"Incident: `{payload['incident_id']}`")
        if payload.get("action_type"):
            lines.append(f"Action: `{payload['action_type']}`")
        if payload.get("target"):
            lines.append(f"Target: `{payload['target']}`")
        return "\n".join(lines)

    async def notify(self, client: Client, payload: dict) -> None:
        """Dispatch notifications based on client settings."""
        settings_map = client.settings or {}
        channels = settings_map.get("notification_channels") or []
        if not channels:
            if settings_map.get("webhook_url") or settings.WEBHOOK_URL:
                channels = ["webhook"]
        channels = list(dict.fromkeys(channels))

        webhook_url = settings_map.get("webhook_url") or settings.WEBHOOK_URL
        telegram_token = settings_map.get("telegram_bot_token")
        telegram_chat_id = settings_map.get("telegram_chat_id")
        email_enabled = settings_map.get("email_enabled", False)
        email_recipients = settings_map.get("email_recipients", [])

        if "webhook" in channels:
            await self.send_webhook(webhook_url, payload)
        if "telegram" in channels:
            await self.send_telegram(telegram_token, telegram_chat_id, self._build_telegram_text(payload))
        if "email" in channels and email_enabled:
            await self.send_email(email_recipients, payload.get("title", "AEGIS Alert"), payload.get("message", ""))


notifier = NotificationService()
