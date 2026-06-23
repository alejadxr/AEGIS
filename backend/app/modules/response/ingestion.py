import json
import logging
import re
from datetime import datetime
from typing import Optional

from app.core.events import event_bus

logger = logging.getLogger("aegis.ingestion")


class AlertIngestion:
    """Alert ingestion from multiple sources: webhook, syslog, file."""

    async def ingest_webhook(self, payload: dict) -> dict:
        """Ingest an alert from a webhook payload."""
        normalized = self._normalize_alert(payload)
        await event_bus.publish("alert_received", normalized)
        logger.info(f"Ingested webhook alert: {normalized.get('title', 'unknown')}")
        return normalized

    async def ingest_syslog(self, raw_message: str) -> dict:
        """Parse and ingest a syslog message."""
        parsed = self._parse_syslog(raw_message)
        normalized = self._normalize_alert(parsed)
        await event_bus.publish("alert_received", normalized)
        logger.info(f"Ingested syslog alert: {normalized.get('title', 'unknown')}")
        return normalized

    async def ingest_file(self, file_content: str, format_type: str = "json") -> list[dict]:
        """Ingest alerts from a file."""
        alerts = []
        if format_type == "json":
            try:
                data = json.loads(file_content)
                if isinstance(data, list):
                    for item in data:
                        normalized = self._normalize_alert(item)
                        alerts.append(normalized)
                        await event_bus.publish("alert_received", normalized)
                else:
                    normalized = self._normalize_alert(data)
                    alerts.append(normalized)
                    await event_bus.publish("alert_received", normalized)
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON file")
        elif format_type == "csv":
            lines = file_content.strip().split("\n")
            if len(lines) > 1:
                headers = lines[0].split(",")
                for line in lines[1:]:
                    values = line.split(",")
                    item = dict(zip(headers, values))
                    normalized = self._normalize_alert(item)
                    alerts.append(normalized)
                    await event_bus.publish("alert_received", normalized)

        logger.info(f"Ingested {len(alerts)} alerts from file")
        return alerts

    def _normalize_alert(self, raw: dict) -> dict:
        """Normalize alert data to a common format."""
        return {
            "title": raw.get("title") or raw.get("name") or raw.get("alert_name", "Security Alert"),
            "description": raw.get("description") or raw.get("message") or raw.get("details", ""),
            "severity": self._normalize_severity(
                raw.get("severity") or raw.get("level") or raw.get("priority", "medium")
            ),
            "source": raw.get("source") or raw.get("agent") or raw.get("tool", "webhook"),
            "source_ip": raw.get("source_ip") or raw.get("src_ip") or raw.get("attacker_ip"),
            "target": raw.get("target") or raw.get("dest_ip") or raw.get("hostname"),
            "timestamp": raw.get("timestamp") or datetime.utcnow().isoformat(),
            "raw": raw,
        }

    def _normalize_severity(self, severity: str) -> str:
        severity = str(severity).lower().strip()
        mapping = {
            "1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info",
            "crit": "critical", "err": "high", "error": "high",
            "warn": "medium", "warning": "medium",
            "notice": "low", "debug": "info",
        }
        return mapping.get(severity, severity if severity in ("critical", "high", "medium", "low", "info") else "medium")

    def _parse_syslog(self, raw: str) -> dict:
        """Parse a basic syslog message."""
        # Match RFC 3164 pattern
        pattern = r"<(\d+)>(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.*)"
        match = re.match(pattern, raw)
        if match:
            priority, timestamp, host, program, pid, message = match.groups()
            return {
                "title": f"{program}: {message[:100]}",
                "description": message,
                "severity": self._priority_to_severity(int(priority)),
                "source": f"syslog:{host}",
                "source_ip": host,
                "timestamp": timestamp,
            }
        return {
            "title": "Syslog Alert",
            "description": raw,
            "severity": "medium",
            "source": "syslog",
        }

    def _priority_to_severity(self, priority: int) -> str:
        severity_num = priority % 8
        if severity_num <= 2:
            return "critical"
        elif severity_num == 3:
            return "high"
        elif severity_num == 4:
            return "medium"
        elif severity_num <= 5:
            return "low"
        return "info"


alert_ingestion = AlertIngestion()
