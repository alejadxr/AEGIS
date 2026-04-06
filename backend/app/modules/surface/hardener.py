import logging

from app.core.openrouter import openrouter_client
from app.services.ai_engine import ai_engine

logger = logging.getLogger("aegis.hardener")


class HardeningEngine:
    """Auto-hardening recommendation and script generator."""

    async def get_recommendations(self, target_data: dict) -> dict:
        """Get AI-powered hardening recommendations."""
        context = {
            "hostname": target_data.get("hostname", ""),
            "asset_type": target_data.get("asset_type", ""),
            "open_ports": target_data.get("ports", []),
            "technologies": target_data.get("technologies", []),
            "vulnerabilities": target_data.get("vulnerabilities", []),
        }
        return await ai_engine.get_remediation(context)

    def generate_hardening_checklist(self, asset_type: str) -> list[dict]:
        """Generate a standard hardening checklist based on asset type."""
        checklists = {
            "web": [
                {"item": "Enable HTTPS/TLS 1.3", "priority": "critical", "category": "encryption"},
                {"item": "Set security headers (CSP, HSTS, X-Frame-Options)", "priority": "high", "category": "headers"},
                {"item": "Disable directory listing", "priority": "medium", "category": "configuration"},
                {"item": "Remove server version banners", "priority": "medium", "category": "information_disclosure"},
                {"item": "Enable rate limiting", "priority": "high", "category": "availability"},
                {"item": "Configure CORS properly", "priority": "high", "category": "access_control"},
                {"item": "Implement input validation", "priority": "critical", "category": "injection"},
                {"item": "Enable WAF rules", "priority": "high", "category": "protection"},
            ],
            "server": [
                {"item": "Disable root SSH login", "priority": "critical", "category": "access_control"},
                {"item": "Enable SSH key-only authentication", "priority": "critical", "category": "authentication"},
                {"item": "Configure firewall (allow only needed ports)", "priority": "critical", "category": "network"},
                {"item": "Enable automatic security updates", "priority": "high", "category": "patching"},
                {"item": "Configure audit logging", "priority": "high", "category": "monitoring"},
                {"item": "Disable unnecessary services", "priority": "medium", "category": "attack_surface"},
                {"item": "Set up fail2ban", "priority": "high", "category": "brute_force"},
            ],
            "api": [
                {"item": "Implement authentication (API keys/OAuth)", "priority": "critical", "category": "authentication"},
                {"item": "Enable rate limiting per client", "priority": "critical", "category": "availability"},
                {"item": "Validate all input parameters", "priority": "critical", "category": "injection"},
                {"item": "Use HTTPS only", "priority": "critical", "category": "encryption"},
                {"item": "Implement proper error handling (no stack traces)", "priority": "high", "category": "information_disclosure"},
                {"item": "Enable request logging", "priority": "high", "category": "monitoring"},
            ],
        }
        return checklists.get(asset_type, checklists["server"])


hardening_engine = HardeningEngine()
