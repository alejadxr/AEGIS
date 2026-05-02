from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Core
    AEGIS_ENV: str = "production"
    AEGIS_SECRET_KEY: str = "aegis-dev-secret-key-change-in-production"
    AEGIS_API_PORT: int = 8000

    # OpenRouter
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    # Database (PostgreSQL only)
    DATABASE_URL: str = "postgresql+asyncpg://cayde6:cayde6pass@localhost:5432/cayde6"

    # Redis / Event bus
    REDIS_URL: str = "redis://localhost:6379"
    USE_MEMORY_BUS: bool = True
    USE_REDIS_STREAMS: bool = False

    # Scanning tools
    NUCLEI_PATH: str = "/usr/bin/nuclei"
    NMAP_PATH: str = "/usr/bin/nmap"
    SUBFINDER_PATH: str = "/usr/bin/subfinder"
    HTTPX_PATH: str = "/usr/bin/httpx"

    # Notifications
    WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440  # 24 hours

    # PayPal
    PAYPAL_CLIENT_ID: str = ""
    PAYPAL_SECRET: str = ""
    PAYPAL_API_URL: str = "https://api-m.paypal.com"

    # Inception Labs (Mercury-2 diffusion LLM)
    INCEPTION_API_KEY: str = ""
    INCEPTION_BASE_URL: str = "https://api.inceptionlabs.ai/v1"

    # Google Gemini (Generative Language API) — cheap+fast, default model
    # gemini-flash-lite-latest. Suitable for enrichment + triage on hot path.
    GEMINI_API_KEY: str = ""
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta"
    GEMINI_DEFAULT_MODEL: str = "gemini-flash-lite-latest"

    # Community Threat Intel Hub
    AEGIS_MONGODB_URI: str = ""     # Direct MongoDB connection (for self-hosted hubs)
    AEGIS_HUB_URL: str = ""         # HTTP hub URL (connect to another AEGIS instance)

    # Log watcher — comma-separated list of PM2 app names to tail.
    # Prevents AEGIS from monitoring unrelated projects on the same host
    # (which produced self-referential SQLi false positives from other apps'
    # traceback dividers). Empty string = tail all apps (legacy behavior).
    AEGIS_MONITORED_APPS: str = "cayde6-api,cayde6-frontend"

    # Attacker allow-list — comma-separated IPs that bypass the internal-IP
    # filter even if they would otherwise be classified as private/Tailscale.
    # Use this for pentest lab machines that need to generate real incidents
    # despite living in Tailscale CGNAT (100.64.0.0/10).
    # Example: AEGIS_ATTACKER_IPS="203.0.113.10,203.0.113.11"
    AEGIS_ATTACKER_IPS: str = ""

    # External firewall API URL (e.g. AEGIS Firewall Agent on Raspberry Pi).
    # When set, AEGIS uses this for real iptables blocking + threat intel.
    AEGIS_FIREWALL_URL: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
