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

    # Community Threat Intel Hub
    AEGIS_MONGODB_URI: str = ""     # Direct MongoDB connection (for self-hosted hubs)
    AEGIS_HUB_URL: str = ""         # HTTP hub URL (connect to another AEGIS instance)

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
