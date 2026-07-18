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

    # Extra log paths to tail in addition to PM2 stdout/stderr.
    # Colon-separated, supports glob patterns. Used to point AEGIS at the
    # unified aegis-feed.jsonl that web apps write to.
    # Example: AEGIS_EXTRA_LOG_PATHS=/Users/alejandxr/web-logs/aegis-feed.jsonl
    AEGIS_EXTRA_LOG_PATHS: str = ""

    # Attacker allow-list — comma-separated IPs that bypass the internal-IP
    # filter even if they would otherwise be classified as private/Tailscale.
    # Use this for pentest lab machines that need to generate real incidents
    # despite living in Tailscale CGNAT (100.64.0.0/10).
    # Example: AEGIS_ATTACKER_IPS="203.0.113.10,203.0.113.11"
    AEGIS_ATTACKER_IPS: str = ""

    # External firewall API URL (e.g. AEGIS Firewall Agent on Raspberry Pi).
    # When set, AEGIS uses this for real iptables blocking + threat intel.
    AEGIS_FIREWALL_URL: str = ""

    # Opt-in incident reconciliation: when enabled, the firewall sync pass will
    # auto-resolve incidents whose source_ip is no longer in the Pi blocklist.
    # Set to True (or AEGIS_AUTO_RECONCILE_INCIDENTS=1 in .env) to activate.
    # Default OFF to avoid surprising existing deployments.
    AEGIS_AUTO_RECONCILE_INCIDENTS: bool = False

    # Opt-in Pi → Mac Pro blocklist pull. When enabled, each firewall sync cycle
    # appends any Pi-blocked IPs missing from the local blocked_ips.txt so the
    # FastAPI 403 middleware enforces them too. Default OFF (push-only).
    AEGIS_FIREWALL_PULL_FROM_PI: bool = False

    # ----------------------------------------------------------------------
    # DoS Shield (v1.6.4.0) — L7 flood detection / mitigation.
    # SAFE DEFAULTS: MODE=monitor (detect+emit only, NEVER 429/block) and the
    # network tier is gated off (NETSHIELD=False). Flipping to active or
    # enabling netshield is an explicit human decision — see deploy_notes.
    # ----------------------------------------------------------------------
    # 'monitor' = detect + log + emit dos.* events, NEVER 429/block.
    # 'active'   = enforce (429 + escalate). Runtime-overridable via /dos/mode.
    AEGIS_DOS_MODE: str = "monitor"
    # Network-tier master gate. False/0 = firewall_client network methods and
    # /dos/netshield endpoints are no-ops. Guards against locking the Mac Pro
    # out of its own Pi gateway. Must be explicitly enabled by an operator.
    AEGIS_DOS_NETSHIELD: bool = False

    # --- Per-IP sliding window ---
    # Baseline peak legit IP = 2 req/s → 5x headroom. Above trips dos.http_flood.
    AEGIS_DOS_PER_IP_RPS: float = 10.0
    AEGIS_DOS_PER_IP_WINDOW: int = 10   # seconds; budget = RPS*WINDOW = 100/10s

    # --- Per-/24-subnet aggregate window (catches clustered botnets) ---
    AEGIS_DOS_SUBNET_RPS: float = 40.0
    AEGIS_DOS_SUBNET_WINDOW: int = 10

    # --- Global aggregate window (catches fully-distributed floods) ---
    # Real API ~0.7 req/s, probe peak ~16.7 req/s → ~70x headroom on real traffic.
    AEGIS_DOS_GLOBAL_RPS: float = 50.0
    AEGIS_DOS_GLOBAL_WINDOW: int = 10

    # --- Expensive-endpoint budget (AI inference, scan triggers) ---
    AEGIS_DOS_EXPENSIVE_RPM: float = 6.0   # per-IP req/min = 1 per 10s
    AEGIS_DOS_EXPENSIVE_PATHS: str = (
        "/api/v1/ask,/api/v1/surface/scan,/api/v1/surface/scan/now"
    )

    # --- Slow-loris heuristics ---
    AEGIS_DOS_CONCURRENCY_PER_IP: int = 20   # max concurrent in-flight per IP
    AEGIS_DOS_SLOW_REQUEST_SECONDS: int = 25  # handler duration => slow-request tick

    # --- Escalation / body / adaptive knobs ---
    AEGIS_DOS_BLOCK_DURATION: int = 900       # seconds an escalated IP stays blocked
    AEGIS_DOS_MAX_BODY_BYTES: int = 10485760  # 10 MB → 413 above this
    AEGIS_DOS_UNDER_ATTACK_FACTOR: float = 0.5  # tighten budgets under attack
    AEGIS_DOS_EVENT_COOLDOWN: int = 30        # min seconds between same (ip,reason) event

    # Direct-peer IPs from which X-Forwarded-For is trusted for client-IP
    # derivation. Default = localhost + Tailscale CGNAT. Any other peer uses the
    # real socket IP, defeating XFF spoofing of rate-limit accounting.
    AEGIS_DOS_TRUSTED_PROXIES: str = "127.0.0.1,::1,100.64.0.0/10"

    # --- Network tier (gated by AEGIS_DOS_NETSHIELD) ---
    AEGIS_DOS_NETSHIELD_SYN_RATE: int = 50    # per-source SYN pkts/sec (iptables hashlimit)
    AEGIS_DOS_NETSHIELD_CONNLIMIT: int = 100  # max concurrent conns/source (iptables connlimit)

    # CORS — comma-separated explicit allow-list. Wildcard ("*") is invalid
    # combined with allow_credentials=True and is never used here (P0-10).
    # Prod overrides via env with the real dashboard origin(s).
    AEGIS_CORS_ORIGINS: str = "http://localhost:3007,http://127.0.0.1:3007"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
