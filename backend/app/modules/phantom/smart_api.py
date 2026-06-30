"""
Smart API Honeypot - Imitates REST APIs with plausible JSON responses.

Exposes endpoints like /api/users, /api/config, /api/admin, /api/v1/auth.
Returns plausible fake user data and configuration values.
Tracks authentication attempts, API key probing, and injection attempts.
"""

import asyncio
import json
import logging
import random
import re
import string
import uuid
from datetime import datetime, timedelta
from typing import Optional

from aiohttp import web

logger = logging.getLogger("aegis.phantom.smart_api")


# ---------------------------------------------------------------------------
# Fake data generators
# ---------------------------------------------------------------------------

FIRST_NAMES = ["James", "Sarah", "Michael", "Emma", "David", "Olivia", "Daniel", "Sophia", "Robert", "Ava"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
DOMAINS = ["company.com", "internal.corp", "acme.io", "example.org"]
ROLES = ["admin", "user", "editor", "viewer", "manager", "analyst"]


def _fake_user(uid: int) -> dict:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    domain = random.choice(DOMAINS)
    return {
        "id": uid,
        "username": f"{first.lower()}.{last.lower()}",
        "email": f"{first.lower()}.{last.lower()}@{domain}",
        "name": f"{first} {last}",
        "role": random.choice(ROLES),
        "active": random.choice([True, True, True, False]),
        "last_login": (datetime.utcnow() - timedelta(hours=random.randint(1, 720))).isoformat(),
        "created_at": (datetime.utcnow() - timedelta(days=random.randint(30, 900))).isoformat(),
    }


def _fake_config() -> dict:
    return {
        "app": {
            "name": "Internal Dashboard",
            "version": "3.2.1",
            "environment": "production",
            "debug": False,
        },
        "database": {
            "host": "db.internal.prod",
            "port": 5432,
            "name": "app_production",
            "pool_size": 20,
        },
        "cache": {
            "driver": "redis",
            "host": "cache.internal.prod",
            "port": 6379,
        },
        "storage": {
            "driver": "s3",
            "bucket": "app-assets-prod",
            "region": "us-east-1",
        },
        "features": {
            "new_dashboard": True,
            "beta_api": False,
            "maintenance_mode": False,
        },
    }


def _fake_api_key() -> str:
    return f"ak_live_{''.join(random.choices(string.ascii_letters + string.digits, k=32))}"


# ---------------------------------------------------------------------------
# Injection detection patterns
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    (r"(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from)", "sql_injection"),
    (r"(?:<script|javascript:|on\w+\s*=|<img\s+src.*onerror)", "xss"),
    (r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self)", "path_traversal"),
    (r"(?:\{%|\\$\\{|\\$\\(|`.*`)", "template_injection"),
    (r"(?:;|\||&&)\s*(?:ls|cat|id|whoami|curl|wget|nc\s)", "command_injection"),
    (r"(?:admin|root|test).*(?:password|pass|pwd|123)", "credential_stuffing"),
]


def _detect_injections(text: str) -> list[str]:
    """Detect injection attempts in request data."""
    detected = []
    for pattern, attack_type in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(attack_type)
    return list(set(detected))


# ---------------------------------------------------------------------------
# Smart API Honeypot
# ---------------------------------------------------------------------------

class SmartAPIHoneypot:
    """REST API honeypot with plausible fake data and injection tracking."""

    def __init__(
        self,
        port: int = 9090,
        theme: Optional[str] = None,
        campaign_id: Optional[str] = None,
        fake_user_count: int = 50,
    ):
        self.port = port
        self.theme = theme
        self.campaign_id = campaign_id
        self._running = False
        self._runner: Optional[web.AppRunner] = None
        self._interaction_queue: Optional[asyncio.Queue] = None
        # Pre-generate fake users — use content_generator when a theme is
        # set so the data + breadcrumbs match the deception campaign.
        if theme:
            try:
                from app.services.honey_ai.content_generator import content_generator
                self._users = content_generator.fake_users(theme, fake_user_count)
            except Exception:
                self._users = [_fake_user(i) for i in range(1, fake_user_count + 1)]
        else:
            self._users = [_fake_user(i) for i in range(1, fake_user_count + 1)]
        self._config = _fake_config()
        self._api_keys: dict[str, dict] = {
            _fake_api_key(): {"user_id": 1, "role": "admin", "created": datetime.utcnow().isoformat()},
        }

    async def start(self, interaction_queue: asyncio.Queue):
        """Start the smart API honeypot."""
        self._interaction_queue = interaction_queue
        self._running = True

        app = web.Application()
        # Auth endpoints
        app.router.add_post("/api/v1/auth/login", self._handle_auth_login)
        app.router.add_post("/api/v1/auth/register", self._handle_auth_register)
        app.router.add_post("/api/v1/auth/token", self._handle_auth_token)
        app.router.add_get("/api/v1/auth/me", self._handle_auth_me)
        # User endpoints
        app.router.add_get("/api/users", self._handle_users_list)
        app.router.add_get("/api/users/{user_id}", self._handle_user_detail)
        app.router.add_get("/api/v1/users", self._handle_users_list)
        # Config / admin
        app.router.add_get("/api/config", self._handle_config)
        app.router.add_get("/api/v1/config", self._handle_config)
        app.router.add_get("/api/admin", self._handle_admin)
        app.router.add_get("/api/v1/admin", self._handle_admin)
        app.router.add_get("/api/v1/admin/stats", self._handle_admin_stats)
        # Health / meta
        app.router.add_get("/api/health", self._handle_health)
        app.router.add_get("/api/v1/health", self._handle_health)
        app.router.add_get("/api/version", self._handle_version)
        # Catch-all
        app.router.add_route("*", "/{path_info:.*}", self._handle_catch_all)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        logger.info(f"[Smart API] Listening on port {self.port}")

    async def stop(self):
        self._running = False
        if self._runner:
            await self._runner.cleanup()
        logger.info("[Smart API] Stopped")

    # ------------------------------------------------------------------
    # Auth endpoints
    # ------------------------------------------------------------------

    async def _handle_auth_login(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        body = await self._read_body(request)
        injections = _detect_injections(body)

        capture = self._build_capture(request, "/api/v1/auth/login", "POST", source_ip)
        capture["body"] = body[:4096]

        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            data = {}

        username = data.get("username", data.get("email", ""))
        password = data.get("password", "")
        capture["credentials_tried"] = [{"username": str(username), "password": str(password)}]

        if injections:
            capture["commands"].append(f"Injection detected: {', '.join(injections)}")

        self._queue_interaction(capture)
        logger.info(f"[Smart API] Auth attempt from {source_ip}: {username} — injections={injections}")

        # Always return auth failure with realistic structure
        return web.json_response({
            "error": "invalid_credentials",
            "message": "Invalid username or password",
            "status": 401,
        }, status=401, headers=self._headers())

    async def _handle_auth_register(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        body = await self._read_body(request)
        capture = self._build_capture(request, "/api/v1/auth/register", "POST", source_ip)
        capture["body"] = body[:4096]
        self._queue_interaction(capture)

        return web.json_response({
            "error": "registration_disabled",
            "message": "Public registration is currently disabled. Contact admin.",
        }, status=403, headers=self._headers())

    async def _handle_auth_token(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        body = await self._read_body(request)
        capture = self._build_capture(request, "/api/v1/auth/token", "POST", source_ip)
        capture["body"] = body[:4096]
        capture["commands"].append("API key/token exchange attempt")
        self._queue_interaction(capture)

        return web.json_response({
            "error": "invalid_grant",
            "message": "The provided authorization grant is invalid or expired.",
        }, status=400, headers=self._headers())

    async def _handle_auth_me(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        capture = self._build_capture(request, "/api/v1/auth/me", "GET", source_ip)

        # Check for API key probing
        auth_header = request.headers.get("Authorization", "")
        api_key = request.headers.get("X-API-Key", "")
        if auth_header or api_key:
            capture["commands"].append(f"API key probe: Authorization={auth_header[:30]}... X-API-Key={api_key[:20]}...")

        self._queue_interaction(capture)

        return web.json_response({
            "error": "unauthorized",
            "message": "Missing or invalid authentication token",
        }, status=401, headers=self._headers())

    # ------------------------------------------------------------------
    # User endpoints
    # ------------------------------------------------------------------

    async def _handle_users_list(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        capture = self._build_capture(request, request.path, "GET", source_ip)

        # Check query params for injection
        query_str = str(request.query_string)
        injections = _detect_injections(query_str)
        if injections:
            capture["commands"].append(f"Injection in query: {', '.join(injections)}")

        self._queue_interaction(capture)

        page = int(request.query.get("page", "1"))
        limit = min(int(request.query.get("limit", "10")), 50)
        start = (page - 1) * limit
        users_page = self._users[start:start + limit]

        return web.json_response({
            "data": users_page,
            "meta": {
                "total": len(self._users),
                "page": page,
                "limit": limit,
                "pages": (len(self._users) + limit - 1) // limit,
            },
        }, headers=self._headers())

    async def _handle_user_detail(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        user_id_raw = request.match_info.get("user_id", "0")
        capture = self._build_capture(request, f"/api/users/{user_id_raw}", "GET", source_ip)

        # Check for injection in path parameter
        injections = _detect_injections(user_id_raw)
        if injections:
            capture["commands"].append(f"Injection in path param: {', '.join(injections)}")
            self._queue_interaction(capture)
            return web.json_response({"error": "bad_request"}, status=400, headers=self._headers())

        self._queue_interaction(capture)

        try:
            uid = int(user_id_raw)
        except ValueError:
            return web.json_response({"error": "not_found"}, status=404, headers=self._headers())

        user = next((u for u in self._users if u["id"] == uid), None)
        if user:
            return web.json_response({"data": user}, headers=self._headers())
        return web.json_response({"error": "not_found"}, status=404, headers=self._headers())

    # ------------------------------------------------------------------
    # Config / Admin
    # ------------------------------------------------------------------

    async def _handle_config(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        capture = self._build_capture(request, request.path, "GET", source_ip)
        capture["commands"].append("Config endpoint accessed (sensitive)")
        self._queue_interaction(capture)
        logger.info(f"[Smart API] Config probe from {source_ip}")

        return web.json_response(self._config, headers=self._headers())

    async def _handle_admin(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        capture = self._build_capture(request, request.path, "GET", source_ip)
        capture["commands"].append("Admin endpoint accessed")
        self._queue_interaction(capture)

        return web.json_response({
            "admin_panel": True,
            "server": "prod-app-01",
            "uptime_hours": random.randint(100, 5000),
            "users_total": len(self._users),
            "active_sessions": random.randint(10, 200),
            "pending_tasks": random.randint(0, 15),
            "version": "3.2.1",
        }, headers=self._headers())

    async def _handle_admin_stats(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        capture = self._build_capture(request, "/api/v1/admin/stats", "GET", source_ip)
        capture["commands"].append("Admin stats probe")
        self._queue_interaction(capture)

        return web.json_response({
            "revenue_mtd": round(random.uniform(15000, 95000), 2),
            "users_active_24h": random.randint(200, 5000),
            "api_calls_24h": random.randint(50000, 500000),
            "error_rate": round(random.uniform(0.1, 2.5), 2),
            "avg_response_ms": random.randint(40, 250),
        }, headers=self._headers())

    # ------------------------------------------------------------------
    # Health / meta
    # ------------------------------------------------------------------

    async def _handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "uptime": random.randint(100000, 999999),
            "version": "3.2.1",
            "timestamp": datetime.utcnow().isoformat(),
        }, headers=self._headers())

    async def _handle_version(self, request: web.Request) -> web.Response:
        return web.json_response({
            "version": "3.2.1",
            "build": "a7f3c2e",
            "node": "18.19.1",
            "environment": "production",
        }, headers=self._headers())

    # ------------------------------------------------------------------
    # Catch-all
    # ------------------------------------------------------------------

    async def _handle_catch_all(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        path = "/" + request.match_info.get("path_info", "")
        method = request.method
        capture = self._build_capture(request, path, method, source_ip)

        body = await self._read_body(request)
        if body:
            capture["body"] = body[:4096]
            injections = _detect_injections(body)
            if injections:
                capture["commands"].append(f"Injection detected: {', '.join(injections)}")

        self._queue_interaction(capture)

        return web.json_response({
            "error": "not_found",
            "message": f"No route found for {method} {path}",
            "status": 404,
        }, status=404, headers=self._headers())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_client_ip(self, request: web.Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "unknown"

    async def _read_body(self, request: web.Request) -> str:
        try:
            raw = await request.read()
            return raw.decode(errors="replace")[:8192]
        except Exception:
            return ""

    def _build_capture(self, request: web.Request, path: str, method: str, source_ip: str) -> dict:
        return {
            "source_ip": source_ip,
            "source_port": None,
            "protocol": "http",
            "path": path,
            "method": method,
            "user_agent": request.headers.get("User-Agent", ""),
            "headers": dict(request.headers),
            "credentials_tried": [],
            "commands": [f"{method} {path}"],
            "session_duration": 0,
            "timestamp": datetime.utcnow().isoformat(),
            "honeypot_type": "smart_api",
        }

    def _queue_interaction(self, data: dict):
        if self._interaction_queue:
            try:
                self._interaction_queue.put_nowait(data)
            except Exception as e:
                logger.error(f"[Smart API] Failed to queue interaction: {e}")

    def _headers(self) -> dict:
        return {
            "Server": "nginx/1.24.0",
            "X-Request-Id": uuid.uuid4().hex,
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": str(random.randint(80, 99)),
        }
