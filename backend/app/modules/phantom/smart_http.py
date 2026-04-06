"""
Smart HTTP Honeypot - AI-driven deception that imitates real web applications.

Serves realistic login forms, admin panels, and dashboards for Next.js,
WordPress, and Laravel apps.  Uses AI to generate dynamic responses for
unexpected paths.  Captures full requests, cookies, form data, and file
uploads.  Auto-plants breadcrumb .env files with fake API keys.
"""

import asyncio
import json
import logging
import random
import string
import uuid
from datetime import datetime
from typing import Optional

from aiohttp import web

from app.core.openrouter import openrouter_client

logger = logging.getLogger("aegis.phantom.smart_http")


# ---------------------------------------------------------------------------
# Breadcrumb .env files (fake but trackable)
# ---------------------------------------------------------------------------

def _generate_breadcrumb_env(app_type: str) -> str:
    """Generate a realistic fake .env with trackable breadcrumb keys."""
    marker = uuid.uuid4().hex[:8]
    base = (
        f"# {app_type.title()} Production Environment\n"
        f"APP_ENV=production\n"
        f"APP_DEBUG=false\n"
        f"APP_KEY=base64:{''.join(random.choices(string.ascii_letters + string.digits, k=32))}\n"
        f"\n"
        f"DB_CONNECTION={'pgsql' if app_type == 'nextjs' else 'mysql'}\n"
        f"DB_HOST=db.internal.prod\n"
        f"DB_PORT={'5432' if app_type == 'nextjs' else '3306'}\n"
        f"DB_DATABASE=app_production\n"
        f"DB_USERNAME=app_user\n"
        f"DB_PASSWORD=Pr0d_P4ss_{marker}\n"
        f"\n"
        f"AWS_ACCESS_KEY_ID=AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}\n"
        f"AWS_SECRET_ACCESS_KEY={''.join(random.choices(string.ascii_letters + string.digits + '+/', k=40))}\n"
        f"AWS_DEFAULT_REGION=us-east-1\n"
        f"AWS_BUCKET=app-assets-prod\n"
        f"\n"
        f"OPENAI_API_KEY=sk-breadcrumb-{marker}\n"
        f"STRIPE_SECRET_KEY=sk_live_breadcrumb_{marker}\n"
        f"JWT_SECRET=jwt-secret-{marker}\n"
        f"REDIS_URL=redis://cache.internal:6379/0\n"
    )

    if app_type == "nextjs":
        base += (
            f"\nNEXT_PUBLIC_API_URL=https://api.internal.prod\n"
            f"NEXTAUTH_SECRET=nextauth-{marker}\n"
            f"NEXTAUTH_URL=https://app.internal.prod\n"
        )
    elif app_type == "laravel":
        base += (
            f"\nMAIL_MAILER=smtp\n"
            f"MAIL_HOST=smtp.internal.prod\n"
            f"MAIL_PORT=587\n"
            f"MAIL_USERNAME=noreply@internal.prod\n"
            f"MAIL_PASSWORD=mail_{marker}\n"
            f"PUSHER_APP_KEY=pusher-{marker}\n"
        )
    elif app_type == "wordpress":
        base += (
            f"\nWP_DB_NAME=wordpress_prod\n"
            f"WP_TABLE_PREFIX=wp_\n"
            f"AUTH_KEY={''.join(random.choices(string.ascii_letters, k=48))}\n"
            f"SECURE_AUTH_KEY={''.join(random.choices(string.ascii_letters, k=48))}\n"
        )

    return base


# ---------------------------------------------------------------------------
# App-specific templates
# ---------------------------------------------------------------------------

NEXTJS_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In - Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#ededed;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#18181b;border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:40px;width:400px;max-width:90vw}
.logo{font-size:20px;font-weight:700;margin-bottom:8px;color:#fff}
.sub{font-size:14px;color:#71717a;margin-bottom:32px}
.field{margin-bottom:20px}
.field label{display:block;font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:6px}
.field input{width:100%;padding:10px 14px;background:#09090b;border:1px solid #27272a;border-radius:8px;color:#fff;font-size:14px;outline:none}
.field input:focus{border-color:#22d3ee}
.btn{width:100%;padding:12px;background:#22d3ee;color:#09090b;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.btn:hover{background:#06b6d4}
.footer{text-align:center;margin-top:20px;font-size:12px;color:#52525b}
.footer a{color:#22d3ee;text-decoration:none}
</style></head>
<body>
<div class="card">
<div class="logo">Dashboard</div>
<div class="sub">Sign in to your account</div>
<form method="POST" action="/api/auth/callback/credentials">
<div class="field"><label>Email</label><input type="email" name="email" required autocomplete="email"></div>
<div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="btn">Sign in</button>
</form>
<div class="footer"><a href="/api/auth/signin/github">Sign in with GitHub</a></div>
</div>
</body></html>"""

NEXTJS_DASHBOARD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#ededed;font-family:-apple-system,sans-serif}
.nav{background:#18181b;border-bottom:1px solid #27272a;padding:12px 24px;display:flex;align-items:center;gap:24px}
.nav-logo{font-weight:700;font-size:16px;color:#fff}
.nav a{color:#71717a;font-size:14px;text-decoration:none}
.main{padding:32px;max-width:1200px;margin:0 auto}
h1{font-size:24px;margin-bottom:8px}
.sub{color:#71717a;font-size:14px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.stat{background:#18181b;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:24px}
.stat-label{font-size:12px;color:#71717a;text-transform:uppercase;letter-spacing:.5px}
.stat-value{font-size:28px;font-weight:700;margin-top:4px}
</style></head><body>
<div class="nav"><span class="nav-logo">App</span><a href="/dashboard">Dashboard</a><a href="/settings">Settings</a><a href="/api/auth/signout">Sign out</a></div>
<div class="main">
<h1>Dashboard</h1><div class="sub">Welcome back, admin</div>
<div class="grid">
<div class="stat"><div class="stat-label">Total Users</div><div class="stat-value">12,847</div></div>
<div class="stat"><div class="stat-label">Revenue (MTD)</div><div class="stat-value">$48,291</div></div>
<div class="stat"><div class="stat-label">Active Sessions</div><div class="stat-value">1,203</div></div>
<div class="stat"><div class="stat-label">API Calls (24h)</div><div class="stat-value">2.4M</div></div>
</div></div></body></html>"""

LARAVEL_LOGIN = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Login - Laravel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f7fafc;font-family:'Nunito',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1);padding:32px;width:400px}
h2{font-size:18px;color:#4a5568;margin-bottom:24px;text-align:center}
.field{margin-bottom:16px}
.field label{display:block;font-size:14px;color:#4a5568;margin-bottom:4px;font-weight:700}
.field input{width:100%;padding:10px 12px;border:1px solid #e2e8f0;border-radius:4px;font-size:14px}
.field input:focus{border-color:#6574cd;outline:none;box-shadow:0 0 0 3px rgba(101,116,205,.2)}
.btn{width:100%;padding:12px;background:#6574cd;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer}
.btn:hover{background:#5a67d8}
.links{text-align:center;margin-top:16px;font-size:13px;color:#718096}
.links a{color:#6574cd;text-decoration:none}
</style></head><body>
<div class="card">
<h2>Login</h2>
<form method="POST" action="/login">
<input type="hidden" name="_token" value="TOKEN_PLACEHOLDER">
<div class="field"><label>E-Mail Address</label><input type="email" name="email" required autocomplete="email"></div>
<div class="field"><label>Password</label><input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="btn">Login</button>
</form>
<div class="links"><a href="/password/reset">Forgot Your Password?</a> | <a href="/register">Register</a></div>
</div></body></html>"""

WORDPRESS_ADMIN = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Dashboard &lsaquo; Site &mdash; WordPress</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f0f0f1;font-family:-apple-system,sans-serif}
#adminmenu{position:fixed;left:0;top:0;bottom:0;width:160px;background:#1d2327;padding-top:32px}
#adminmenu a{display:block;padding:8px 12px;color:#c3c4c7;font-size:13px;text-decoration:none}
#adminmenu a:hover{color:#72aee6}
#wpadminbar{position:fixed;top:0;left:160px;right:0;height:32px;background:#1d2327;display:flex;align-items:center;padding:0 16px}
#wpadminbar span{color:#c3c4c7;font-size:13px}
.wrap{margin-left:160px;padding:52px 20px 20px}
h1{font-size:23px;font-weight:400;color:#1d2327;margin-bottom:16px}
.welcome{background:#fff;border:1px solid #c3c4c7;border-left:4px solid #72aee6;padding:16px;margin-bottom:20px}
</style></head><body>
<div id="adminmenu">
<a href="/wp-admin/">Dashboard</a>
<a href="/wp-admin/edit.php">Posts</a>
<a href="/wp-admin/upload.php">Media</a>
<a href="/wp-admin/edit.php?post_type=page">Pages</a>
<a href="/wp-admin/users.php">Users</a>
<a href="/wp-admin/plugins.php">Plugins</a>
<a href="/wp-admin/options-general.php">Settings</a>
</div>
<div id="wpadminbar"><span>WordPress 6.5.2</span></div>
<div class="wrap">
<h1>Dashboard</h1>
<div class="welcome">
<p><strong>Welcome!</strong> You have 3 pending updates and 2 comments awaiting moderation.</p>
</div></div></body></html>"""


APP_CONFIGS = {
    "nextjs": {
        "login_html": NEXTJS_LOGIN,
        "dashboard_html": NEXTJS_DASHBOARD,
        "server_header": "Next.js",
        "extra_headers": {"X-Powered-By": "Next.js"},
        "login_paths": {"/api/auth/signin", "/auth/signin", "/login", "/sign-in"},
        "login_action": "/api/auth/callback/credentials",
        "admin_paths": {"/dashboard", "/admin", "/settings", "/api/auth/session"},
        "api_paths": {
            "/_next/data": '{"pageProps":{"session":null},"__N_SSP":true}',
            "/api/health": '{"status":"ok","uptime":847291}',
        },
    },
    "wordpress": {
        "login_html": None,  # uses TEMPLATES from http_honeypot
        "dashboard_html": WORDPRESS_ADMIN,
        "server_header": "Apache/2.4.52 (Ubuntu)",
        "extra_headers": {"X-Powered-By": "PHP/8.1.0"},
        "login_paths": {"/wp-login.php", "/wp-admin", "/login"},
        "login_action": "/wp-login.php",
        "admin_paths": {"/wp-admin/", "/wp-admin/admin.php", "/wp-admin/plugins.php"},
        "api_paths": {
            "/wp-json/wp/v2/posts": '[{"id":1,"title":{"rendered":"Hello world!"},"status":"publish"}]',
            "/wp-json/wp/v2/users": '[{"id":1,"name":"admin","slug":"admin"}]',
            "/xmlrpc.php": '<?xml version="1.0"?><methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>',
        },
    },
    "laravel": {
        "login_html": LARAVEL_LOGIN,
        "dashboard_html": None,
        "server_header": "Apache/2.4.57 (Debian)",
        "extra_headers": {"X-Powered-By": "PHP/8.2.4"},
        "login_paths": {"/login", "/admin/login", "/auth/login"},
        "login_action": "/login",
        "admin_paths": {"/dashboard", "/admin", "/home", "/nova"},
        "api_paths": {
            "/api/user": '{"id":1,"name":"Admin","email":"admin@example.com"}',
            "/telescope": '<html><body>Telescope</body></html>',
        },
    },
}


# Paths that always serve the breadcrumb .env
ENV_PATHS = {"/.env", "/.env.local", "/.env.production", "/config/.env", "/.env.backup"}


class SmartHTTPHoneypot:
    """AI-driven HTTP honeypot that imitates real web applications."""

    def __init__(self, port: int = 8080, app_type: str = "nextjs"):
        self.port = port
        self.app_type = app_type
        self._running = False
        self._runner: Optional[web.AppRunner] = None
        self._interaction_queue: Optional[asyncio.Queue] = None
        self._config = APP_CONFIGS.get(app_type, APP_CONFIGS["nextjs"])
        self._breadcrumb_env = _generate_breadcrumb_env(app_type)

    async def start(self, interaction_queue: asyncio.Queue):
        """Start the smart HTTP honeypot."""
        self._interaction_queue = interaction_queue
        self._running = True

        app = web.Application(client_max_size=10 * 1024 * 1024)  # 10MB uploads
        app.router.add_route("*", "/{path_info:.*}", self._handle_request)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        logger.info(f"[Smart HTTP] Listening on port {self.port} as {self.app_type}")

    async def stop(self):
        self._running = False
        if self._runner:
            await self._runner.cleanup()
        logger.info("[Smart HTTP] Stopped")

    # ------------------------------------------------------------------
    # Request handling
    # ------------------------------------------------------------------

    async def _handle_request(self, request: web.Request) -> web.Response:
        path = "/" + request.match_info.get("path_info", "")
        method = request.method
        source_ip = self._get_client_ip(request)

        # Capture full request data
        capture = await self._capture_request(request, path, method, source_ip)

        # Route to appropriate handler
        if method == "POST" and path in (self._config["login_action"], *self._config["login_paths"]):
            return await self._handle_login(request, capture)

        if path in ENV_PATHS:
            return self._serve_env(capture)

        if path == "/robots.txt":
            return self._serve_robots()

        if path in self._config["admin_paths"]:
            return self._serve_admin(capture)

        for api_path, api_response in self._config["api_paths"].items():
            if path.startswith(api_path):
                return self._serve_api(api_path, api_response, capture)

        if path in self._config["login_paths"] or path == "/":
            return self._serve_login()

        # For unknown paths, try AI-generated response
        return await self._ai_response(path, method, capture)

    async def _handle_login(self, request: web.Request, capture: dict) -> web.Response:
        """Capture login attempts and show a fake error."""
        try:
            data = await request.post()
            email = data.get("email", data.get("username", ""))
            password = data.get("password", "")
            capture["credentials_tried"] = [{"username": str(email), "password": str(password)}]
            logger.info(f"[Smart HTTP] Login attempt from {capture['source_ip']}: {email}")
        except Exception as e:
            logger.warning(f"[Smart HTTP] Error parsing login: {e}")

        self._queue_interaction(capture)

        # Return a realistic error
        headers = self._response_headers()
        if self.app_type == "nextjs":
            return web.json_response(
                {"error": "CredentialsSignin", "url": "/api/auth/error?error=CredentialsSignin"},
                status=401, headers=headers,
            )
        elif self.app_type == "laravel":
            return web.Response(
                status=302, headers={**headers, "Location": "/login", "Set-Cookie": "laravel_session=fake; Path=/; HttpOnly"},
            )
        else:
            login_html = self._config.get("login_html") or NEXTJS_LOGIN
            error_html = login_html.replace("</form>", '<p style="color:#ef4444;margin-top:12px;font-size:13px">Invalid credentials.</p></form>')
            return web.Response(text=error_html, content_type="text/html", headers=headers)

    def _serve_env(self, capture: dict) -> web.Response:
        """Serve a breadcrumb .env file."""
        capture["commands"].append(f"GET {capture.get('path', '/.env')} (breadcrumb served)")
        self._queue_interaction(capture)
        return web.Response(
            text=self._breadcrumb_env,
            content_type="text/plain",
            headers=self._response_headers(),
        )

    def _serve_robots(self) -> web.Response:
        robots = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /api/\n"
            "Disallow: /dashboard/\n"
            "Disallow: /.env\n"
            "Disallow: /config/\n"
            "Sitemap: /sitemap.xml\n"
        )
        return web.Response(text=robots, content_type="text/plain")

    def _serve_login(self) -> web.Response:
        html = self._config.get("login_html") or NEXTJS_LOGIN
        return web.Response(text=html, content_type="text/html", headers=self._response_headers())

    def _serve_admin(self, capture: dict) -> web.Response:
        """Serve a fake admin/dashboard page."""
        capture["commands"].append(f"Accessed admin panel: {capture.get('path')}")
        self._queue_interaction(capture)
        html = self._config.get("dashboard_html")
        if not html:
            html = NEXTJS_DASHBOARD
        return web.Response(text=html, content_type="text/html", headers=self._response_headers())

    def _serve_api(self, api_path: str, response_body: str, capture: dict) -> web.Response:
        """Serve a fake API response."""
        capture["commands"].append(f"API probe: {api_path}")
        self._queue_interaction(capture)
        content_type = "application/json" if response_body.startswith(("{", "[")) else "text/html"
        return web.Response(text=response_body, content_type=content_type, headers=self._response_headers())

    async def _ai_response(self, path: str, method: str, capture: dict) -> web.Response:
        """Use AI to generate a plausible response for an unknown path."""
        capture["commands"].append(f"{method} {path} (AI response)")
        self._queue_interaction(capture)

        try:
            messages = [{
                "role": "user",
                "content": (
                    f"An attacker is probing a {self.app_type} application and requested: "
                    f"{method} {path}\n"
                    f"User-Agent: {capture.get('user_agent', 'unknown')}\n\n"
                    f"Generate a realistic HTML or JSON response that a real {self.app_type} "
                    f"app would return for this path. Keep it brief (under 500 chars). "
                    f"Include realistic but fake data. No markdown, just raw HTML or JSON."
                ),
            }]
            result = await openrouter_client.query(messages, "decoy_content")
            content = result.get("content", "").strip()
            if not content:
                raise ValueError("Empty AI response")

            content_type = "application/json" if content.startswith(("{", "[")) else "text/html"
            return web.Response(text=content, content_type=content_type, headers=self._response_headers())
        except Exception as e:
            logger.debug(f"[Smart HTTP] AI response failed: {e}")
            # Fallback to 404
            return web.Response(
                text="<html><body><h1>404 Not Found</h1></body></html>",
                content_type="text/html", status=404,
                headers=self._response_headers(),
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_client_ip(self, request: web.Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "unknown"

    async def _capture_request(self, request: web.Request, path: str, method: str, source_ip: str) -> dict:
        """Capture full request details for intelligence."""
        headers = dict(request.headers)
        cookies = dict(request.cookies)

        body_text = ""
        file_uploads = []
        if method in ("POST", "PUT", "PATCH"):
            try:
                if request.content_type and "multipart" in request.content_type:
                    reader = await request.multipart()
                    async for part in reader:
                        if part.filename:
                            file_data = await part.read(chunk_size=4096)
                            file_uploads.append({
                                "filename": part.filename,
                                "content_type": part.headers.get("Content-Type", ""),
                                "size": len(file_data),
                            })
                        else:
                            body_text += (await part.read()).decode(errors="replace")
                else:
                    raw = await request.read()
                    body_text = raw.decode(errors="replace")[:8192]
            except Exception:
                pass

        return {
            "source_ip": source_ip,
            "source_port": None,
            "protocol": "http",
            "path": path,
            "method": method,
            "user_agent": headers.get("User-Agent", ""),
            "headers": headers,
            "cookies": cookies,
            "body": body_text[:4096],
            "file_uploads": file_uploads,
            "credentials_tried": [],
            "commands": [f"{method} {path}"],
            "session_duration": 0,
            "timestamp": datetime.utcnow().isoformat(),
            "honeypot_type": "smart_http",
            "app_imitated": self.app_type,
        }

    def _queue_interaction(self, data: dict):
        if self._interaction_queue:
            try:
                self._interaction_queue.put_nowait(data)
            except Exception as e:
                logger.error(f"[Smart HTTP] Failed to queue interaction: {e}")

    def _response_headers(self) -> dict:
        headers = {"Server": self._config["server_header"]}
        headers.update(self._config.get("extra_headers", {}))
        return headers
