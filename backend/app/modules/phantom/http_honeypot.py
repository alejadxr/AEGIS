import asyncio
import ipaddress as _ipaddress
import json
import logging
from datetime import datetime
from pathlib import Path

from aiohttp import web

# Private/internal IP ranges — connections from these are NOT real attacks
_SAFE_NETS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),
]

def _is_internal(ip: str) -> bool:
    try:
        addr = _ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private or any(addr in n for n in _SAFE_NETS)
    except (ValueError, TypeError):
        return False

logger = logging.getLogger("aegis.phantom.http_honeypot")

CONFIG_PATH = Path.home() / "AEGIS" / "backend" / "honeypot_config.json"

# ---------------------------------------------------------------------------
# HTML Templates
# ---------------------------------------------------------------------------

TEMPLATES = {
    "wordpress": """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>WordPress &mdash; Log In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f1f1f1;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.wp-login{background:#fff;padding:26px;width:320px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
h1{text-align:center;margin-bottom:20px}
h1 a{font-size:20px;color:#23282d;text-decoration:none;font-weight:400}
.form-group{margin-bottom:16px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:4px;color:#444}
input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:4px;font-size:14px}
input[type=text]:focus,input[type=password]:focus{border-color:#0073aa;outline:none;box-shadow:0 0 0 1px #0073aa}
.wp-submit{width:100%;padding:10px;background:#0073aa;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer}
.wp-submit:hover{background:#006799}
.forgetmenot{font-size:12px;color:#555;margin-top:8px}
.nav{text-align:center;margin-top:16px;font-size:12px}
.nav a{color:#0073aa;text-decoration:none}
</style>
</head>
<body>
<div class="wp-login">
<h1><a>WordPress</a></h1>
<form method="POST" action="/login">
<div class="form-group"><label for="user_login">Username or Email Address</label>
<input type="text" name="username" id="user_login" required autocomplete="username"></div>
<div class="form-group"><label for="user_pass">Password</label>
<input type="password" name="password" id="user_pass" required autocomplete="current-password"></div>
<input type="submit" name="wp-submit" class="wp-submit" value="Log In">
<label class="forgetmenot"><input type="checkbox" name="rememberme"> Remember Me</label>
</form>
<div class="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>
</div>
</body></html>""",

    "phpmyadmin": """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>phpMyAdmin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#2a2a2a;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.pma-box{background:#f5f5f5;width:340px;border-radius:4px;overflow:hidden}
.pma-header{background:#f5793a;padding:14px 20px;color:#fff;font-size:20px;font-weight:bold}
.pma-body{padding:24px}
.form-group{margin-bottom:14px}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:3px;font-size:14px}
.pma-submit{width:100%;padding:10px;background:#f5793a;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer;font-weight:600}
.pma-submit:hover{background:#e06425}
.pma-version{text-align:center;margin-top:12px;font-size:11px;color:#999}
</style>
</head>
<body>
<div class="pma-box">
<div class="pma-header">phpMyAdmin</div>
<div class="pma-body">
<form method="POST" action="/login">
<div class="form-group"><label>Username</label>
<input type="text" name="username" required autocomplete="username" placeholder="root"></div>
<div class="form-group"><label>Password</label>
<input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="pma-submit">Go</button>
</form>
<div class="pma-version">phpMyAdmin 5.2.1 &mdash; MySQL 8.0.36</div>
</div>
</div>
</body></html>""",

    "grafana": """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Grafana</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#111217;color:#d8d9da;font-family:'Roboto',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.gf-box{width:360px}
.gf-logo{text-align:center;margin-bottom:30px;font-size:28px;font-weight:300;letter-spacing:2px;color:#ff9900}
.gf-card{background:#1f2128;border:1px solid #34343b;border-radius:4px;padding:30px}
h3{font-size:18px;font-weight:400;margin-bottom:24px;color:#d8d9da}
.form-group{margin-bottom:18px}
label{display:block;font-size:12px;color:#9fa7b3;margin-bottom:6px;font-weight:500;letter-spacing:.5px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;background:#0b0c0e;border:1px solid #34343b;border-radius:2px;color:#d8d9da;font-size:14px}
input:focus{border-color:#ff9900;outline:none}
.gf-submit{width:100%;padding:12px;background:#ff9900;color:#fff;border:none;border-radius:2px;font-size:14px;cursor:pointer;font-weight:500}
.gf-submit:hover{background:#e68900}
.gf-footer{text-align:center;margin-top:16px;font-size:12px;color:#6d7179}
.gf-footer a{color:#6d7179;text-decoration:none}
</style>
</head>
<body>
<div class="gf-box">
<div class="gf-logo">GRAFANA</div>
<div class="gf-card">
<h3>Welcome to Grafana</h3>
<form method="POST" action="/login">
<div class="form-group"><label>Email or username</label>
<input type="text" name="username" required autocomplete="username"></div>
<div class="form-group"><label>Password</label>
<input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="gf-submit">Log in</button>
</form>
<div class="gf-footer"><a href="/user/password/send-reset-email">Forgot your password?</a></div>
</div>
</div>
</body></html>""",

    "jenkins": """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Sign in [Jenkins]</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f6f6f6;font-family:Georgia,'Times New Roman',serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.jenkins-header{position:fixed;top:0;left:0;right:0;background:#335061;height:42px;display:flex;align-items:center;padding:0 16px}
.jenkins-header span{color:#fff;font-size:18px;font-family:sans-serif;font-weight:300;letter-spacing:1px}
.jk-box{background:#fff;width:380px;border:1px solid #ccc;border-radius:2px;padding:24px;margin-top:42px}
h1{font-size:20px;font-weight:400;color:#333;margin-bottom:20px}
.form-group{margin-bottom:14px}
label{display:block;font-size:13px;color:#333;margin-bottom:4px}
input[type=text],input[type=password]{width:100%;padding:7px 10px;border:1px solid #ccc;border-radius:2px;font-size:13px}
.jk-submit{padding:8px 20px;background:#4878a0;color:#fff;border:none;border-radius:2px;font-size:13px;cursor:pointer}
.jk-submit:hover{background:#3a6285}
.footer{text-align:center;margin-top:14px;font-size:12px;color:#888}
</style>
</head>
<body>
<div class="jenkins-header"><span>Jenkins</span></div>
<div class="jk-box">
<h1>Sign in to Jenkins</h1>
<form method="POST" action="/login">
<div class="form-group"><label>Username</label>
<input type="text" name="username" required autocomplete="username"></div>
<div class="form-group"><label>Password</label>
<input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="jk-submit">Sign in</button>
</form>
<div class="footer">Jenkins 2.440.3 &mdash; <a href="/securityRealm/createAccount">Create an account</a></div>
</div>
</body></html>""",

    "gitlab": """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Sign in &middot; GitLab</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fafafa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.gl-box{width:380px}
.gl-logo{text-align:center;margin-bottom:20px;font-size:26px;font-weight:700;color:#e24329}
.gl-logo span{color:#fca326}
.gl-card{background:#fff;border:1px solid #ddd;border-radius:4px;padding:28px}
h1{font-size:17px;color:#303030;margin-bottom:20px;font-weight:600}
.form-group{margin-bottom:14px}
label{display:block;font-size:13px;color:#303030;margin-bottom:4px;font-weight:600}
input[type=text],input[type=password]{width:100%;padding:9px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px}
input:focus{border-color:#6b4fbb;outline:none;box-shadow:0 0 0 2px rgba(107,79,187,.15)}
.gl-submit{width:100%;padding:11px;background:#6b4fbb;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;font-weight:600}
.gl-submit:hover{background:#5943a3}
.gl-footer{text-align:center;margin-top:14px;font-size:12px;color:#6e6e6e}
.gl-footer a{color:#6b4fbb;text-decoration:none}
</style>
</head>
<body>
<div class="gl-box">
<div class="gl-logo">Git<span>Lab</span></div>
<div class="gl-card">
<h1>Sign in to GitLab</h1>
<form method="POST" action="/login">
<div class="form-group"><label>Username or email address</label>
<input type="text" name="username" required autocomplete="username"></div>
<div class="form-group"><label>Password</label>
<input type="password" name="password" required autocomplete="current-password"></div>
<button type="submit" class="gl-submit">Sign in</button>
</form>
<div class="gl-footer"><a href="/users/password/new">Forgot your password?</a></div>
</div>
</div>
</body></html>""",
}

TEMPLATE_HEADERS = {
    "wordpress": {"Server": "Apache/2.4.52 (Ubuntu)", "X-Powered-By": "PHP/8.1.0"},
    "phpmyadmin": {"Server": "Apache/2.4.57 (Debian)", "X-Powered-By": "PHP/8.2.0"},
    "grafana": {"Server": "nginx/1.24.0"},
    "jenkins": {"Server": "Jetty(10.0.13)", "X-Content-Type-Options": "nosniff"},
    "gitlab": {"Server": "nginx", "X-Content-Type-Options": "nosniff"},
}

FAKE_ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /api/
Disallow: /config/
Disallow: /.env
Disallow: /backup/
Disallow: /internal/
"""

WATCHED_PATHS = {
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/.env",
    "/api/config", "/config", "/admin/login", "/administrator",
    "/wp-login.php", "/.git", "/backup", "/robots.txt", "/sitemap.xml",
    "/setup", "/install", "/dashboard", "/.htaccess",
}


def _get_active_template() -> tuple[str, dict]:
    """Return (html, headers) for the currently active template from config.

    The returned HTML includes the defensive canary `<script>` immediately
    before `</body>`. The canary runs ONLY on these honeypot decoy pages —
    never on the real AEGIS dashboard.
    """
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
        tpl = cfg.get("http", {}).get("template", "wordpress")
    except Exception:
        tpl = "wordpress"
    html = TEMPLATES.get(tpl, TEMPLATES["wordpress"])
    headers = TEMPLATE_HEADERS.get(tpl, TEMPLATE_HEADERS["wordpress"])

    # Inject the defensive canary just before </body>.
    try:
        from app.modules.phantom.canary_js import build_canary_script
        # Same-origin POST: the honeypot itself accepts /__c and forwards to DB.
        # Avoids CORS / cross-port issues; the attacker cannot infer the real
        # AEGIS API port from this endpoint name.
        canary = build_canary_script(
            endpoint="/__c",
            honeypot_source="mac_http_8888",
        )
        if "</body>" in html:
            html = html.replace("</body>", canary + "</body>", 1)
        else:
            html = html + canary
    except Exception as exc:
        logger.debug("[HTTP Honeypot] canary inject failed: %s", exc)
    return html, headers


class HTTPHoneypot:
    """HTTP honeypot on port 8888 — serves rotating decoy pages."""

    def __init__(self, port: int = 8888):
        self.port = port
        self._running = False
        self._runner: web.AppRunner | None = None
        self._interaction_queue: asyncio.Queue | None = None

    async def start(self, interaction_queue: asyncio.Queue):
        self._interaction_queue = interaction_queue
        self._running = True

        app = web.Application()
        app.router.add_get("/", self._handle_root)
        app.router.add_post("/login", self._handle_login)
        app.router.add_get("/robots.txt", self._handle_robots)
        # Defensive canary collection endpoint — same-origin so the browser
        # POSTs without CORS issues. Path name is intentionally obscure.
        app.router.add_post("/__c", self._handle_canary)
        app.router.add_route("*", "/{path_info:.*}", self._handle_catch_all)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.port)
        await site.start()
        logger.info(f"[HTTP Honeypot] Listening on port {self.port}")

    def _get_client_ip(self, request: web.Request) -> str:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote or "unknown"

    def _log_interaction(self, source_ip: str, path: str, method: str, headers: dict, extra: dict = None):
        # Skip internal/private IPs — these are self-scans, uptime checks, not real attacks
        if _is_internal(source_ip):
            return
        data = {
            "source_ip": source_ip,
            "source_port": None,
            "protocol": "http",
            "path": path,
            "method": method,
            "user_agent": headers.get("User-Agent", ""),
            "headers": dict(headers),
            "credentials_tried": [],
            "commands": [f"{method} {path}"],
            "session_duration": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if extra:
            data.update(extra)
        try:
            self._interaction_queue.put_nowait(data)
        except Exception as e:
            logger.error(f"[HTTP Honeypot] Failed to queue interaction: {e}")

    async def _handle_root(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        logger.info(f"[HTTP] GET / from {source_ip}")
        self._log_interaction(source_ip, "/", "GET", dict(request.headers))
        html, headers = _get_active_template()
        return web.Response(text=html, content_type="text/html", headers=headers)

    async def _handle_login(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        try:
            data = await request.post()
            username = data.get("username", "")
            password = data.get("password", "")
            logger.info(f"[HTTP] Login attempt from {source_ip}: {username}:{password}")
            self._log_interaction(
                source_ip, "/login", "POST", dict(request.headers),
                extra={
                    "credentials_tried": [{"username": username, "password": password}],
                    "commands": [f"POST /login username={username} password={password}"],
                }
            )
        except Exception as e:
            logger.warning(f"[HTTP] Error parsing login from {source_ip}: {e}")

        html, headers = _get_active_template()
        return web.Response(text=html, content_type="text/html", headers=headers, status=200)

    async def _handle_canary(self, request: web.Request) -> web.Response:
        """Same-origin canary POST. Persists to honeypot_canaries via the
        canary module. Returns 204 (sendBeacon needs no body)."""
        source_ip = self._get_client_ip(request)
        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        # Skip internal IPs (self-scans / uptime probes / Tailscale).
        if _is_internal(source_ip):
            return web.Response(status=204)
        try:
            from datetime import datetime as _dt
            from app.database import async_session
            from app.models.honeypot_canary import HoneypotCanary

            real_ip = None
            for cand in (data.get("webrtc_candidates") or [])[:32]:
                if not isinstance(cand, str):
                    continue
                cand = cand.strip()
                # Same _is_internal logic — only public, differing
                if cand and cand != source_ip and not _is_internal(cand):
                    real_ip = cand
                    break

            async with async_session() as db:
                row = HoneypotCanary(
                    client_id=None,
                    source_ip=source_ip,
                    real_ip_webrtc=real_ip,
                    webrtc_candidates=(data.get("webrtc_candidates") or [])[:32],
                    fingerprint_hash=(data.get("fingerprint_hash") or "")[:64] or None,
                    headless_detected=bool(data.get("headless_detected")),
                    browser_meta=data.get("browser_meta") or {},
                    honeypot_source=str(data.get("honeypot_source") or "mac_http_8888")[:64],
                    captured_at=_dt.utcnow(),
                )
                db.add(row)
                await db.commit()
            logger.info(
                "[HTTP Honeypot] canary src=%s real=%s headless=%s fp=%s",
                source_ip, real_ip, data.get("headless_detected"),
                (data.get("fingerprint_hash") or "")[:12],
            )
        except Exception as e:
            logger.warning(f"[HTTP Honeypot] canary persist failed: {e}")
        return web.Response(status=204)

    async def _handle_robots(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        logger.info(f"[HTTP] robots.txt accessed from {source_ip}")
        self._log_interaction(source_ip, "/robots.txt", "GET", dict(request.headers))
        return web.Response(text=FAKE_ROBOTS_TXT, content_type="text/plain")

    async def _handle_catch_all(self, request: web.Request) -> web.Response:
        source_ip = self._get_client_ip(request)
        path = "/" + request.match_info.get("path_info", "")
        method = request.method
        logger.info(f"[HTTP] {method} {path} from {source_ip} UA={request.headers.get('User-Agent','')!r}")
        self._log_interaction(source_ip, path, method, dict(request.headers))

        html, headers = _get_active_template()

        if path in (
            "/.env", "/api/config", "/config",
            "/.env.bak", "/.env.example", "/.env.production", "/.env.local",
            "/api/v1/internal/config",
        ):
            fake_env = (
                "# Production Environment\n"
                "APP_KEY=base64:fake_key_x8Kp2mN9vQ3wR7yT\n"
                "DB_HOST=db.internal.prod\n"
                "DB_USER=admin\n"
                "DB_PASSWORD=Tr4p_P4ssw0rd_2026\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7BREADCRUMB\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYBREADCRUMB\n"
                "OPENAI_API_KEY=sk-breadcrumb-trap-key\n"
                "STRIPE_SECRET_KEY=sk_live_breadcrumb_trap\n"
                "JWT_SECRET=breadcrumb-jwt-secret\n"
                "ADMIN_PASSWORD=Tr4p_Adm1n_2026\n"
                "API_SECRET=not_real_s3cr3t\n"
                "REDIS_URL=redis://cache.internal:6379\n"
            )
            return web.Response(
                text=fake_env,
                content_type="text/plain",
                headers={"Server": "Apache/2.4.52 (Ubuntu)"},
            )

        if path in ("/wp-config.php", "/wp-config.php.bak", "/wp-config.txt"):
            # WordPress config file with AWS canary credentials embedded as comments.
            # Reusing the same BREADCRUMB tokens so attackers trip the existing
            # BREADCRUMB_INDICATORS detector when they replay the creds anywhere.
            fake_wpconfig = (
                "<?php\n"
                "// ** Database settings ** //\n"
                "define( 'DB_NAME', 'wp_prod' );\n"
                "define( 'DB_USER', 'admin' );\n"
                "define( 'DB_PASSWORD', 'Tr4p_P4ssw0rd_2026' );\n"
                "define( 'DB_HOST', 'db.internal.prod' );\n"
                "\n"
                "// ** AWS S3 backup credentials (added 2025-11-14) ** //\n"
                "// AWS_ACCESS_KEY_ID=AKIAIOSFODNN7BREADCRUMB\n"
                "// AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYBREADCRUMB\n"
                "// S3_BUCKET=prod-backups-internal\n"
                "\n"
                "define( 'AUTH_KEY',         'breadcrumb-jwt-secret' );\n"
                "define( 'SECURE_AUTH_KEY',  'Tr4p_Adm1n_2026' );\n"
                "define( 'LOGGED_IN_KEY',    'sk-breadcrumb-trap-key' );\n"
                "define( 'NONCE_KEY',        'sk_live_breadcrumb_trap' );\n"
                "\n"
                "$table_prefix = 'wp_';\n"
                "define( 'WP_DEBUG', false );\n"
                "if ( ! defined( 'ABSPATH' ) ) {\n"
                "    define( 'ABSPATH', __DIR__ . '/' );\n"
                "}\n"
                "require_once ABSPATH . 'wp-settings.php';\n"
            )
            return web.Response(
                text=fake_wpconfig,
                content_type="text/plain",  # Apache mis-serves as text when leaked
                headers={"Server": "Apache/2.4.52 (Ubuntu)"},
            )

        if path in ("/wp-admin", "/wp-login.php", "/phpmyadmin", "/admin", "/administrator",
                    "/grafana", "/jenkins", "/gitlab"):
            return web.Response(text=html, content_type="text/html", headers=headers, status=200)

        return web.Response(
            text="<html><body><h1>404 Not Found</h1></body></html>",
            content_type="text/html",
            status=404,
            headers={"Server": headers.get("Server", "nginx/1.24.0")},
        )

    async def stop(self):
        self._running = False
        if self._runner:
            await self._runner.cleanup()
        logger.info("[HTTP Honeypot] Stopped")


http_honeypot = HTTPHoneypot(port=8888)
