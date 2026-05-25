#!/usr/bin/env python3
"""
AEGIS HTTP Honeypot (Pi edition)
================================
Stdlib-only HTTP honeypot. Serves a fake WordPress login page, logs every
interaction to JSONL, and pushes the source IP to the local aegis-firewall
(:8765) on any credential-submission attempt or suspicious path. Also fires
an event to the Mac Pro AEGIS API (best-effort).
"""

import json
import logging
import os
import socket
import sys
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("HONEYPOT_PORT", "8081"))
LOG_FILE = os.environ.get("HONEYPOT_LOG", "/var/log/aegis/honeypot.log")
FIREWALL_URL = os.environ.get("AEGIS_LOCAL_FW", "http://127.0.0.1:8765")
AEGIS_API = os.environ.get("AEGIS_API_URL", "http://100.87.222.58:8000")
AEGIS_API_KEY = os.environ.get("AEGIS_API_KEY", "")

_SAFE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
]

SUSPICIOUS_PATHS = (
    "/.env", "/.git", "/wp-admin", "/wp-config", "/phpmyadmin",
    "/admin.php", "/server-status", "/.ssh", "/etc/passwd",
    "/owa/", "/manager/html", "/actuator", "/cgi-bin/",
    "/_ignition/", "/console/", "/api/jsonws/",
)

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("aegis-honeypot")

WP_LOGIN_PAGE = b"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>WordPress &mdash; Log In</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f1f1f1;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.wp-login{background:#fff;padding:26px;width:320px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.13)}h1{text-align:center;margin-bottom:20px}h1 a{font-size:20px;color:#23282d;text-decoration:none}.form-group{margin-bottom:16px}label{display:block;font-size:13px;font-weight:600;margin-bottom:4px;color:#444}input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:4px;font-size:14px}.wp-submit{width:100%;padding:10px;background:#0073aa;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer}.nav{text-align:center;margin-top:16px;font-size:12px}.nav a{color:#0073aa;text-decoration:none}</style>
</head><body><div class="wp-login"><h1><a>WordPress</a></h1>
<form method="POST" action="/wp-login.php">
<div class="form-group"><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" required></div>
<div class="form-group"><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" required></div>
<input type="submit" name="wp-submit" class="wp-submit" value="Log In"></form>
<div class="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>
</div></body></html>"""

ROBOTS_TXT = b"User-agent: *\nDisallow: /wp-admin/\nDisallow: /admin/\nDisallow: /.env\n"


def _is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
        # Note: NOT using `addr.is_private` — in Py 3.9+ it returns True for
        # TEST-NET (RFC 5737: 192.0.2/24, 198.51.100/24, 203.0.113/24) and
        # other "not globally reachable" ranges. We explicitly enumerate
        # the LAN/loopback/Tailscale ranges we want to skip.
        return addr.is_loopback or any(addr in n for n in _SAFE_NETS)
    except (ValueError, TypeError):
        return False


def _log_event(event):
    event["ts"] = datetime.now(timezone.utc).isoformat()
    line = json.dumps(event, default=str)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError as e:
        log.warning("Cannot write %s: %s", LOG_FILE, e)
    log.info(line)


def _block_ip(ip, reason):
    if _is_internal(ip):
        return
    body = json.dumps({"ip": ip, "reason": "honeypot:" + reason, "ttl": 86400}).encode()
    req = urllib.request.Request(
        FIREWALL_URL + "/block",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            log.info("blocked %s reason=%s code=%s", ip, reason, resp.status)
    except (urllib.error.URLError, socket.timeout) as e:
        log.warning("block %s failed: %s", ip, e)


def _report_to_aegis(event):
    if not AEGIS_API_KEY:
        return
    body = json.dumps(event).encode()
    req = urllib.request.Request(
        AEGIS_API + "/api/v1/phantom/external-event",
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": AEGIS_API_KEY},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=2).read()
    except Exception:
        pass


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def _client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For") or self.headers.get("CF-Connecting-IP")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _record(self, method, body=None, action="log"):
        ip = self._client_ip()
        event = {
            "source": "aegis-honeypot-pi",
            "ip": ip,
            "method": method,
            "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
            "host": self.headers.get("Host", ""),
            "body": (body[:512].decode("utf-8", "replace") if body else ""),
            "action": action,
            "internal": _is_internal(ip),
        }
        _log_event(event)
        _report_to_aegis(event)
        if action == "block":
            _block_ip(ip, method + " " + self.path[:40])

    def do_GET(self):
        path = self.path.lower()
        if any(s in path for s in SUSPICIOUS_PATHS):
            self._record("GET", action="block")
            self.send_response(404)
            self.end_headers()
            return
        if path.startswith("/robots.txt"):
            self._record("GET")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(ROBOTS_TXT)))
            self.end_headers()
            self.wfile.write(ROBOTS_TXT)
            return
        self._record("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(WP_LOGIN_PAGE)))
        self.send_header("Set-Cookie", "wordpress_test_cookie=WP+Cookie+check; path=/")
        self.end_headers()
        self.wfile.write(WP_LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 4096)) if length else b""
        self._record("POST", body=body, action="block")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><div id='login_error'><strong>Error:</strong> The password you entered is incorrect.</div></body></html>")

    def do_HEAD(self):
        self._record("HEAD")
        self.send_response(200)
        self.end_headers()


def main():
    log.info("AEGIS honeypot listening on %s:%d (log=%s)", LISTEN_HOST, LISTEN_PORT, LOG_FILE)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), HoneypotHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
