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

# Defensive canary JS — embedded in the WordPress decoy page only.
# Tor Browser blocks WebRTC entirely; raw scrapers never execute JS.
# Captures voluntary browser features (WebRTC ICE candidates, canvas/audio
# fingerprint, automation markers) and POSTs same-origin to /__c.
_CANARY_JS = b"""<script>(function(){if(!document||!window)return;var c={webrtc_candidates:[],fingerprint_hash:null,headless_detected:false,browser_meta:{},honeypot_source:"pi_http_8081"};try{var h=false;if(navigator.webdriver===true)h=true;if(window.callPhantom||window._phantom)h=true;if(window.__nightmare)h=true;if(navigator.userAgent&&/HeadlessChrome|PhantomJS/i.test(navigator.userAgent))h=true;c.headless_detected=h;}catch(e){}try{c.browser_meta={ua:navigator.userAgent||null,lang:navigator.language||null,langs:(navigator.languages||[]).slice(0,8),platform:navigator.platform||null,cores:navigator.hardwareConcurrency||null,tz:Intl.DateTimeFormat().resolvedOptions().timeZone||null,screen:{w:screen.width,h:screen.height,d:window.devicePixelRatio||1},plugins:Array.prototype.slice.call(navigator.plugins||[]).map(function(p){return p&&p.name;}).filter(Boolean).slice(0,8),referrer:document.referrer||null};}catch(e){}function H(s){var h=5381;for(var i=0;i<s.length;i++)h=((h<<5)+h)^s.charCodeAt(i);return('00000000'+(h>>>0).toString(16)).slice(-8);}try{var p=[];var cv=document.createElement('canvas');cv.width=220;cv.height=40;var ctx=cv.getContext('2d');if(ctx){ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillStyle='#069';ctx.fillText('aegis canary \\u2603 '+(navigator.platform||''),2,2);ctx.fillStyle='rgba(102,204,0,.7)';ctx.fillText('AEGIS',4,18);p.push(cv.toDataURL());}var gc=document.createElement('canvas');var gl=gc.getContext('webgl')||gc.getContext('experimental-webgl');if(gl){var d=gl.getExtension('WEBGL_debug_renderer_info');if(d){p.push(gl.getParameter(d.UNMASKED_VENDOR_WEBGL));p.push(gl.getParameter(d.UNMASKED_RENDERER_WEBGL));}}if(window.AudioContext||window.webkitAudioContext){var AC=window.AudioContext||window.webkitAudioContext;var a=new AC();p.push(a.sampleRate+'|'+a.baseLatency);try{a.close();}catch(e){}}p.push((c.browser_meta.tz||'')+'|'+(c.browser_meta.screen||{}).w+'x'+(c.browser_meta.screen||{}).h+'|'+(c.browser_meta.ua||''));c.fingerprint_hash=H(p.join('::'));}catch(e){}function s(){try{var b=JSON.stringify(c);if(navigator.sendBeacon){navigator.sendBeacon('/__c',new Blob([b],{type:'application/json'}));return;}var x=new XMLHttpRequest();x.open('POST','/__c',true);x.setRequestHeader('Content-Type','application/json');x.send(b);}catch(e){}}try{var R=window.RTCPeerConnection||window.webkitRTCPeerConnection||window.mozRTCPeerConnection;if(R){var pc=new R({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});pc.createDataChannel('');pc.onicecandidate=function(e){if(!e||!e.candidate||!e.candidate.candidate)return;var m=/([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9:]+:[a-f0-9:]+)/i.exec(e.candidate.candidate);if(m&&m[1]&&c.webrtc_candidates.indexOf(m[1])===-1)c.webrtc_candidates.push(m[1]);};pc.createOffer().then(function(o){pc.setLocalDescription(o);}).catch(function(){});setTimeout(function(){try{pc.close();}catch(e){}s();},1400);}else{setTimeout(s,200);}}catch(e){setTimeout(s,200);}})();</script>"""

WP_LOGIN_PAGE = b"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>WordPress &mdash; Log In</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#f1f1f1;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.wp-login{background:#fff;padding:26px;width:320px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.13)}h1{text-align:center;margin-bottom:20px}h1 a{font-size:20px;color:#23282d;text-decoration:none}.form-group{margin-bottom:16px}label{display:block;font-size:13px;font-weight:600;margin-bottom:4px;color:#444}input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:4px;font-size:14px}.wp-submit{width:100%;padding:10px;background:#0073aa;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer}.nav{text-align:center;margin-top:16px;font-size:12px}.nav a{color:#0073aa;text-decoration:none}</style>
</head><body><div class="wp-login"><h1><a>WordPress</a></h1>
<form method="POST" action="/wp-login.php">
<div class="form-group"><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" required></div>
<div class="form-group"><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" required></div>
<input type="submit" name="wp-submit" class="wp-submit" value="Log In"></form>
<div class="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>
</div>""" + _CANARY_JS + b"""</body></html>"""

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

    def _forward_canary(self, payload_bytes: bytes, attacker_ip: str):
        """Forward canary capture to AEGIS API with source_ip_override."""
        try:
            data = json.loads(payload_bytes.decode("utf-8", "ignore") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data["source_ip_override"] = attacker_ip
        data.setdefault("honeypot_source", "pi_http_8081")
        body = json.dumps(data).encode()
        # Forward over Tailscale (private CIDR) -> trusted forwarder rule on API
        url = AEGIS_API + "/api/v1/phantom/canary"
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=3).read()
            log.info("canary forwarded src=%s candidates=%d",
                     attacker_ip, len(data.get("webrtc_candidates") or []))
        except Exception as e:
            log.warning("canary forward failed: %s", e)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        # /__c is the defensive canary submission endpoint (same-origin from
        # the WordPress decoy page). Handled separately so it doesn't trigger
        # block actions like real /wp-login.php POSTs.
        if self.path.startswith("/__c"):
            body = self.rfile.read(min(length, 16384)) if length else b""
            attacker_ip = self._client_ip()
            if not _is_internal(attacker_ip):
                self._forward_canary(body, attacker_ip)
            self.send_response(204)
            self.end_headers()
            return
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
