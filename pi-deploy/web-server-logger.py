#!/usr/bin/env python3
import http.server
import socketserver
import sys
import os
from datetime import datetime, timedelta
import json
import re
import urllib.request
import urllib.error

# Attack detection patterns - Added by Rasputin
ATTACK_PATTERNS = {
    "sql_injection": re.compile(r"(?:union.+select|select.+from|insert.+into|drop.+table|1=1|or.+1=1|admin.--)", re.I),
    "xss": re.compile(r"(?:<script|javascript:|onerror|onload|<iframe|<svg.+onload|alert.?\()", re.I),
    "path_traversal": re.compile(r"(?:\.\./|%2e%2e|/etc/passwd|/proc/self)", re.I),
    "command_injection": re.compile(r"(?:;.*(cat|ls|id|whoami|wget|curl)|\|.*(cat|ls))", re.I),
}

def detect_attack(path):
    for attack_type, pattern in ATTACK_PATTERNS.items():
        if pattern.search(path):
            return attack_type
    return None


PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
LOG_FILE = sys.argv[2] if len(sys.argv) > 2 else "/tmp/access.log"
STATS_FILE = LOG_FILE.replace(".log", "-stats.json")

# Backend API server
BACKEND_URL = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8080"

# Allowed locations (DO = Dominican Republic, US with specific regions)
ALLOWED_COUNTRIES = ["DO"]
ALLOWED_US_REGIONS = ["NY", "NJ", "FL"]  # New York area and common regions

# Country codes to names
COUNTRIES = {
    "DO": "Dominican Republic", "US": "United States", "MX": "Mexico",
    "ES": "Spain", "AR": "Argentina", "CO": "Colombia", "CL": "Chile",
    "PE": "Peru", "VE": "Venezuela", "EC": "Ecuador", "GT": "Guatemala",
    "CU": "Cuba", "PR": "Puerto Rico", "PA": "Panama", "CR": "Costa Rica",
    "UY": "Uruguay", "PY": "Paraguay", "BO": "Bolivia", "HN": "Honduras",
    "SV": "El Salvador", "NI": "Nicaragua", "BR": "Brazil", "CA": "Canada",
    "GB": "United Kingdom", "DE": "Germany", "FR": "France", "IT": "Italy",
    "JP": "Japan", "CN": "China", "IN": "India", "AU": "Australia",
    "RU": "Russia", "KR": "South Korea", "NL": "Netherlands", "SE": "Sweden"
}

def get_device_info(ua):
    ua_lower = ua.lower() if ua else ""

    if "iphone" in ua_lower:
        device = "iPhone"
    elif "ipad" in ua_lower:
        device = "iPad"
    elif "android" in ua_lower and "mobile" in ua_lower:
        device = "Android"
    elif "android" in ua_lower:
        device = "Android Tablet"
    elif "macintosh" in ua_lower or "mac os" in ua_lower:
        device = "Mac"
    elif "windows" in ua_lower:
        device = "Windows"
    elif "linux" in ua_lower:
        device = "Linux"
    elif "bot" in ua_lower or "crawler" in ua_lower or "spider" in ua_lower:
        device = "Bot"
    else:
        device = "Unknown"

    if "chrome" in ua_lower and "edg" not in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        browser = "Edge"
    elif "opera" in ua_lower:
        browser = "Opera"
    elif "bot" in ua_lower:
        browser = "Bot"
    else:
        browser = "Other"

    return device, browser

def is_suspicious(country_code):
    if not country_code or country_code == "":
        return False  # Local requests are OK
    if country_code in ALLOWED_COUNTRIES:
        return False
    if country_code == "US":
        return False  # Allow all US for now
    return True

def cleanup_old_visits(visits, hours=24):
    cutoff = datetime.now() - timedelta(hours=hours)
    return [v for v in visits if datetime.fromisoformat(v["time"]) > cutoff]

def cleanup_old_logs(log_file, days=30):
    try:
        if not os.path.exists(log_file):
            return
        lines = []
        cutoff = datetime.now() - timedelta(days=days)
        with open(log_file, "r") as f:
            for line in f:
                try:
                    timestamp = line.split(" | ")[0]
                    if datetime.fromisoformat(timestamp) > cutoff:
                        lines.append(line)
                except:
                    lines.append(line)
        with open(log_file, "w") as f:
            f.writelines(lines)
    except:
        pass

class ProxyLoggingHandler(http.server.SimpleHTTPRequestHandler):
    # Correct MIME types for modern web files
    extensions_map = {
        '': 'application/octet-stream',
        '.html': 'text/html',
        '.htm': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.mjs': 'application/javascript',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon',
        '.woff': 'font/woff',
        '.woff2': 'font/woff2',
        '.ttf': 'font/ttf',
        '.otf': 'font/otf',
        '.pdf': 'application/pdf',
        '.webp': 'image/webp',
        '.xml': 'application/xml',
        '.txt': 'text/plain',
        '.map': 'application/json',
    }

    def get_real_ip(self):
        cf_headers = ["Cf-Connecting-Ip", "CF-Connecting-IP", "cf-connecting-ip",
                      "X-Forwarded-For", "X-Real-IP"]
        for header_name in cf_headers:
            ip = self.headers.get(header_name)
            if ip:
                if "forward" in header_name.lower():
                    ip = ip.split(",")[0].strip()
                return ip
        return self.client_address[0]

    def get_country(self):
        country_code = self.headers.get("Cf-Ipcountry") or self.headers.get("CF-IPCountry") or ""
        country_name = COUNTRIES.get(country_code.upper(), country_code.upper() if country_code else "Local")
        return country_code.upper(), country_name

    def log_message(self, format, *args):
        real_ip = self.get_real_ip()
        ua = self.headers.get("User-Agent", "Unknown")
        country_code, country_name = self.get_country()
        device, browser = get_device_info(ua)
        suspicious = is_suspicious(country_code)
        
        # Detect attacks in full path (includes query string)
        attack_type = detect_attack(self.path)
        if attack_type:
            suspicious = True
            status = "ATTACK:" + attack_type.upper()
        else:
            status = "SUSPICIOUS" if suspicious else "OK"

        log_line = "{} | {} | {} | {} | {} | {} {} | {}".format(
            datetime.now().isoformat(),
            real_ip,
            country_code or "LOCAL",
            device,
            status,
            self.command,
            self.path,
            browser
        )
        with open(LOG_FILE, "a") as f:
            f.write(log_line + "\n")

        # === AEGIS unified feed (inline — no external dep) ===
        # Append one JSON line per request to the central feed so AEGIS
        # log_watcher gets HTTP-layer visibility with real client IPs.
        try:
            import json as _aegis_json
            import os as _aegis_os
            from datetime import datetime as _aegis_dt, timezone as _aegis_tz
            _aegis_feed = _aegis_os.environ.get(
                "AEGIS_FEED_PATH",
                "/Users/alejandxr/web-logs/aegis-feed.jsonl",
            )
            _aegis_app = _aegis_os.environ.get("AEGIS_APP_NAME") or (
                _aegis_os.path.basename(LOG_FILE)
                .replace("-access.log", "")
                .replace(".log", "")
            )
            _aegis_status = 200
            if args and len(args) >= 3:
                try:
                    _aegis_status = int(str(args[2]).split()[0])
                except (ValueError, IndexError):
                    pass
            _aegis_now = _aegis_dt.now(_aegis_tz.utc)
            _aegis_record = {
                "ts": _aegis_now.strftime("%Y-%m-%dT%H:%M:%S.")
                      + f"{_aegis_now.microsecond // 1000:03d}Z",
                "app": _aegis_app,
                "src_ip": real_ip,
                "method": self.command,
                "path": self.path,
                "status": _aegis_status,
            }
            for _k, _v in (
                ("ua", ua),
                ("ref", self.headers.get("Referer", "")),
                ("host", self.headers.get("Host", "")),
                ("country", country_code),
                ("fwd_chain", self.headers.get("X-Forwarded-For", "")),
                ("cf_ray", self.headers.get("Cf-Ray", "")),
                ("attack_type", attack_type or ""),
            ):
                if _v:
                    _aegis_record[_k] = _v
            with open(_aegis_feed, "a", buffering=1) as _fh:
                _fh.write(_aegis_json.dumps(_aegis_record, ensure_ascii=False) + "\n")
        except Exception:
            pass  # never let logging take down the proxy

        # Cleanup old logs periodically (every 100 requests)
        self.update_stats(real_ip, country_code, country_name, device, browser, ua, suspicious)

    def update_stats(self, real_ip, country_code, country_name, device, browser, ua, suspicious):
        stats = {
            "total_requests": 0,
            "unique_ips": [],
            "last_updated": "",
            "recent_visits": [],
            "suspicious_visits": [],
            "countries": {},
            "devices": {},
            "browsers": {},
            "alerts": []
        }
        if os.path.exists(STATS_FILE):
            try:
                with open(STATS_FILE, "r") as f:
                    stats = json.load(f)
            except:
                pass

        # Ensure all keys exist
        for key in ["suspicious_visits", "alerts"]:
            if key not in stats:
                stats[key] = []

        stats["total_requests"] += 1
        if real_ip not in stats["unique_ips"]:
            stats["unique_ips"].append(real_ip)
        stats["last_updated"] = datetime.now().isoformat()

        # Count countries
        if "countries" not in stats:
            stats["countries"] = {}
        if country_name:
            stats["countries"][country_name] = stats["countries"].get(country_name, 0) + 1

        # Count devices
        if "devices" not in stats:
            stats["devices"] = {}
        stats["devices"][device] = stats["devices"].get(device, 0) + 1

        # Count browsers
        if "browsers" not in stats:
            stats["browsers"] = {}
        stats["browsers"][browser] = stats["browsers"].get(browser, 0) + 1

        visit = {
            "time": datetime.now().isoformat(),
            "ip": real_ip,
            "path": self.path,
            "country": country_name,
            "country_code": country_code,
            "device": device,
            "browser": browser,
            "ua": ua[:100] if ua else "Unknown",
            "suspicious": suspicious
        }

        # Add to appropriate list
        if suspicious:
            stats["suspicious_visits"] = [visit] + stats.get("suspicious_visits", [])[:99]
            # Add alert
            alert = {
                "time": datetime.now().isoformat(),
                "type": "suspicious_visitor",
                "message": "Visitor from {} ({}) - IP: {}".format(country_name, country_code, real_ip),
                "ip": real_ip,
                "country": country_name
            }
            stats["alerts"] = [alert] + stats.get("alerts", [])[:49]

        # Add to recent visits
        recent = stats.get("recent_visits", [])
        stats["recent_visits"] = [visit] + recent[:99]

        # Cleanup old visits (keep last 24 hours)
        stats["recent_visits"] = cleanup_old_visits(stats["recent_visits"], 24)
        stats["suspicious_visits"] = cleanup_old_visits(stats.get("suspicious_visits", []), 24)

        with open(STATS_FILE, "w") as f:
            json.dump(stats, f)

        # Cleanup logs periodically
        if stats["total_requests"] % 100 == 0:
            cleanup_old_logs(LOG_FILE, 30)

    def is_api_request(self):
        """Check if this is an API request that should be proxied"""
        # Proxy /api/* and legacy root-level endpoints
        if self.path.startswith('/api/'):
            return True
        # Legacy endpoints at root level (ALL backend routes)
        legacy_paths = [
            '/test-connection', '/health',
            '/extract-recipe', '/analyze-frame', '/extract-spark-data',
            '/extract-rework-info', '/estimate-all-measurements',
            '/analyze-damage', '/analyze-rework-damage',
            '/base-catalog.csv', '/base-catalog', '/next-order-id', '/order-counter',
            '/log', '/urgent-orders', '/rxi/',
            '/gemini/', '/jobs/', '/customers/', '/tasks/', '/catalog/'
        ]
        for legacy in legacy_paths:
            if self.path.startswith(legacy) or self.path == legacy.rstrip('/'):
                return True
        return False

    def proxy_request(self, method):
        """Proxy request to backend API server"""
        target_url = BACKEND_URL + self.path

        # Read request body if present
        content_length = self.headers.get('Content-Length')
        body = None
        if content_length:
            body = self.rfile.read(int(content_length))

        # Build headers for backend request
        headers = {}
        for header in ['Content-Type', 'Accept', 'Authorization']:
            if self.headers.get(header):
                headers[header] = self.headers.get(header)

        # AEGIS: inject real client IP into upstream request so the backend
        # (e.g. FastAPI sid-backend) sees the real attacker instead of 127.0.0.1.
        # Combined with uvicorn --proxy-headers --forwarded-allow-ips=127.0.0.1
        # this lets request.client.host resolve correctly.
        _aegis_real_ip = self.get_real_ip()
        if _aegis_real_ip and _aegis_real_ip not in ("127.0.0.1", "::1"):
            headers["X-Forwarded-For"] = _aegis_real_ip
            headers["X-Real-IP"] = _aegis_real_ip
            _aegis_cf = self.headers.get("Cf-Connecting-Ip") or self.headers.get("CF-Connecting-IP")
            if _aegis_cf:
                headers["CF-Connecting-IP"] = _aegis_cf
            _aegis_cfray = self.headers.get("Cf-Ray") or self.headers.get("CF-Ray")
            if _aegis_cfray:
                headers["CF-Ray"] = _aegis_cfray
            _aegis_country = self.headers.get("Cf-Ipcountry") or self.headers.get("CF-IPCountry")
            if _aegis_country:
                headers["CF-IPCountry"] = _aegis_country

        try:
            req = urllib.request.Request(
                target_url,
                data=body,
                headers=headers,
                method=method
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                # Send response status
                self.send_response(response.status)

                # Forward response headers
                for header, value in response.getheaders():
                    # Skip hop-by-hop headers
                    if header.lower() not in ['transfer-encoding', 'connection', 'keep-alive']:
                        self.send_header(header, value)

                # Add CORS headers for API
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                self.end_headers()

                # Send response body
                self.wfile.write(response.read())

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            error_body = e.read() if e.fp else b'{"error": "Backend error"}'
            self.wfile.write(error_body)

        except urllib.error.URLError as e:
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Backend unavailable", "details": str(e.reason)}).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Proxy error", "details": str(e)}).encode())

    def do_GET(self):
        if self.is_api_request():
            self.proxy_request('GET')
        else:
            # Add no-cache headers for service worker
            if self.path in ['/service-worker.js', '/sw.js']:
                sw_file = 'sw.js' if self.path == '/sw.js' else 'service-worker.js'
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                try:
                    with open(sw_file, 'rb') as f:
                        self.wfile.write(f.read())
                except:
                    pass
                return
            # Long cache for hashed assets (1 year)
            if '/assets/' in self.path and ('-' in self.path.split('/')[-1]):
                self.send_response(200)
                file_path = self.path.lstrip('/')
                ext = os.path.splitext(file_path)[1]
                content_type = self.extensions_map.get(ext, 'application/octet-stream')
                self.send_header('Content-Type', content_type)
                self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
                self.end_headers()
                try:
                    with open(file_path, 'rb') as f:
                        self.wfile.write(f.read())
                except FileNotFoundError:
                    self.send_error(404)
                return
            # No-cache for HTML (index.html, /) to force iOS PWA updates
            if self.path == '/' or self.path.endswith('.html'):
                file_path = 'index.html' if self.path == '/' else self.path.lstrip('/')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                try:
                    with open(file_path, 'rb') as f:
                        self.wfile.write(f.read())
                except FileNotFoundError:
                    self.send_error(404)
                return
            super().do_GET()

    def do_POST(self):
        if self.is_api_request():
            self.proxy_request('POST')
        else:
            self.send_response(405)
            self.end_headers()

    def do_PUT(self):
        if self.is_api_request():
            self.proxy_request('PUT')
        else:
            self.send_response(405)
            self.end_headers()

    def do_DELETE(self):
        if self.is_api_request():
            self.proxy_request('DELETE')
        else:
            self.send_response(405)
            self.end_headers()

    def do_PATCH(self):
        if self.is_api_request():
            self.proxy_request('PATCH')
        else:
            self.send_response(405)
            self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), ProxyLoggingHandler) as httpd:
        print("Serving on port {}, logging to {}".format(PORT, LOG_FILE))
        print("API proxy enabled: /api/* -> {}".format(BACKEND_URL))
        httpd.serve_forever()
