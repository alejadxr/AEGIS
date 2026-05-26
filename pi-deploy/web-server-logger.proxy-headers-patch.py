#!/usr/bin/env python3
"""Patch script: add X-Forwarded-For / X-Real-IP header injection to
web-server-logger.py's proxy_request() so the upstream backend sees the
real client IP instead of 127.0.0.1.

Idempotent.
"""
import sys

TARGET = "/Users/alejandxr/web-server-logger.py"

with open(TARGET) as f:
    src = f.read()

if "_aegis_real_ip = self.get_real_ip()" in src:
    print("proxy headers already injected — skipping")
    sys.exit(0)

# Anchor: the for-loop that builds upstream headers.
ANCHOR = """        # Build headers for backend request
        headers = {}
        for header in ['Content-Type', 'Accept', 'Authorization']:
            if self.headers.get(header):
                headers[header] = self.headers.get(header)
"""

INJECT = """
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
"""

if ANCHOR not in src:
    print("ERROR: proxy_request anchor not found", file=sys.stderr)
    sys.exit(1)

new_src = src.replace(ANCHOR, ANCHOR + INJECT, 1)
with open(TARGET, "w") as f:
    f.write(new_src)
print(f"OK: injected {len(INJECT)} bytes (X-Forwarded-For / X-Real-IP / CF-*)")
