#!/usr/bin/env python3
"""Idempotent patcher for sid-backend FastAPI main.py.
Adds AEGIS access-log middleware after CORSMiddleware.
"""
import sys

TARGET = "/Users/alejandxr/sid-wilab/backend/main.py"

with open(TARGET) as f:
    src = f.read()

if "AEGIS unified-feed middleware" in src:
    print("AEGIS middleware already injected — skipping")
    sys.exit(0)

ANCHOR = '''app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
'''

INJECT = '''
# === AEGIS unified-feed middleware ===
# Emits one JSON line per HTTP request to /Users/alejandxr/web-logs/aegis-feed.jsonl
# so AEGIS log_watcher gets HTTP-layer visibility with real client IPs.
# Requires uvicorn to be launched with --proxy-headers --forwarded-allow-ips=127.0.0.1
# AND for the upstream proxy (web-server-logger.py) to inject X-Forwarded-For.
import json as _aegis_json
import time as _aegis_time
from datetime import datetime as _aegis_dt, timezone as _aegis_tz
_AEGIS_FEED = os.environ.get(
    "AEGIS_FEED_PATH", "/Users/alejandxr/web-logs/aegis-feed.jsonl"
)

@app.middleware("http")
async def _aegis_access_log(request, call_next):
    _start = _aegis_time.time()
    response = await call_next(request)
    try:
        _hdr = request.headers
        _src_ip = (
            _hdr.get("cf-connecting-ip")
            or (_hdr.get("x-forwarded-for") or "").split(",")[0].strip()
            or _hdr.get("x-real-ip")
            or (request.client.host if request.client else "unknown")
        )
        _now = _aegis_dt.now(_aegis_tz.utc)
        _record = {
            "ts": _now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{_now.microsecond // 1000:03d}Z",
            "app": "sid-backend",
            "src_ip": _src_ip,
            "method": request.method,
            "path": str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
            "status": response.status_code,
            "rt_ms": int((_aegis_time.time() - _start) * 1000),
        }
        for _k, _hk in (
            ("ua", "user-agent"),
            ("ref", "referer"),
            ("host", "host"),
            ("country", "cf-ipcountry"),
            ("fwd_chain", "x-forwarded-for"),
            ("cf_ray", "cf-ray"),
        ):
            _v = _hdr.get(_hk)
            if _v:
                _record[_k] = _v
        with open(_AEGIS_FEED, "a", buffering=1) as _fh:
            _fh.write(_aegis_json.dumps(_record, ensure_ascii=False) + "\\n")
    except Exception:
        pass  # never let logging break the request
    return response

'''

if ANCHOR not in src:
    print("ERROR: CORSMiddleware anchor not found", file=sys.stderr)
    sys.exit(1)

new_src = src.replace(ANCHOR, ANCHOR + INJECT, 1)
with open(TARGET, "w") as f:
    f.write(new_src)
print(f"OK: injected {len(INJECT)} bytes")
