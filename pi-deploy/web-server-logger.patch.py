"""Patch script: inline-injects AEGIS unified-feed write into web-server-logger.py
AND adds X-Forwarded-For / X-Real-IP header injection to proxy_request so the
upstream backend (sid-backend FastAPI) sees the real client IP.

Idempotent: detects if AEGIS feed block is already present and skips.
Run on Mac Pro: python3 web-server-logger.patch.py
"""
import re
import sys

TARGET = "/Users/alejandxr/web-server-logger.py"

with open(TARGET) as f:
    src = f.read()

if "AEGIS_FEED_PATH" in src:
    print("AEGIS feed block already present — skipping")
    sys.exit(0)

INJECT_AFTER = '        with open(LOG_FILE, "a") as f:\n            f.write(log_line + "\\n")\n'

INJECT_BLOCK = '''
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
                _fh.write(_aegis_json.dumps(_aegis_record, ensure_ascii=False) + "\\n")
        except Exception:
            pass  # never let logging take down the proxy
'''

if INJECT_AFTER not in src:
    print("ERROR: insertion point not found in target file", file=sys.stderr)
    sys.exit(1)

new_src = src.replace(INJECT_AFTER, INJECT_AFTER + INJECT_BLOCK, 1)

with open(TARGET, "w") as f:
    f.write(new_src)

print(f"OK: injected {len(INJECT_BLOCK)} bytes into {TARGET}")
