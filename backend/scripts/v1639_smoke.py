#!/usr/bin/env python3
"""
v1.6.3.9 integration smoke test.

Verifies the AEGIS deployment end-to-end against a live API:

    1. GET  /health                                version == "1.6.3.9"
    2. POST /api/v1/correlation/test               synthetic ssh_failed_auth event
                                                   (falls back to a benign 401-flood
                                                   against /api/v1/dashboard/health
                                                   if the test endpoint is unavailable)
    3. GET  /api/v1/response/incidents?since=24h   no "SSH Brute Force Detected"
                                                   incidents present (verifies the
                                                   sigma_auth_account_lockout dedup
                                                   change shipped in v1.6.3.9)
    4. GET  /api/v1/correlation/rules              http_auth_brute_force rule loaded
       GET  /api/v1/correlation/stats              rules_total > 0

Usage
-----
    AEGIS_API_KEY=... python backend/scripts/v1639_smoke.py
    AEGIS_API_KEY=... AEGIS_BASE_URL=http://YOUR_SERVER_IP:8000 \\
        python backend/scripts/v1639_smoke.py

Exit code is 0 when every check passes, 1 otherwise. Pure stdlib — no pytest,
no httpx, no requests.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

EXPECTED_VERSION = "1.6.3.9"
BANNED_INCIDENT_TITLES = {"SSH Brute Force Detected"}
REQUIRED_RULE_IDS = {"http_auth_brute_force"}

DEFAULT_BASE_URL = os.environ.get("AEGIS_BASE_URL", "http://localhost:8000")
API_KEY = os.environ.get("AEGIS_API_KEY", "").strip()
TIMEOUT = float(os.environ.get("AEGIS_SMOKE_TIMEOUT", "10"))

# Allow self-signed certs in lab deployments.
_SSL_CTX = ssl.create_default_context()
if os.environ.get("AEGIS_SMOKE_INSECURE") == "1":
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# Tiny pretty printer
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_BOLD = "\033[1m"

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{_RESET}"


def _row(status: str, name: str, detail: str = "") -> None:
    pad = name.ljust(48)
    print(f"  {status}  {pad}{detail}")


def ok(name: str, detail: str = "") -> None:
    _row(_c("PASS", _GREEN + _BOLD), name, detail)


def fail(name: str, detail: str = "") -> None:
    _row(_c("FAIL", _RED + _BOLD), name, detail)


def warn(name: str, detail: str = "") -> None:
    _row(_c("WARN", _YELLOW + _BOLD), name, detail)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

class HTTPResult:
    __slots__ = ("status", "headers", "body", "error")

    def __init__(
        self,
        status: int,
        headers: dict[str, str],
        body: bytes,
        error: str | None = None,
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.error = error

    def json(self) -> Any:
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))


def http(
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = TIMEOUT,
) -> HTTPResult:
    url = base_url.rstrip("/") + path
    data: bytes | None = None
    headers: dict[str, str] = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["X-API-Key"] = api_key

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return HTTPResult(resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as e:
        try:
            payload = e.read()
        except Exception:
            payload = b""
        return HTTPResult(e.code, dict(e.headers or {}), payload, error=str(e))
    except urllib.error.URLError as e:
        return HTTPResult(0, {}, b"", error=f"URLError: {e.reason}")
    except Exception as e:  # pragma: no cover - last-resort guard
        return HTTPResult(0, {}, b"", error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_health(base_url: str) -> bool:
    r = http("GET", "/health", base_url=base_url)
    if r.status != 200:
        fail("health endpoint reachable", f"status={r.status} err={r.error or ''}")
        return False
    try:
        payload = r.json() or {}
    except Exception as e:
        fail("health endpoint returns JSON", f"{type(e).__name__}: {e}")
        return False
    version = str(payload.get("version", ""))
    if version != EXPECTED_VERSION:
        fail(
            "health version == " + EXPECTED_VERSION,
            f"got version={version!r} payload={payload}",
        )
        return False
    ok(f"health version == {EXPECTED_VERSION}", f"ai_mode={payload.get('ai_mode')}")
    return True


def check_synthetic_event(base_url: str, api_key: str) -> bool:
    """
    Submit a synthetic ssh_failed_auth event to /api/v1/correlation/test (analyst+).
    Falls back to a benign 401-flood against /api/v1/dashboard/health when the
    correlation/test endpoint is forbidden or missing - this still exercises the
    auth path and produces real telemetry.
    """
    event = {
        "event": {
            "type": "ssh_failed_auth",
            "src_ip": "203.0.113.66",
            "user": "root",
            "timestamp": time.time(),
            "source": "v1639_smoke",
        }
    }
    r = http(
        "POST",
        "/api/v1/correlation/test",
        body=event,
        api_key=api_key,
        base_url=base_url,
    )
    if r.status == 200:
        try:
            payload = r.json() or {}
        except Exception:
            payload = {}
        triggered = payload.get("triggered_count", 0)
        ok(
            "synthetic event accepted (/correlation/test)",
            f"triggered_rules={triggered}",
        )
        return True

    if r.status in (401, 403):
        warn(
            "synthetic event via /correlation/test",
            f"status={r.status} - falling back to 401-flood",
        )
        # Generate a small burst of 401s using an obviously-bogus key.
        flood_url = "/api/v1/dashboard/health"
        bogus_key = "smoke-bogus-key-not-real"
        statuses: list[int] = []
        for _ in range(5):
            fr = http("GET", flood_url, api_key=bogus_key, base_url=base_url)
            statuses.append(fr.status)
        if any(s in (401, 403, 404) for s in statuses):
            ok(
                "fallback 401-flood produced expected status",
                f"statuses={statuses}",
            )
            return True
        fail(
            "fallback 401-flood produced expected status",
            f"statuses={statuses}",
        )
        return False

    fail(
        "synthetic event accepted (/correlation/test)",
        f"status={r.status} err={r.error or ''} body={r.body[:200]!r}",
    )
    return False


def check_no_ssh_brute_force_incidents(base_url: str, api_key: str) -> bool:
    r = http(
        "GET",
        "/api/v1/response/incidents?since=24h&limit=1000",
        api_key=api_key,
        base_url=base_url,
    )
    if r.status != 200:
        fail(
            "incidents endpoint reachable",
            f"status={r.status} err={r.error or ''}",
        )
        return False
    try:
        incidents = r.json() or []
    except Exception as e:
        fail("incidents response is JSON", f"{type(e).__name__}: {e}")
        return False
    if not isinstance(incidents, list):
        fail("incidents response is a list", f"got type={type(incidents).__name__}")
        return False

    offenders = [
        i for i in incidents
        if isinstance(i, dict) and i.get("title") in BANNED_INCIDENT_TITLES
    ]
    if offenders:
        sample = [
            {
                "id": o.get("id"),
                "title": o.get("title"),
                "detected_at": o.get("detected_at"),
                "source_ip": o.get("source_ip"),
            }
            for o in offenders[:3]
        ]
        fail(
            "no 'SSH Brute Force Detected' incidents in last 24h",
            f"found {len(offenders)} (showing up to 3): {sample}",
        )
        return False
    ok(
        "no 'SSH Brute Force Detected' incidents in last 24h",
        f"total incidents scanned={len(incidents)}",
    )
    return True


def check_rules_loaded(base_url: str, api_key: str) -> bool:
    passed = True

    # /correlation/rules - confirm http_auth_brute_force is present + enabled.
    r = http(
        "GET",
        "/api/v1/correlation/rules",
        api_key=api_key,
        base_url=base_url,
    )
    if r.status != 200:
        fail(
            "correlation/rules reachable",
            f"status={r.status} err={r.error or ''}",
        )
        passed = False
        rules: list[dict[str, Any]] = []
    else:
        try:
            rules = r.json() or []
        except Exception as e:
            fail("correlation/rules is JSON", f"{type(e).__name__}: {e}")
            passed = False
            rules = []

    rule_ids = {
        r["id"] for r in rules
        if isinstance(r, dict) and isinstance(r.get("id"), str)
    }
    missing = REQUIRED_RULE_IDS - rule_ids
    if missing:
        fail(
            "required rules present",
            f"missing={sorted(missing)} loaded_count={len(rule_ids)}",
        )
        passed = False
    elif rules:
        # Also surface whether the rule is enabled - disabled is still a fail.
        target = next(
            (r for r in rules if r.get("id") == "http_auth_brute_force"),
            None,
        )
        if target and target.get("enabled") is False:
            fail(
                "http_auth_brute_force rule enabled",
                "rule present but enabled=false",
            )
            passed = False
        else:
            ok(
                "http_auth_brute_force rule loaded",
                f"total_rules={len(rule_ids)}",
            )

    # /correlation/stats - sanity check (rules_total > 0).
    s = http(
        "GET",
        "/api/v1/correlation/stats",
        api_key=api_key,
        base_url=base_url,
    )
    if s.status != 200:
        warn(
            "correlation/stats reachable",
            f"status={s.status} err={s.error or ''}",
        )
        return passed
    try:
        stats = s.json() or {}
    except Exception as e:
        warn("correlation/stats is JSON", f"{type(e).__name__}: {e}")
        return passed
    total = int(stats.get("rules_total", 0) or 0)
    enabled = int(stats.get("rules_enabled", 0) or 0)
    if total <= 0:
        fail("correlation rules_total > 0", f"stats={stats}")
        return False
    ok(
        "correlation stats sane",
        f"rules_total={total} rules_enabled={enabled} "
        f"events_processed={stats.get('events_processed')}",
    )
    return passed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    base_url = DEFAULT_BASE_URL
    print()
    print(_c(f"AEGIS v{EXPECTED_VERSION} smoke test", _BOLD))
    print(f"  target : {base_url}")
    print(f"  api key: {'set (' + str(len(API_KEY)) + ' chars)' if API_KEY else _c('UNSET', _YELLOW)}")
    print()

    if not API_KEY:
        warn(
            "AEGIS_API_KEY environment variable",
            "unset - checks 2-4 will likely fail with 401",
        )

    results = {
        "health":        check_health(base_url),
        "synthetic":     check_synthetic_event(base_url, API_KEY),
        "no_ssh_brute":  check_no_ssh_brute_force_incidents(base_url, API_KEY),
        "rules_loaded": check_rules_loaded(base_url, API_KEY),
    }

    print()
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    summary = f"{passed}/{total} checks passed"
    if passed == total:
        print(_c(f"  ALL GREEN - {summary}", _GREEN + _BOLD))
        return 0
    failed_names = [k for k, v in results.items() if not v]
    print(_c(f"  FAILED - {summary} (failed: {', '.join(failed_names)})", _RED + _BOLD))
    return 1


if __name__ == "__main__":
    sys.exit(main())
