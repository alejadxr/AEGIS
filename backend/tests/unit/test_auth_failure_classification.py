"""A credential attack must be detected; an expired session must not look like one.

Both halves were broken, in opposite directions:

* Replaying a week of real traffic, the SID office's own client -- 9,000+
  successful requests, 233 GET /api/notifications/* -> 401 from an expired
  session still polling -- opened brute-force incidents that would have
  autonomously blocked the office. Web-app 401s fell through to the generic
  auth_failure fallback, which exists for FTP/SMTP/RDP.
* Meanwhile http_auth_brute_force excluded every path containing "/login"
  (path_excludes is a substring match) and all of "/api/v1/auth/", so 40
  POST /api/v1/auth/login -> 401 fired nothing. The brute-force rule could not
  see a brute force.

The dividing line is the one _is_session_check already stated for AEGIS's own
API: credential attempts are POSTs. A GET/HEAD/OPTIONS 401 carries at most a
stale token.
"""
import json

import pytest

from app.services import correlation_engine as ce
from app.services.event_normalizer import normalize


def _line(source: str, ip: str, method: str, path: str) -> str:
    if source == "cayde6-api":
        return f'INFO:     {ip}:5000 - "{method} {path} HTTP/1.1" 401 Unauthorized'
    return "[AEGIS] " + json.dumps(
        {"app": source, "src_ip": ip, "method": method, "path": path, "status": 401, "ua": "t"}
    )


async def _burst(monkeypatch, source, ip, method, path, n=40):
    engine = ce.CorrelationEngine()
    fired: set[str] = set()
    for i in range(n):
        monkeypatch.setattr(ce, "_now_ts", lambda t=1_800_000_000 + i: t)
        event = normalize(_line(source, ip, method, path), source=source)
        for rule in await engine.evaluate(event):
            fired.add(rule["id"])
    return fired


BRUTE_FORCE_RULES = {"http_auth_brute_force", "generic_credential_attack", "brute_force_ssh"}


@pytest.mark.parametrize(
    "source,ip,path",
    [
        ("sid-backend", "198.51.100.20", "/api/notifications/unread-count"),
        ("cayde6-api", "198.51.100.21", "/api/v1/response/incidents"),
        ("cayde6-api", "198.51.100.22", "/api/v1/auth/me"),
    ],
)
async def test_expired_session_polling_is_not_a_brute_force(monkeypatch, source, ip, path):
    fired = await _burst(monkeypatch, source, ip, "GET", path)
    assert not (fired & BRUTE_FORCE_RULES), f"expired session raised {fired & BRUTE_FORCE_RULES}"


@pytest.mark.parametrize(
    "source,path",
    [
        ("sid-backend", "/api/auth/login"),
        ("cayde6-api", "/api/v1/auth/login"),
        ("sable", "/wp-login.php"),
    ],
)
async def test_credential_brute_force_on_a_login_endpoint_is_detected(monkeypatch, source, path):
    fired = await _burst(monkeypatch, source, "45.13.12.9", "POST", path)
    assert "http_auth_brute_force" in fired, f"40 POST 401 to {path} fired only {fired}"


def test_classification_follows_the_method():
    get = normalize(_line("sid-backend", "45.13.12.9", "GET", "/api/x"), source="sid-backend")
    post = normalize(_line("sid-backend", "45.13.12.9", "POST", "/api/x"), source="sid-backend")
    assert get["event_type"] == "http_request"
    assert post["event_type"] == "http_auth_failure"
