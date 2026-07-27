"""Regression tests for the `[AEGIS] {json}` structured access-log envelope.

Front-line apps that sit behind Cloudflare (e.g. `sable`) do NOT log in the
PM2/uvicorn common-log format the historic `_ACCESS_LOG_RE` understands. They
emit one JSON object per request, prefixed with an ``[AEGIS]`` marker, carrying
the real client IP resolved from ``CF-Connecting-IP``:

    2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111",
    "method":"GET","path":"/x?stream.url=file%3A%2F%2F%2Fetc%2Fpasswd",
    "status":200,"ua":"curl","cf_ray":"z-AMS"}

Before the parser learned this shape, `normalize()` returned ``None`` for every
such line (access_match was None → drop guard), so AEGIS was 100% blind to
these apps regardless of attack volume. These tests lock in the fix.
"""

from urllib.parse import quote

from app.services import event_normalizer as en

_SABLE = "sable"


def _aegis_line(path: str, ip: str = "45.148.10.111", method: str = "GET",
                status: int = 200, ua: str = "curl") -> str:
    return (
        f'2026-07-24 11:05:12: [AEGIS] {{"ts":"2026-07-24T15:05:12.176Z",'
        f'"app":"sable","src_ip":"{ip}","method":"{method}",'
        f'"path":"{path}","status":{status},"ua":"{ua}","country":"NL",'
        f'"host":"sable.somoswilab.com","fwd_chain":"{ip}","cf_ray":"z-AMS"}}'
    )


def test_aegis_json_is_not_dropped():
    """A structured envelope must produce an event, never a silent drop."""
    ev = en.normalize(_aegis_line("/"), source=_SABLE)
    assert ev is not None, "sable [AEGIS] JSON line was dropped"
    assert ev["source_ip"] == "45.148.10.111"
    assert ev["request_path"] == "/"
    assert ev["request_method"] == "GET"
    assert ev["response_status"] == 200


def test_aegis_json_url_encoded_traversal_is_classified():
    """A percent-encoded LFI payload must be caught via the decoded path."""
    path = "/solr/x?stream.url=" + quote("file:///etc/passwd", safe="")
    ev = en.normalize(_aegis_line(path), source=_SABLE)
    assert ev is not None
    assert ev["threat_type"] == "path_traversal"
    assert ev["source_ip"] == "45.148.10.111"


def test_aegis_json_url_encoded_sqli_is_classified():
    path = "/?q=" + quote("union select 1,2,3--", safe="")
    ev = en.normalize(_aegis_line(path), source=_SABLE)
    assert ev is not None
    assert ev["threat_type"] == "sql_injection"


def test_aegis_json_url_encoded_xss_is_classified():
    path = "/?skw=" + quote('" onfocus="alert(document.domain)" autofocus="', safe="")
    ev = en.normalize(_aegis_line(path), source=_SABLE)
    assert ev is not None
    assert ev["threat_type"] == "xss"


def test_aegis_json_benign_request_still_counts():
    """Benign 200s become generic http_request so rate/enum rules can count."""
    ev = en.normalize(_aegis_line("/about"), source=_SABLE)
    assert ev is not None
    assert ev["event_type"] == "http_request"


def test_ipv6_mapped_loopback_envelope_parses():
    """Internal worker calls (::ffff:127.0.0.1) still yield a parseable event.

    The IPv4-only _IP_RE fallback cannot see this IP; the envelope must."""
    line = _aegis_line("/api/aaas/worker/drain", ip="::ffff:127.0.0.1",
                       method="POST", ua="node")
    ev = en.normalize(line, source=_SABLE)
    assert ev is not None
    assert ev["source_ip"] == "::ffff:127.0.0.1"


def test_common_log_regression_still_parses():
    """The historic PM2/uvicorn common-log path must be unaffected."""
    line = 'INFO:     45.148.10.111:51000 - "GET /?q=union%20select HTTP/1.1" 200'
    ev = en.normalize(line, source="cayde6-api")
    assert ev is not None
    assert ev["source_ip"] == "45.148.10.111"


def test_non_aegis_noise_still_dropped():
    """A non-envelope, non-access-log line must still drop (no over-matching)."""
    ev = en.normalize("2026-07-24 11:05:12: some random log message here",
                      source=_SABLE)
    assert ev is None
