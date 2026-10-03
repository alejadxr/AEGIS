"""Shared-cloud crawler ranges are conditionally safe, not a blind spot."""
import pytest

from app.core import attack_detector as ad

GCP_IP = "34.100.50.20"       # inside 34.64.0.0/10 (arbitrary customer address)
AZURE_IP = "13.66.10.10"      # inside 13.66.0.0/17
PRECISE_GOOGLEBOT = "66.249.66.1"  # inside 66.249.64.0/19
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
CURL_UA = "curl/8.4.0"


@pytest.fixture(autouse=True)
def _clean_cache():
    ad._rdns_cache.clear()
    ad._rdns_inflight.clear()
    yield
    ad._rdns_cache.clear()
    ad._rdns_inflight.clear()


def test_ranges_are_split():
    assert ad._is_shared_cloud_ip(GCP_IP) and ad._is_shared_cloud_ip(AZURE_IP)
    assert not ad._is_crawler_ip(GCP_IP) and not ad._is_crawler_ip(AZURE_IP)
    assert ad._is_crawler_ip(PRECISE_GOOGLEBOT)


@pytest.mark.parametrize("ip", [GCP_IP, AZURE_IP, "35.190.1.1"])
def test_gcp_azure_not_safe_without_ua_or_with_plain_ua(ip):
    assert not ad._is_safe_ip(ip)
    assert not ad._is_safe_ip(ip, CURL_UA)


def test_precise_googlebot_safe_regardless_of_ua():
    assert ad._is_safe_ip(PRECISE_GOOGLEBOT)
    assert ad._is_safe_ip(PRECISE_GOOGLEBOT, CURL_UA)


def test_verified_crawler_ua_on_gcp_is_safe():
    ad._rdns_cache[GCP_IP] = (True, 1e18)
    assert ad._is_safe_ip(GCP_IP, GOOGLEBOT_UA)
    # UA-less callers (EDR, honeypots, chain detector) still treat it as unsafe
    assert not ad._is_safe_ip(GCP_IP)
    assert not ad._is_safe_ip(GCP_IP, CURL_UA)


def test_spoofed_googlebot_ua_rejected_rdns_not_safe():
    ad._rdns_cache[GCP_IP] = (False, 1e18)
    assert not ad._is_safe_ip(GCP_IP, GOOGLEBOT_UA)


async def test_unverified_triggers_background_check_and_is_not_safe(monkeypatch):
    calls = []
    monkeypatch.setattr(ad, "_fcrdns_verify_blocking", lambda ip: calls.append(ip) or True)
    assert not ad._is_safe_ip(GCP_IP, GOOGLEBOT_UA)  # miss: not safe yet
    assert GCP_IP in ad._rdns_inflight
    import asyncio
    for _ in range(50):
        if GCP_IP in ad._rdns_cache:
            break
        await asyncio.sleep(0.01)
    assert calls == [GCP_IP]
    assert ad._is_safe_ip(GCP_IP, GOOGLEBOT_UA)  # now verified


def test_fcrdns_requires_allowed_suffix_and_forward_match(monkeypatch):
    import socket
    def fake(host, fwd):
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (host, [], [ip]))
        monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: [(2, 1, 6, "", (fwd, 0))])
    fake("crawl-1.googlebot.com", GCP_IP)
    assert ad._fcrdns_verify_blocking(GCP_IP)
    fake("crawl-1.googlebot.com", "203.0.113.9")        # forward mismatch
    assert not ad._fcrdns_verify_blocking(GCP_IP)
    fake("34-100-50-20.bc.googleusercontent.com", GCP_IP)  # tenant PTR
    assert not ad._fcrdns_verify_blocking(GCP_IP)
    fake("msnbot-1.search.msn.com", AZURE_IP)
    assert ad._fcrdns_verify_blocking(AZURE_IP)


async def _detected(monkeypatch, ip, ua, path="/x/../../etc/passwd"):
    """Run the middleware; return True if the request went through detection."""
    from starlette.requests import Request
    from starlette.responses import Response
    hits = []
    monkeypatch.setattr(ad, "_record_attack", lambda i, t, *a, **k: hits.append(i) or False)
    scope = {"type": "http", "method": "GET", "path": path, "query_string": b"",
             "headers": [(b"user-agent", ua.encode())],
             "client": (ip, 1234), "server": ("t", 80), "scheme": "http"}

    async def nxt(_r):
        return Response("ok")
    await ad.AttackDetectorMiddleware(app=None).dispatch(Request(scope), nxt)
    return bool(hits)


async def test_middleware_gcp_attack_non_crawler_is_detected(monkeypatch):
    assert await _detected(monkeypatch, GCP_IP, CURL_UA)


async def test_middleware_spoofed_googlebot_on_gcp_still_inspected(monkeypatch):
    ad._rdns_cache[GCP_IP] = (False, 1e18)
    assert await _detected(monkeypatch, GCP_IP, GOOGLEBOT_UA)


async def test_middleware_verified_googlebot_on_gcp_passes(monkeypatch):
    ad._rdns_cache[GCP_IP] = (True, 1e18)
    assert not await _detected(monkeypatch, GCP_IP, GOOGLEBOT_UA)


async def test_middleware_precise_range_passes(monkeypatch):
    assert not await _detected(monkeypatch, PRECISE_GOOGLEBOT, CURL_UA)
