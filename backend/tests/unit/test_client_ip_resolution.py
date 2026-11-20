"""The client IP must not be writable by the client (audit C2/A3/M16/M20)."""
from app.core.client_ip import resolve_client_ip, rate_limit_key
from app.core.dos_middleware import _client_ip

LOCAL = "127.0.0.1"
ATTACKER = "203.0.113.50"
VICTIM = "198.51.100.7"


def test_untrusted_peer_ignores_every_forwarding_header():
    headers = {"x-forwarded-for": VICTIM, "cf-connecting-ip": VICTIM}
    assert resolve_client_ip(ATTACKER, headers) == ATTACKER


def test_spoofed_first_xff_value_is_not_used_behind_the_tunnel():
    # Cloudflare APPENDS the real address to whatever the client sent.
    headers = {"x-forwarded-for": f"10.0.0.1, {ATTACKER}"}
    assert resolve_client_ip(LOCAL, headers) == ATTACKER


def test_cf_connecting_ip_wins_over_xff():
    headers = {"x-forwarded-for": f"{VICTIM}, {ATTACKER}", "cf-connecting-ip": ATTACKER}
    assert resolve_client_ip(LOCAL, headers) == ATTACKER


def test_attacker_cannot_frame_a_victim_through_xff():
    headers = {"x-forwarded-for": f"{VICTIM}, {ATTACKER}"}
    assert resolve_client_ip(LOCAL, headers) != VICTIM


def test_trusted_hops_on_the_right_are_skipped():
    headers = {"x-forwarded-for": f"{ATTACKER}, 100.64.0.9, 127.0.0.1"}
    assert resolve_client_ip(LOCAL, headers) == ATTACKER


def test_single_xff_from_trusted_proxy_still_resolves():
    assert resolve_client_ip(LOCAL, {"x-forwarded-for": ATTACKER}) == ATTACKER


def test_garbage_header_is_never_returned_as_an_ip():
    assert resolve_client_ip(LOCAL, {"x-forwarded-for": "not-an-ip"}) == LOCAL
    assert resolve_client_ip(LOCAL, {"cf-connecting-ip": "evil\n[DETECT] x"}) == LOCAL
    # A malformed hop poisons everything to its left.
    assert resolve_client_ip(LOCAL, {"x-forwarded-for": f"{VICTIM}, junk"}) == LOCAL


def test_no_headers_returns_peer():
    assert resolve_client_ip(LOCAL, {}) == LOCAL
    assert resolve_client_ip(None, {}) == "unknown"


def test_ipv4_mapped_localhost_is_a_trusted_proxy():
    assert resolve_client_ip("::ffff:127.0.0.1", {"cf-connecting-ip": ATTACKER}) == ATTACKER


class _Req:
    def __init__(self, peer, headers):
        self.client = type("C", (), {"host": peer})()
        self.headers = headers


def test_middleware_helper_and_rate_limit_key_share_the_resolver():
    req = _Req(LOCAL, {"x-forwarded-for": f"10.0.0.1, {ATTACKER}"})
    assert _client_ip(req) == ATTACKER
    # Behind the tunnel the limiter key must be the client, not localhost:
    # otherwise ten bad logins from anyone lock the operator out.
    assert rate_limit_key(req) == ATTACKER
