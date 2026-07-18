# backend/tests/unit/test_xff_trusted_proxy.py
from app.core.dos_middleware import _client_ip

class _Req:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}

def test_xff_ignored_from_untrusted_peer():
    # Attacker connects directly (public peer) and spoofs XFF=127.0.0.1
    req = _Req(peer="203.0.113.9", xff="127.0.0.1")
    assert _client_ip(req) == "203.0.113.9"  # must NOT trust the spoofed header
