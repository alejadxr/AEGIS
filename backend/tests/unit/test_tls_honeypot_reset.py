"""A peer that resets before sending anything must not escape the handler.

nmap's quick scan does exactly this against the TLS honeypot, and each one
logged "Unhandled exception in client_connected_cb" with a ConnectionResetError
whose traceback pointed at an already-guarded wait_closed() line.
"""
import asyncio

from app.modules.phantom import tls_honeypot


class _ResetReader:
    async def read(self, n):
        raise ConnectionResetError(54, "Connection reset by peer")


class _Writer:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, key):
        return ("198.51.100.30", 51000) if key == "peername" else None

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        raise ConnectionResetError(54, "Connection reset by peer")


async def test_reset_before_client_hello_is_handled():
    writer = _Writer()
    await tls_honeypot._handle(_ResetReader(), writer)  # must not raise
    assert writer.closed
