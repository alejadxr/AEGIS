"""
TLS honeypot listener — captures JA4 fingerprint from incoming ClientHello.

Architecture:
  1. asyncio.start_server on port 8889 (configurable via AEGIS_TLS_HP_PORT).
  2. Peek the first up-to-4KB raw bytes from the client (TLS record + CH).
  3. Pure-Python JA4 extraction (no ssl handshake yet).
  4. Try to complete the TLS handshake using a self-signed cert, then serve
     a plain HTML decoy page so the attacker doesn't notice they were just
     fingerprinted. If TLS handshake fails (likely — many scanners send
     intentionally-bad CHs), close cleanly.
  5. Persist {ip, ja4, sni, known_tool} into the tls_fingerprints table.

Self-signed cert path: ~/.aegis/tls_honeypot.crt + .key. Auto-generated on
first start via openssl (only if the binary is on PATH). If openssl is
missing OR cert can't be created, the listener still runs but skips the
TLS handshake (closes after JA4 capture).

Disabled by default. Set AEGIS_TLS_HP_ENABLE=1 to start it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import subprocess
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from app.database import async_session
from app.models.tls_fingerprint import TlsFingerprint
from app.services.ja4 import extract_ja4_from_client_hello, identify_tool

logger = logging.getLogger("aegis.phantom.tls_honeypot")

_CERT_DIR = Path(os.environ.get("AEGIS_TLS_HP_CERT_DIR", str(Path.home() / ".aegis")))
_CERT_FILE = _CERT_DIR / "tls_honeypot.crt"
_KEY_FILE = _CERT_DIR / "tls_honeypot.key"

_DECOY_HTML = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Length: 117\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<!doctype html><html><head><title>Welcome to nginx!</title></head>"
    b"<body><h1>Welcome to nginx!</h1></body></html>"
)


def _ensure_cert() -> bool:
    """Generate a self-signed cert if missing. Returns True if cert is usable."""
    if _CERT_FILE.exists() and _KEY_FILE.exists():
        return True
    try:
        _CERT_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", str(_KEY_FILE), "-out", str(_CERT_FILE),
                "-days", "365",
                "-subj", "/CN=mail.example.com/O=Example/C=US",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        logger.info("tls_honeypot: generated self-signed cert at %s", _CERT_FILE)
        return True
    except Exception as exc:
        logger.warning("tls_honeypot: failed to generate cert: %s", exc)
        return False


async def _persist(ip: str, ja4: str, sni: str | None, source: str) -> None:
    """Upsert one fingerprint observation."""
    try:
        tool_info = identify_tool(ja4)
        async with async_session() as s:
            row = (
                await s.execute(
                    select(TlsFingerprint)
                    .where(TlsFingerprint.ip == ip)
                    .where(TlsFingerprint.ja4 == ja4)
                )
            ).scalar_one_or_none()
            if row is None:
                row = TlsFingerprint(
                    ip=ip,
                    ja4=ja4,
                    sni=(sni or "")[:255] if sni else None,
                    ja4_known_tool=(tool_info or {}).get("tool"),
                    ja4_category=(tool_info or {}).get("category"),
                    ja4_confidence=(tool_info or {}).get("confidence"),
                    honeypot_source=source,
                    count=1,
                )
                s.add(row)
            else:
                row.count = (row.count or 0) + 1
                row.last_seen = datetime.utcnow()
                if not row.sni and sni:
                    row.sni = sni[:255]
            await s.commit()
    except Exception as exc:
        logger.warning("tls_honeypot: persist error: %s", exc)


async def _extract_sni(raw: bytes) -> str | None:
    """Best-effort SNI pluck — separate from JA4 because UI wants it raw."""
    try:
        if len(raw) < 43 or raw[0] != 0x16 or raw[5] != 0x01:
            return None
        # Skip TLS record(5) + handshake header(4) + version(2) + random(32) = 43
        off = 43
        sid_len = raw[off]; off += 1 + sid_len
        cs_len = (raw[off] << 8) | raw[off + 1]; off += 2 + cs_len
        cm_len = raw[off]; off += 1 + cm_len
        if off + 2 > len(raw):
            return None
        ext_total = (raw[off] << 8) | raw[off + 1]
        off += 2
        ext_end = min(off + ext_total, len(raw))
        while off + 4 <= ext_end:
            t = (raw[off] << 8) | raw[off + 1]
            l = (raw[off + 2] << 8) | raw[off + 3]
            off += 4
            if t == 0x0000 and l >= 5 and off + l <= len(raw):
                # server_name extension: list(2) + name_type(1) + name_len(2) + name
                name_type = raw[off + 2]
                if name_type == 0:
                    nlen = (raw[off + 3] << 8) | raw[off + 4]
                    end = off + 5 + nlen
                    if end <= len(raw):
                        return raw[off + 5 : end].decode("ascii", errors="ignore")
                return None
            off += l
        return None
    except Exception:
        return None


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "0.0.0.0"
    raw = b""
    try:
        # Read first chunk(s) — JA4 ClientHellos fit in <4KB in practice.
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        if raw:
            ja4 = extract_ja4_from_client_hello(raw)
            sni = await _extract_sni(raw) if ja4 else None
            if ja4:
                logger.info("tls_honeypot: %s ja4=%s sni=%s", ip, ja4, sni)
                await _persist(ip, ja4, sni, "mac-tls-8889")
            else:
                logger.debug("tls_honeypot: %s no JA4 (raw[:8]=%s)", ip, raw[:8].hex())

        # Best-effort: don't try a real TLS handshake from raw bytes (we already
        # consumed them). Just close. A future enhancement could splice into
        # an SSLObject — for now JA4 capture is the value, not the decoy.
        with __import__("contextlib").suppress(Exception):
            writer.write(b"")
            await writer.drain()
    finally:
        with __import__("contextlib").suppress(Exception):
            writer.close()
            await writer.wait_closed()


_server: asyncio.base_events.Server | None = None


async def start_tls_honeypot() -> None:
    """Bind the TLS honeypot listener.

    Disabled only if AEGIS_TLS_HP_ENABLE is explicitly set to "0". Default is
    enabled so JA4 capture works out of the box on fresh installs.
    """
    global _server
    if os.environ.get("AEGIS_TLS_HP_ENABLE", "1").strip() == "0":
        logger.info("tls_honeypot: disabled (AEGIS_TLS_HP_ENABLE=0)")
        return
    port = int(os.environ.get("AEGIS_TLS_HP_PORT", "8889"))
    bind = os.environ.get("AEGIS_TLS_HP_BIND", "0.0.0.0")
    # Cert generation is optional — we don't currently complete the handshake,
    # but generate it anyway so future-versions can splice TLS.
    _ensure_cert()
    try:
        _server = await asyncio.start_server(_handle, host=bind, port=port)
        logger.info("tls_honeypot: listening on %s:%d", bind, port)
    except Exception as exc:
        logger.warning("tls_honeypot: failed to bind %s:%d: %s", bind, port, exc)


async def stop_tls_honeypot() -> None:
    global _server
    if _server is not None:
        _server.close()
        with __import__("contextlib").suppress(Exception):
            await _server.wait_closed()
        _server = None
        logger.info("tls_honeypot: stopped")
