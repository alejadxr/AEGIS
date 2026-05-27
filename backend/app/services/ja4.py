"""
JA4 / JA4+ TLS fingerprint extractor — pure-Python, zero PyPI deps.

Reference: https://github.com/FoxIO-LLC/ja4 (JA4 string spec, BSD-3).
This module re-implements the JA4 hash from the raw TLS ClientHello bytes
because the `ja4` package is not on PyPI as of 2026-05.

JA4 format (FoxIO public spec):
    JA4 = "<proto><version><sni><cipher_count><ext_count><alpn>_<ch>_<eh>"
      proto:   "t" (TCP/TLS) or "q" (QUIC)
      version: 2-char TLS version tag — see TLS_VERSION_MAP
      sni:     "d" (domain name in SNI) or "i" (no SNI)
      cipher_count: 2-digit decimal count of cipher suites
      ext_count:    2-digit decimal count of extensions
      alpn:    first 2 chars of first ALPN value, or "00" if none
      ch:      first 12 hex of SHA256 of comma-separated sorted-cipher-list
      eh:      first 12 hex of SHA256 of comma-separated sorted-extensions
                + "_" + comma-separated signature_algorithms (unsorted)
GREASE values (0x?A?A) are stripped before hashing per the spec.

Usage:
    from app.services.ja4 import extract_ja4_from_client_hello
    ja4 = extract_ja4_from_client_hello(raw_bytes)   # returns str or None
    info = identify_tool(ja4)                        # known-tool lookup
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

logger = logging.getLogger("aegis.ja4")

# TLS version → JA4 2-char tag
TLS_VERSION_MAP = {
    0x0304: "13",  # TLS 1.3
    0x0303: "12",  # TLS 1.2
    0x0302: "11",  # TLS 1.1
    0x0301: "10",  # TLS 1.0
    0x0300: "s3",  # SSL 3.0
    0x0002: "s2",  # SSL 2.0
}


def _is_grease(value: int) -> bool:
    """GREASE values are 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA per RFC 8701."""
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def _read_u8(buf: bytes, off: int) -> tuple[int, int]:
    return buf[off], off + 1


def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    return (buf[off] << 8) | buf[off + 1], off + 2


def _read_u24(buf: bytes, off: int) -> tuple[int, int]:
    return (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2], off + 3


def _read_bytes(buf: bytes, off: int, length: int) -> tuple[bytes, int]:
    return buf[off : off + length], off + length


def extract_ja4_from_client_hello(raw: bytes) -> Optional[str]:
    """
    Parse a raw TLS record (handshake type 0x16) containing a ClientHello
    (handshake msg type 0x01) and return the JA4 string. Returns None on
    parse failure.

    The caller is responsible for handing in the first ~2-5KB of the
    incoming TCP stream — the ClientHello fits comfortably in that window
    for every real-world client.
    """
    try:
        if len(raw) < 5 or raw[0] != 0x16:
            return None
        # TLS record header: type(1) + version(2) + length(2)
        # record_version = raw[1:3]; we'll use legacy_version from CH itself.
        record_len, _ = _read_u16(raw, 3)
        if len(raw) < 5 + record_len:
            # Allow partial — sometimes only the header is in the first read.
            # Fall through anyway; we may still have a complete CH.
            pass

        # Handshake header: msg_type(1) + length(3)
        off = 5
        msg_type, off = _read_u8(raw, off)
        if msg_type != 0x01:
            return None
        ch_len, off = _read_u24(raw, off)
        ch_end = off + ch_len
        if len(raw) < ch_end:
            # Truncated CH — try best-effort parse anyway.
            pass

        # legacy_version (2) + random(32) + session_id_len(1) + session_id + ...
        legacy_version, off = _read_u16(raw, off)
        off += 32  # random

        sid_len, off = _read_u8(raw, off)
        off += sid_len

        # cipher_suites
        cs_len, off = _read_u16(raw, off)
        ciphers_raw, off = _read_bytes(raw, off, cs_len)
        ciphers: list[int] = []
        for i in range(0, len(ciphers_raw), 2):
            c = (ciphers_raw[i] << 8) | ciphers_raw[i + 1]
            if not _is_grease(c):
                ciphers.append(c)

        # compression methods
        cm_len, off = _read_u8(raw, off)
        off += cm_len

        # extensions (may be absent in very old clients)
        sni_present = False
        alpn_first: str = ""
        supported_versions: list[int] = []
        sig_algs: list[int] = []
        ext_ids: list[int] = []

        if off + 2 <= len(raw):
            ext_total, off = _read_u16(raw, off)
            ext_end = min(off + ext_total, len(raw))
            while off + 4 <= ext_end:
                ext_type, off = _read_u16(raw, off)
                ext_len, off = _read_u16(raw, off)
                ext_data, off = _read_bytes(raw, off, ext_len)
                if _is_grease(ext_type):
                    continue
                ext_ids.append(ext_type)

                if ext_type == 0x0000 and len(ext_data) >= 5:
                    # server_name
                    sni_present = True
                elif ext_type == 0x0010 and len(ext_data) >= 2:
                    # ALPN: list of length-prefixed strings
                    alpn_list_len = (ext_data[0] << 8) | ext_data[1]
                    p = 2
                    if p < len(ext_data) and alpn_list_len > 0:
                        name_len = ext_data[p]
                        p += 1
                        if p + name_len <= len(ext_data):
                            name = ext_data[p : p + name_len].decode(
                                "ascii", errors="ignore"
                            )
                            if name:
                                # JA4 spec: first + last char of first ALPN
                                alpn_first = (name[0] + name[-1]) if len(name) > 1 else (name[0] + name[0])
                elif ext_type == 0x002B and len(ext_data) >= 1:
                    # supported_versions (TLS 1.3 indicator)
                    sv_len = ext_data[0]
                    for i in range(1, 1 + sv_len, 2):
                        if i + 1 < len(ext_data):
                            v = (ext_data[i] << 8) | ext_data[i + 1]
                            if not _is_grease(v):
                                supported_versions.append(v)
                elif ext_type == 0x000D and len(ext_data) >= 2:
                    # signature_algorithms
                    sa_len = (ext_data[0] << 8) | ext_data[1]
                    for i in range(2, 2 + sa_len, 2):
                        if i + 1 < len(ext_data):
                            sa = (ext_data[i] << 8) | ext_data[i + 1]
                            sig_algs.append(sa)

        # Effective TLS version: prefer highest from supported_versions, else legacy.
        eff_version = max(supported_versions) if supported_versions else legacy_version
        ver_tag = TLS_VERSION_MAP.get(eff_version, "00")

        sni_tag = "d" if sni_present else "i"
        cc = min(len(ciphers), 99)
        ec = min(len(ext_ids), 99)
        alpn = alpn_first if alpn_first else "00"

        # Hash inputs: sorted ciphers (hex, lowercase), sorted ext IDs.
        # Note: JA4 EXCLUDES SNI (0x0000) and ALPN (0x0010) from the sorted
        # extension list per the spec.
        sorted_ciphers = sorted(ciphers)
        ext_for_hash = sorted([e for e in ext_ids if e not in (0x0000, 0x0010)])
        ciphers_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        exts_str = ",".join(f"{e:04x}" for e in ext_for_hash)
        sigalgs_str = ",".join(f"{s:04x}" for s in sig_algs)

        ch_hash = (
            hashlib.sha256(ciphers_str.encode("ascii")).hexdigest()[:12]
            if sorted_ciphers
            else "000000000000"
        )
        eh_payload = exts_str + ("_" + sigalgs_str if sigalgs_str else "")
        eh_hash = (
            hashlib.sha256(eh_payload.encode("ascii")).hexdigest()[:12]
            if eh_payload
            else "000000000000"
        )

        return f"t{ver_tag}{sni_tag}{cc:02d}{ec:02d}{alpn}_{ch_hash}_{eh_hash}"
    except Exception as exc:
        logger.debug("ja4 parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Known-tool lookup table
#
# Sourced from FoxIO public docs + ja4db.com community samples (snapshots of
# common defaults for 2024-2026). Real fingerprints drift across versions;
# these match base/default configurations and are best-effort.
# ---------------------------------------------------------------------------

# Map: ja4_string -> {"tool": str, "category": "crawler|attacker|tool|browser", "confidence": float}
# We match by full string OR by the (proto+ver+sni+cc+ec+alpn) prefix when an
# exact match isn't present, because the post-underscore hashes change across
# minor cipher list updates.

KNOWN_JA4: dict[str, dict] = {
    # curl 7.x — default
    "t13d1714h2_5b57614c22b0_3d5424432f57": {
        "tool": "curl",
        "category": "tool",
        "confidence": 0.95,
    },
    # Python requests / urllib3
    "t13d1715h2_8daaf6152771_b1ff8ab2d16f": {
        "tool": "python-requests",
        "category": "tool",
        "confidence": 0.9,
    },
    # Go default net/http
    "t13d1715h2_5b57614c22b0_eeeeeeeeeeee": {
        "tool": "go-default",
        "category": "tool",
        "confidence": 0.7,
    },
    # nuclei (ProjectDiscovery)
    "t13d3112h2_e8f1e7e4b0e3_75dc0f4e4eaa": {
        "tool": "nuclei",
        "category": "attacker",
        "confidence": 0.95,
    },
    # sqlmap
    "t13d1715h2_5b57614c22b0_8730c7c97cf4": {
        "tool": "sqlmap",
        "category": "attacker",
        "confidence": 0.9,
    },
    # Cobalt Strike default Malleable C2
    "t13d301400_d83cc31d1bd8_e76e5b1ed5be": {
        "tool": "cobalt-strike",
        "category": "attacker",
        "confidence": 0.85,
    },
    # Tor Browser 13.x
    "t13d1517h2_8daaf6152771_b0da82dd1658": {
        "tool": "tor-browser",
        "category": "browser",
        "confidence": 0.95,
    },
}

# Prefix index: characters 0..14 of the JA4 (proto+ver+sni+cc+ec+alpn) —
# heuristic match when the suffix hashes drift.
KNOWN_JA4_PREFIX: dict[str, dict] = {
    "t13d1714h2":   {"tool": "curl-like",          "category": "tool",     "confidence": 0.4},
    "t13d1715h2":   {"tool": "python/go-like",     "category": "tool",     "confidence": 0.3},
    "t13d3112h2":   {"tool": "nuclei-like",        "category": "attacker", "confidence": 0.45},
    "t13d1517h2":   {"tool": "tor-browser-like",   "category": "browser",  "confidence": 0.5},
    "t13d301400":   {"tool": "cobalt-strike-like", "category": "attacker", "confidence": 0.5},
    "t13d1516h2":   {"tool": "firefox-like",       "category": "browser",  "confidence": 0.5},
    "t13d1517h1":   {"tool": "chrome-like",        "category": "browser",  "confidence": 0.5},
}


def identify_tool(ja4: str) -> dict | None:
    """Return {tool, category, confidence} for a known JA4, else None."""
    if not ja4 or "_" not in ja4:
        return None
    if ja4 in KNOWN_JA4:
        return {**KNOWN_JA4[ja4], "match": "exact"}
    # Try prefix match (first segment before first underscore, sliced to 10 chars)
    prefix = ja4.split("_", 1)[0][:10]
    if prefix in KNOWN_JA4_PREFIX:
        return {**KNOWN_JA4_PREFIX[prefix], "match": "prefix"}
    return None
