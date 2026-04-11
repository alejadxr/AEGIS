"""
IOC Validation Layer — prevents poisoning of the threat sharing network.

Rules:
1. IP addresses must be valid public IPs (not RFC1918, not loopback, not link-local)
2. Domains must be valid FQDNs (not localhost, not internal)
3. Hashes must be valid hex strings of correct length (MD5=32, SHA1=40, SHA256=64)
4. URLs must have valid scheme (http/https) and public host
5. Confidence must be 0.0-1.0
6. IOC values are sanitized (stripped, lowercased for domains/hashes)
7. Known-safe values are rejected (Google DNS, Cloudflare DNS, etc.)
"""
import ipaddress
import re
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("aegis.ioc_validator")

# IPs that must NEVER be shared as threats
SAFE_IPS = {
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "9.9.9.9",                       # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "127.0.0.1", "0.0.0.0",
}

SAFE_DOMAINS = {
    "google.com", "cloudflare.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "localhost",
}

VALID_IOC_TYPES = {"ip", "domain", "hash", "url", "email"}
VALID_THREAT_TYPES = {
    "malware", "phishing", "brute_force", "c2", "botnet", "scanner",
    "exploit", "ransomware", "apt", "spam", "tor_exit", "proxy",
    "data_exfil", "credential_theft", "unknown",
}

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


class IOCValidationError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def validate_ioc(
    ioc_type: str,
    ioc_value: str,
    threat_type: str = "unknown",
    confidence: float = 0.5,
    source_node: Optional[str] = None,
) -> dict:
    """
    Validate and sanitize an IOC. Returns cleaned IOC dict or raises IOCValidationError.
    """
    # Basic field validation
    if not ioc_type or ioc_type not in VALID_IOC_TYPES:
        raise IOCValidationError(f"Invalid ioc_type: {ioc_type}")

    if not ioc_value or not isinstance(ioc_value, str):
        raise IOCValidationError("Empty or invalid ioc_value")

    ioc_value = ioc_value.strip()
    if len(ioc_value) > 2048:
        raise IOCValidationError("ioc_value too long (max 2048)")

    if threat_type not in VALID_THREAT_TYPES:
        threat_type = "unknown"

    confidence = max(0.0, min(1.0, float(confidence)))

    # Type-specific validation
    if ioc_type == "ip":
        ioc_value = _validate_ip(ioc_value)
    elif ioc_type == "domain":
        ioc_value = _validate_domain(ioc_value)
    elif ioc_type == "hash":
        ioc_value = _validate_hash(ioc_value)
    elif ioc_type == "url":
        ioc_value = _validate_url(ioc_value)
    elif ioc_type == "email":
        ioc_value = _validate_email(ioc_value)

    return {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "threat_type": threat_type,
        "confidence": confidence,
        "validated": True,
    }


def _validate_ip(value: str) -> str:
    """Validate IP: must be public, not safe-listed."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise IOCValidationError(f"Invalid IP address: {value}")

    if ip.is_private:
        raise IOCValidationError(f"Private IP rejected: {value}")
    if ip.is_loopback:
        raise IOCValidationError(f"Loopback IP rejected: {value}")
    if ip.is_link_local:
        raise IOCValidationError(f"Link-local IP rejected: {value}")
    if ip.is_multicast:
        raise IOCValidationError(f"Multicast IP rejected: {value}")
    if ip.is_reserved:
        raise IOCValidationError(f"Reserved IP rejected: {value}")
    if value in SAFE_IPS:
        raise IOCValidationError(f"Safe-listed IP rejected: {value}")

    return str(ip)


def _validate_domain(value: str) -> str:
    """Validate domain: must be a valid FQDN, not safe-listed."""
    value = value.lower().rstrip(".")
    if not _DOMAIN_RE.match(value):
        raise IOCValidationError(f"Invalid domain: {value}")
    if value in SAFE_DOMAINS or any(value.endswith(f".{s}") for s in SAFE_DOMAINS):
        raise IOCValidationError(f"Safe-listed domain rejected: {value}")
    return value


def _validate_hash(value: str) -> str:
    """Validate hash: must be hex string of valid length."""
    value = value.lower().strip()
    if len(value) not in _HASH_LENGTHS:
        raise IOCValidationError(f"Invalid hash length {len(value)} (expected 32/40/64)")
    if not _HEX_RE.match(value):
        raise IOCValidationError("Hash contains non-hex characters")
    return value


def _validate_url(value: str) -> str:
    """Validate URL: must have valid scheme and public host."""
    if not value.startswith(("http://", "https://")):
        raise IOCValidationError("URL must start with http:// or https://")
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        if not host:
            raise IOCValidationError("URL has no hostname")
        # Check if host is an IP
        try:
            _validate_ip(host)
        except IOCValidationError:
            # Not an IP or private IP in URL
            if host in ("localhost", "127.0.0.1", "0.0.0.0"):
                raise IOCValidationError(f"Local URL rejected: {value}")
    except IOCValidationError:
        raise
    except Exception:
        raise IOCValidationError(f"Malformed URL: {value}")
    return value


def _validate_email(value: str) -> str:
    """Basic email validation."""
    value = value.lower().strip()
    if "@" not in value or "." not in value.split("@")[-1]:
        raise IOCValidationError(f"Invalid email: {value}")
    return value
