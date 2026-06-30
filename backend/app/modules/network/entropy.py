"""
Shannon entropy calculator and DGA (Domain Generation Algorithm) domain detector.

Used by the DNS monitor to identify algorithmically-generated domains
commonly associated with malware C2 communication.
"""

import math
import re
from collections import Counter

# Common legitimate words/brands that appear in domains.
# Domains containing these are much less likely to be DGA.
COMMON_WORDS = frozenset({
    "google", "facebook", "amazon", "microsoft", "apple", "netflix",
    "twitter", "linkedin", "github", "stackoverflow", "cloudflare",
    "akamai", "fastly", "wordpress", "shopify", "stripe", "paypal",
    "youtube", "instagram", "whatsapp", "telegram", "discord",
    "reddit", "wikipedia", "mozilla", "firefox", "chrome", "safari",
    "outlook", "office", "windows", "ubuntu", "debian", "fedora",
    "docker", "kubernetes", "nginx", "apache", "jenkins", "gitlab",
    "bitbucket", "atlassian", "jira", "confluence", "slack", "zoom",
    "dropbox", "onedrive", "icloud", "azure", "amazonaws", "heroku",
    "digitalocean", "linode", "vultr", "ovh", "godaddy", "namecheap",
    "cloudfront", "elasticbeanstalk", "s3", "ec2",
    "mail", "smtp", "imap", "pop3", "webmail", "email",
    "login", "auth", "account", "secure", "admin", "portal",
    "update", "download", "support", "help", "docs", "blog",
    "static", "cdn", "assets", "images", "media", "fonts",
    "api", "gateway", "proxy", "cache", "status", "monitor",
})

# Legitimate TLDs that are less commonly abused
COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil",
    "co", "io", "dev", "app", "me", "us", "uk", "de", "fr", "jp",
})

# TLDs frequently used in malicious campaigns
SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz",
    "club", "work", "info", "online", "site", "wang", "win",
    "bid", "stream", "download", "racing", "review", "date",
    "accountant", "science", "party", "cricket", "faith",
})


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns a float >= 0. Higher values indicate more randomness.
    Typical English text: ~3.5-4.5
    Random hex strings: ~3.7-4.0
    Truly random base62: ~5.0+
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _extract_registerable_domain(domain: str) -> str:
    """Extract the registerable part of a domain (strip TLD and subdomain dots)."""
    domain = domain.rstrip(".")
    parts = domain.split(".")
    if len(parts) >= 2:
        # Return everything except the TLD
        return ".".join(parts[:-1])
    return domain


def _has_common_word(domain_lower: str) -> bool:
    """Check if the domain contains any well-known brand or common word."""
    for word in COMMON_WORDS:
        if word in domain_lower:
            return True
    return False


def _get_tld(domain: str) -> str:
    """Extract the TLD from a domain."""
    domain = domain.rstrip(".")
    parts = domain.split(".")
    if parts:
        return parts[-1].lower()
    return ""


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total alpha characters.
    DGA domains tend to have unusual consonant clustering."""
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    vowels = set("aeiou")
    consonants = sum(1 for c in alpha if c not in vowels)
    return consonants / len(alpha)


def _digit_ratio(s: str) -> float:
    """Ratio of digits to total characters. DGA domains often mix digits."""
    if not s:
        return 0.0
    digits = sum(1 for c in s if c.isdigit())
    return digits / len(s)


def is_dga_domain(domain: str) -> dict:
    """Analyze a domain for DGA characteristics.

    Returns a dict with:
        - is_dga: bool indicating if the domain looks algorithmically generated
        - score: float 0-1 confidence score
        - entropy: Shannon entropy of the registerable domain part
        - reasons: list of reasons why it was flagged
    """
    domain_lower = domain.lower().rstrip(".")
    registerable = _extract_registerable_domain(domain_lower)
    # Remove dots for entropy calculation on the label itself
    label_for_entropy = registerable.replace(".", "")

    entropy = calculate_entropy(label_for_entropy)
    tld = _get_tld(domain_lower)
    reasons = []
    score = 0.0

    # --- Entropy check ---
    if entropy > 3.5 and len(label_for_entropy) > 15:
        score += 0.35
        reasons.append(f"high_entropy={entropy:.2f}")
    elif entropy > 3.8 and len(label_for_entropy) > 10:
        score += 0.25
        reasons.append(f"elevated_entropy={entropy:.2f}")

    # --- Length check ---
    if len(label_for_entropy) > 20:
        score += 0.15
        reasons.append(f"long_label={len(label_for_entropy)}")
    elif len(label_for_entropy) > 30:
        score += 0.25
        reasons.append(f"very_long_label={len(label_for_entropy)}")

    # --- Consonant ratio ---
    cr = _consonant_ratio(label_for_entropy)
    if cr > 0.8:
        score += 0.15
        reasons.append(f"high_consonant_ratio={cr:.2f}")

    # --- Digit mixing ---
    dr = _digit_ratio(label_for_entropy)
    if dr > 0.3:
        score += 0.15
        reasons.append(f"high_digit_ratio={dr:.2f}")

    # --- Suspicious TLD ---
    if tld in SUSPICIOUS_TLDS:
        score += 0.10
        reasons.append(f"suspicious_tld={tld}")

    # --- No vowels pattern (hex-like) ---
    if len(label_for_entropy) > 10 and re.match(r'^[a-f0-9]+$', label_for_entropy):
        score += 0.30
        reasons.append("hex_like_domain")

    # --- False positive suppression ---
    if _has_common_word(domain_lower):
        score *= 0.3  # Heavily penalize known-brand domains
        reasons.append("contains_common_word(reduced)")

    if tld in COMMON_TLDS and score < 0.4:
        score *= 0.7
        # No reason added, just a quiet reduction

    score = min(score, 1.0)
    is_dga = score >= 0.45

    return {
        "is_dga": is_dga,
        "score": round(score, 3),
        "entropy": round(entropy, 3),
        "reasons": reasons,
        "domain": domain_lower,
    }
