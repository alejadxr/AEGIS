"""
Unit tests for the additive-confidence and consensus-risk helpers in
`app.services.ip_intel`. These exercise the pure aggregation functions in
isolation — no network, no DB.

Cases:
  1. Tor exit on cloud datacenter (Alibaba) → DC>=0.9, TOR=1.0, ATTACKER>=0.9,
     consensus_risk>=90.
  2. Google DNS 8.8.8.8 → DC=1.0 (cloud), TOR=0.0, low attacker.
  3. Random consumer IP (no flags) → all 0.0, consensus 0.
"""

import pytest

from app.services.ip_intel import _confidence_additive, _consensus_risk


def test_tor_exit_on_cloud_datacenter():
    merged = {
        "is_tor": True,
        "is_datacenter": True,
        "is_malicious": True,
        "shodan_tags": ["cloud", "alibaba"],
        "proxycheck_type": "TOR",
        "proxycheck_risk": 80,
        "asn_reputation_owner": "Alibaba (US) Technology Co., Ltd.",
        "org": "Alibaba Cloud",
        "hostname": "ecs.alibaba-inc.com",
        "ipapi_is_abuse_score": 0.7,
    }
    asn_rep = {"asn_reputation_tag": "cloud"}

    conf = _confidence_additive(merged, tor_match=True, asn_rep=asn_rep)
    assert conf["tor"] == 1.0, conf
    assert conf["datacenter"] >= 0.9, conf
    assert conf["attacker"] >= 0.9, conf

    risk = _consensus_risk(merged, tor_match=True, spamhaus_match=False)
    assert risk >= 90, risk


def test_google_dns_known_service():
    merged = {
        "is_tor": False,
        "is_datacenter": True,
        "is_known_service": True,
        "shodan_tags": ["google", "cloud"],
        "asn_reputation_owner": "Google LLC",
        "org": "Google LLC",
        "hostname": "dns.google",
    }
    asn_rep = {"asn_reputation_tag": "cloud"}

    conf = _confidence_additive(merged, tor_match=False, asn_rep=asn_rep)
    assert conf["datacenter"] == 1.0, conf
    assert conf["tor"] == 0.0, conf
    # Some attacker hints can come through other providers; for Google DNS
    # with no provider flags we expect <=0.4 (lenient upper bound).
    assert conf["attacker"] <= 0.4, conf


def test_random_consumer_ip_no_flags():
    merged = {
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_datacenter": False,
        "is_malicious": False,
        "shodan_tags": [],
        "asn_reputation_owner": "Consumer ISP, S.A.",
        "org": "Consumer ISP, S.A.",
        "hostname": "client-1-2-3-4.isp.example.net",
    }
    asn_rep = {"asn_reputation_tag": "isp"}

    conf = _confidence_additive(merged, tor_match=False, asn_rep=asn_rep)
    assert conf == {"tor": 0.0, "vpn": 0.0, "proxy": 0.0,
                    "datacenter": 0.0, "attacker": 0.0}, conf

    risk = _consensus_risk(merged, tor_match=False, spamhaus_match=False)
    assert risk == 0, risk


def test_consensus_risk_picks_max_signal():
    """ipquery says 0 but abuseipdb says 87 → consensus should be 87."""
    merged = {
        "risk_score": 0,
        "abuseipdb_score": 87,
    }
    risk = _consensus_risk(merged, tor_match=False, spamhaus_match=False)
    assert risk == 87, risk


def test_consensus_risk_tor_baseline():
    """Tor exit alone → at least 90."""
    merged = {"is_tor": True, "risk_score": 0}
    risk = _consensus_risk(merged, tor_match=True, spamhaus_match=False)
    assert risk >= 90, risk
