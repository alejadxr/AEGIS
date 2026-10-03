from app.services import block_ttl as t


def test_default_ttl_for_ordinary_alert():
    assert t.compute_ttl_hours("medium", ["http_auth_brute_force"]) == t.BASE_TTL_HOURS


def test_critical_severity_gets_long_block():
    assert t.compute_ttl_hours("critical", []) == t.CRITICAL_TTL_HOURS


def test_cve_rule_gets_long_block_even_if_severity_low():
    ids = t.collect_rule_ids({"sigma_matches": ["sigma_cve_2025_34026_vite_fs"]})
    assert t.compute_ttl_hours("high", ids) == t.CRITICAL_TTL_HOURS


def test_exploit_class_rule_markers():
    for rid in ("sigma_web_path_traversal", "sigma_command_injection", "sigma_webshell_upload"):
        assert t.is_critical_or_exploit("medium", [rid])
    assert not t.is_critical_or_exploit("medium", ["sigma_web_scanner_ua"])


def test_threat_type_exploit_class():
    assert t.compute_ttl_hours("high", [], threat_type="rce") == t.CRITICAL_TTL_HOURS


def test_repeat_offender_doubles_and_caps():
    base = t.BASE_TTL_HOURS
    assert t.compute_ttl_hours("low", [], prior_blocks=1) == base * 2
    assert t.compute_ttl_hours("low", [], prior_blocks=2) == base * 4
    assert t.compute_ttl_hours("critical", [], prior_blocks=50) == t.MAX_TTL_HOURS


def test_collect_rule_ids_accepts_dict_matches_and_pattern():
    ids = t.collect_rule_ids({"pattern": "RCE", "sigma_matches": [{"id": "A"}, {"rule_id": "B"}]})
    assert ids == ["rce", "a", "b"]
