# backend/tests/unit/test_matches_filter_generic.py
"""The generalised filter vocabulary: `<field>_contains`, `<field>_contains_all`
and `<field>_excludes` on any field, not just `path`.

Companion to test_matches_filter_path.py (legacy path_* behaviour) and
test_matches_filter_legacy_parity.py (old-vs-new oracle over the corpus).
"""
from app.services.correlation_engine import _compile_filter_regex, _matches_filter


# ---------------------------------------------------------------------------
# user-agent: the field this was built for
# ---------------------------------------------------------------------------

def test_ua_contains_reads_user_agent_through_the_alias_table():
    # Normalizer events carry `user_agent`; rules are written with the short
    # `ua` spelling, exactly like `method` vs `request_method`.
    event = {"user_agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}
    assert _matches_filter(event, {"ua_contains": ["sqlmap", "nikto"]}) is True


def test_user_agent_contains_long_spelling_also_works():
    event = {"user_agent": "Nikto/2.1.6"}
    assert _matches_filter(event, {"user_agent_contains": ["nikto"]}) is True


def test_contains_is_case_insensitive_both_ways():
    assert _matches_filter({"user_agent": "Mozilla ZGRAB"}, {"ua_contains": ["zgrab"]}) is True
    assert _matches_filter({"user_agent": "mozilla zgrab"}, {"ua_contains": ["ZGRAB"]}) is True


def test_contains_all_requires_every_fragment():
    event = {"user_agent": "Mozilla/5.0 zgrab/0.x"}
    assert _matches_filter(event, {"ua_contains_all": ["mozilla", "zgrab"]}) is True
    assert _matches_filter(event, {"ua_contains_all": ["mozilla", "curl"]}) is False


def test_excludes_fails_when_any_fragment_present():
    assert _matches_filter({"user_agent": "curl/8.4.0"}, {"ua_excludes": ["curl", "wget"]}) is False
    assert _matches_filter({"user_agent": "Mozilla/5.0"}, {"ua_excludes": ["curl", "wget"]}) is True


def test_generic_operators_compose_with_the_rest_of_the_vocabulary():
    event = {"request_method": "GET", "request_path": "/wp-login.php", "user_agent": "sqlmap/1.7"}
    filt = {"method": "GET", "path_contains": ["wp-login"], "ua_contains": ["sqlmap"], "ua_excludes": ["mozilla"]}
    assert _matches_filter(event, filt) is True
    assert _matches_filter(dict(event, user_agent="Mozilla sqlmap"), filt) is False


# ---------------------------------------------------------------------------
# Safety: absent / non-text fields never raise
# ---------------------------------------------------------------------------

def test_absent_field_fails_contains_and_passes_excludes():
    # uvicorn's default access log has no UA, so `user_agent` is None on every
    # cayde6-api event. A UA rule must simply not match there — not blow up.
    event = {"request_path": "/", "user_agent": None}
    assert _matches_filter(event, {"ua_contains": ["sqlmap"]}) is False
    assert _matches_filter(event, {"ua_contains_all": ["sqlmap"]}) is False
    assert _matches_filter(event, {"ua_excludes": ["sqlmap"]}) is True
    assert _matches_filter({}, {"ua_contains": ["sqlmap"]}) is False


def test_non_text_field_is_not_substring_matched():
    assert _matches_filter({"response_status": 404}, {"status_contains": ["40"]}) is False
    assert _matches_filter({"response_status": 404}, {"status_excludes": ["40"]}) is True
    assert _matches_filter({"suid": True}, {"suid_contains": ["true"]}) is False
    assert _matches_filter({"meta": {"a": 1}}, {"meta_contains": ["a"]}) is False


def test_list_valued_field_matches_when_any_element_contains_fragment():
    # `tags` is a populated list on every normalizer event.
    event = {"tags": ["scanner", "api_401"]}
    assert _matches_filter(event, {"tags_contains": ["SCANNER"]}) is True
    assert _matches_filter(event, {"tags_contains": ["error_5xx"]}) is False
    assert _matches_filter(event, {"tags_contains_all": ["scanner", "401"]}) is True
    assert _matches_filter(event, {"tags_contains_all": ["scanner", "5xx"]}) is False
    assert _matches_filter(event, {"tags_excludes": ["scanner"]}) is False
    assert _matches_filter({"tags": []}, {"tags_contains": ["scanner"]}) is False
    assert _matches_filter({"tags": [1, None, "scanner"]}, {"tags_contains": ["scanner"]}) is True


def test_bare_string_value_is_a_single_fragment():
    assert _matches_filter({"user_agent": "curl/8"}, {"ua_contains": "CURL"}) is True
    assert _matches_filter({"user_agent": "curl/8"}, {"ua_excludes": "curl"}) is False


def test_malformed_fragment_value_never_matches():
    # Neither list nor string: the clause can never hold (validate_filter
    # reports it at load). Fail closed rather than fire on everything.
    assert _matches_filter({"user_agent": "7"}, {"ua_contains": 7}) is False
    assert _matches_filter({"user_agent": "x"}, {"ua_contains": {"a": 1}}) is False
    assert _matches_filter({"user_agent": "x"}, {"ua_contains": None}) is False


def test_non_string_fragments_are_coerced_like_legacy_path_contains():
    assert _matches_filter({"request_path": "/errors/404"}, {"path_contains": [404]}) is True
    assert _matches_filter({"user_agent": "bot-2026"}, {"ua_contains": [2026]}) is True


# ---------------------------------------------------------------------------
# path_* keeps its exact legacy resolution
# ---------------------------------------------------------------------------

def test_path_fallback_chain_skips_empty_and_none_values():
    # Legacy or-chain: path -> request_path -> url -> "". The alias table
    # would stop at a `path` key that is present but None; the chain must not.
    assert _matches_filter({"path": None, "url": "/etc/passwd"}, {"path_contains": ["/etc/passwd"]}) is True
    assert _matches_filter({"path": "", "request_path": "/x/../y"}, {"path_contains": ["../"]}) is True
    assert _matches_filter({"path": "", "request_path": "", "url": ""}, {"path_contains": ["x"]}) is False
    assert _matches_filter({}, {"path_excludes": ["/api/v1/health"]}) is True


def test_other_fields_use_the_alias_table_not_the_path_chain():
    # `request_path_contains` and `url_contains` are new keys; they resolve
    # through _event_get (first present key wins), which is fine for them.
    assert _matches_filter({"request_path": "/A/b"}, {"request_path_contains": ["/a/"]}) is True
    assert _matches_filter({"url": "http://169.254.169.254/"}, {"url_contains": ["169.254.169.254"]}) is True


# ---------------------------------------------------------------------------
# _gt / _regex hardening
# ---------------------------------------------------------------------------

def test_gt_against_non_comparable_value_fails_closed():
    # A producer that emits bytes as a JSON string used to raise TypeError out
    # of evaluate(), aborting every remaining candidate rule for that event.
    assert _matches_filter({"bytes": "1000"}, {"bytes_gt": 100}) is False
    assert _matches_filter({"bytes": 1000}, {"bytes_gt": 100}) is True
    assert _matches_filter({"bytes": 100}, {"bytes_gt": 100}) is False


def test_regex_invalid_pattern_fails_closed():
    assert _matches_filter({"command_line": "x"}, {"command_line_regex": "("}) is False


def test_regex_is_compiled_once_per_pattern():
    pattern = r"(?i)certutil(\.exe)?$"
    _compile_filter_regex.cache_clear()
    event = {"process_name": "CertUtil.exe"}
    assert _matches_filter(event, {"process_name_regex": pattern}) is True
    assert _matches_filter(event, {"process_name_regex": pattern}) is True
    assert _matches_filter({"process_name": "bash"}, {"process_name_regex": pattern}) is False
    info = _compile_filter_regex.cache_info()
    assert info.misses == 1 and info.hits == 2, info


# ---------------------------------------------------------------------------
# Real normalizer output
# ---------------------------------------------------------------------------

def test_sable_json_envelope_event_matches_a_ua_rule():
    from app.services.event_normalizer import normalize

    event = normalize(
        '2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET",'
        '"path":"/wp-login.php","status":404,"ua":"sqlmap/1.7.2#stable (https://sqlmap.org)","cf_ray":"z-AMS"}',
        source="sable",
    )
    assert event is not None
    assert event["user_agent"].startswith("sqlmap/")
    assert _matches_filter(event, {"ua_contains": ["sqlmap", "nikto", "nuclei"]}) is True


def test_combined_log_format_event_matches_a_ua_rule():
    from app.services.event_normalizer import normalize

    event = normalize(
        '45.148.10.111 - - [24/Sep/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "Nuclei - Open-source project"',
        source="cayde6-frontend",
    )
    assert event is not None
    assert _matches_filter(event, {"ua_contains": ["nuclei"]}) is True
    assert _matches_filter(event, {"tags_contains": ["scanner"]}) is True


def test_uvicorn_default_access_log_has_no_user_agent_to_match():
    # Documented limitation, not a bug in the interpreter: uvicorn's default
    # access-log format omits the UA, so a UA rule cannot fire on cayde6-api
    # lines. It must fail cleanly rather than raise.
    from app.services.event_normalizer import normalize

    event = normalize('INFO:     45.148.10.111:51000 - "GET /wp-login.php HTTP/1.1" 404', source="cayde6-api")
    assert event is not None
    assert event["user_agent"] is None
    assert _matches_filter(event, {"ua_contains": ["sqlmap"]}) is False
    assert _matches_filter(event, {"ua_excludes": ["sqlmap"]}) is True
