from pathlib import Path

import yaml

from app.services.correlation_engine import _matches_filter

_RULE = Path(__file__).resolve().parents[2] / "app/rules/sigma/web_attacks/sigma_web_xxe.yaml"
_FILTER = yaml.safe_load(_RULE.read_text())["condition"]["filter"]


def test_static_asset_get_is_not_xxe():
    assert not _matches_filter({"request_path": "/media/system/js/core.js"}, _FILTER)


def test_api_system_ping_is_not_xxe():
    assert not _matches_filter({"request_path": "/access/api/v1/system/ping"}, _FILTER)


def test_file_scheme_in_benign_param_is_not_xxe():
    assert not _matches_filter({"request_path": "/open?u=file://docs/a.txt"}, _FILTER)


def test_real_entity_payload_matches():
    p = '/x?d=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    assert _matches_filter({"request_path": p}, _FILTER)


def test_url_encoded_entity_matches():
    assert _matches_filter({"request_path": "/x?d=%3C!ENTITY%20xxe"}, _FILTER)
