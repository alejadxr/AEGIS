"""Precision of the web-path rules corrected after the 10-day traffic review,
the AI-credential rule, the single-shot visibility rules and the atomic
blocklist write."""
import threading
from pathlib import Path

import pytest
import yaml

from app.core import ip_blocker
from app.services.correlation_engine import BUILT_IN_RULES, _matches_filter

_RULES = Path(__file__).resolve().parents[2] / "app/rules/sigma"


def _rule(rel: str) -> dict:
    return yaml.safe_load((_RULES / rel).read_text())


def _hit(rule: dict, path: str, method: str = "GET") -> bool:
    return _matches_filter(
        {"request_path": path, "request_method": method}, rule["condition"]["filter"]
    )


VERSA = _rule("web_attacks/sigma_cve_versa_concerto_2025_34026.yaml")
SSRF = _rule("web_attacks/sigma_web_ssrf.yaml")
TRAVERSAL = _rule("web_attacks/sigma_web_path_traversal.yaml")
UPLOAD = _rule("web_attacks/sigma_web_file_upload.yaml")
PROBE = _rule("web_attacks/sigma_web_sensitive_file_probe.yaml")
AI_CRED = _rule("ai_infra/sigma_ai_credential_probe.yaml")
HARVEST = _rule("web_attacks/sigma_web_secret_harvest_instant.yaml")
PHP = _rule("web_attacks/sigma_web_php_probe.yaml")


@pytest.mark.parametrize("path", ["/actuator", "/actuator/health", "/api/actuator-status"])
def test_versa_ignores_benign_actuator(path):
    assert not _hit(VERSA, path)


@pytest.mark.parametrize("ep", ["env", "heapdump", "threaddump", "configprops", "mappings"])
def test_versa_matches_disclosing_endpoints(ep):
    assert _hit(VERSA, f"/actuator/{ep}")
    assert VERSA["severity"] == "critical"


FRAMEWORK = _rule("web_attacks/sigma_web_framework_probe.yaml")


@pytest.mark.parametrize("path", [
    "/actuator", "/actuator/health", "/swagger-ui.html", "/swagger/v1", "/openapi.json",
    "/graphql", "/_cat/indices", "/api/datasources", "/debug/vars", "/server-status",
])
def test_framework_probe_is_low_single_shot(path):
    assert _hit(FRAMEWORK, path)
    assert FRAMEWORK["severity"] == "low" and FRAMEWORK["condition"]["count_threshold"] == 1


def test_actuator_no_longer_feeds_high_three_hit_rule():
    assert not _hit(PROBE, "/actuator")
    assert not _hit(PROBE, "/actuator/health")


def test_ssrf_ignores_localhost_key_path():
    assert not _hit(SSRF, "/localhost.key")
    assert not _hit(SSRF, "/static/127.0.0.1.png")


@pytest.mark.parametrize("path", [
    "/fetch?url=http://localhost:8080/admin",
    "/fetch?host=localhost",
    "/img?u=http://127.0.0.1/x",
    "/img?ip=127.0.0.1",
    "/x?u=http://0.0.0.0:22",
    "/latest/meta-data?u=169.254.169.254",
    "/x?u=metadata.google.internal",
])
def test_ssrf_matches_real_payloads(path):
    assert _hit(SSRF, path)


@pytest.mark.parametrize("path", [
    "/a/../../etc/hosts", "/a/..%2f..%2fx", "/a/..%2F..%2Fx", "/a/..%5cwin.ini",
    "/a/..;/manager", "/a/%252e%252e/x", "/proc/self/environ", "/a/%2E%2E/x",
])
def test_traversal_encodings(path):
    assert _hit(TRAVERSAL, path)


@pytest.mark.parametrize("path", [
    "/_next/static/chunks/app.js", "/api/items?name=a.b..c", "/blog/what-is-a-path",
])
def test_traversal_ignores_nextjs_routes(path):
    assert not _hit(TRAVERSAL, path)


def test_xmlrpc_post_is_not_a_file_upload():
    assert not _hit(UPLOAD, "/xmlrpc.php", "POST")
    assert _hit(UPLOAD, "/uploads/shell.php", "POST")
    assert _hit(PHP, "/xmlrpc.php", "POST")


def test_builtin_fallbacks_match_yaml():
    by_id = {r["id"]: r["condition"].get("filter") for r in BUILT_IN_RULES}
    for rule in (SSRF, TRAVERSAL, UPLOAD):
        assert by_id[rule["id"]] == rule["condition"]["filter"]


AI_PATHS = [
    "/.claude/settings.json", "/.cursor/mcp.json", "/.windsurf/x", "/.continue/config.json",
    "/.codex/config.toml", "/.gemini/settings.json", "/.aider.conf.yml", "/.mcp.json",
    "/mcp.json", "/.vscode/sftp.json", "/.vscode/settings.json", "/litellm.yaml",
    "/litellm_config.yaml", "/.env.anthropic", "/.env.openai", "/.openai/key",
    "/.anthropic/key", "/.config/gh/hosts.yml", "/.CLAUDE/x",
]


@pytest.mark.parametrize("path", AI_PATHS)
def test_ai_credential_paths_match(path):
    assert _hit(AI_CRED, path)


@pytest.mark.parametrize("path", ["/", "/api/v1/incidents", "/dashboard/settings", "/_next/static/a.js"])
def test_ai_credential_ignores_app_routes(path):
    assert not _hit(AI_CRED, path)


def test_ai_credential_shape():
    c = AI_CRED["condition"]
    assert (c["count_threshold"], c["time_window_seconds"], c["group_by"]) == (1, 300, "source_ip")
    assert AI_CRED["severity"] == "high"


@pytest.mark.parametrize("path", ["/.env", "/.aws/credentials", "/.git/config", "/.ssh/id_rsa", "/.npmrc"])
def test_secret_harvest_matches(path):
    assert _hit(HARVEST, path)


@pytest.mark.parametrize("path", [
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php", "/wp-login.php", "/wp-admin/install.php",
    "/xmlrpc.php", "/cgi-bin/luci",
])
def test_php_probe_matches(path):
    assert _hit(PHP, path)


def test_visibility_rules_never_high_enough_to_block():
    assert HARVEST["severity"] == "low" and PHP["severity"] == "low"
    for r in (HARVEST, PHP):
        assert r["condition"]["count_threshold"] == 1


def test_atomic_write_survives_concurrent_reader(tmp_path):
    target = tmp_path / "blocked_ips.txt"
    ips = {f"198.51.100.{i}" for i in range(1, 200)}
    full = "# h\n" + "\n".join(sorted(ips)) + "\n"
    ip_blocker.atomic_write_text(target, full)
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            text = target.read_text()
            if text != full and text != full + "203.0.113.1\n":
                bad.append(len(text))

    t = threading.Thread(target=reader)
    t.start()
    for _ in range(300):
        ip_blocker.atomic_write_text(target, full + "203.0.113.1\n")
        ip_blocker.atomic_write_text(target, full)
    stop.set()
    t.join()
    assert not bad
    assert [p.name for p in tmp_path.iterdir()] == ["blocked_ips.txt"]


def test_reload_keeps_previous_set_on_damaged_file(tmp_path, monkeypatch):
    target = tmp_path / "blocked_ips.txt"
    monkeypatch.setattr(ip_blocker, "BLOCKED_IPS_FILE", target)
    monkeypatch.setattr(ip_blocker, "_should_purge_ip", lambda ip: (False, ""))  # doc IPs would be purged
    previous = {f"198.51.100.{i}" for i in range(1, 41)}
    target.write_text("# AEGIS\n198.51.100.1\n")
    assert ip_blocker._load_blocked_ips(previous=previous) == previous
    assert ip_blocker._load_blocked_ips() == {"198.51.100.1"}
