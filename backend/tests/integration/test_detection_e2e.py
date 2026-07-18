"""Raw-log -> normalizer -> correlation-engine end-to-end test — Task A4 (P0-5).

WHY THIS TEST EXISTS
---------------------
Every other detection test in this repo builds event dicts by hand (e.g.
``{"path": "...", "source_ip": "..."}``), bypassing ``event_normalizer.normalize``
entirely. That is exactly how the A1/A3 regressions slipped through: the real
normalizer emits the field ``request_path`` (not ``path``), and
``correlation_engine._matches_filter`` had to be patched to read both keys
(see ``tests/unit/test_matches_filter_path.py``). A hand-built event dict can
silently paper over a broken wiring between the two modules.

This test drives the REAL pipeline instead:

    raw log line (str)
        -> app.services.event_normalizer.normalize(line, source)   [pure function]
        -> app.services.correlation_engine.CorrelationEngine.evaluate(event)  [async]

and asserts on the actual fired-rule objects the engine returns, so a future
regression in either module (wrong field name, wrong event_type, wrong
protocol classification, YAML/BUILT_IN_RULES drift) fails this test instead
of shipping silently.

REAL API SHAPES (verified by reading the source, not assumed):

* ``event_normalizer.normalize(log_line: str, source: str = "") -> dict | None``
  parses a RAW log line string via ``_ACCESS_LOG_RE`` -- a combined/access-log
  shaped regex requiring a quoted ``"METHOD /path HTTP/x.y"`` segment where the
  captured path is ``\\S+`` (a single whitespace-free token). The returned
  dict's HTTP path lives under the key ``request_path`` (NOT ``path``).
* ``CorrelationEngine.evaluate(self, event: dict) -> list[dict]`` is a
  coroutine. It appends the event to an in-memory sliding window, matches it
  against ``self._rules_by_type[event["event_type"]]``, and returns only the
  list of SIGMA-style rules that fired (chain-rule triggers are handled
  separately and are NOT included in the return value -- confirmed by reading
  ``evaluate()``: ``chain_triggered`` is a local variable, never merged into
  the ``triggered`` list that gets returned).
* Fired-rule entries are ``app.schemas.rule.Rule`` pydantic objects when the
  YAML pack under ``app/rules/`` loads successfully (the default/expected
  path -- confirmed present in this repo), or plain ``dict`` copies of
  ``BUILT_IN_RULES`` if YAML loading fails entirely. Both shapes expose a
  compatible ``.get(key, default)`` method (``Rule`` defines dict-style
  ``__getitem__``/``get``/``__contains__`` specifically so existing
  ``rule["id"]`` / ``rule.get(...)`` engine code keeps working against either
  shape), so assertions here use ``.get()`` throughout rather than assuming
  one representation.

ENGINE CONSTRUCTION: mirrors the only other place in this repo that builds a
``CorrelationEngine`` directly, ``tests/perf/test_event_throughput.py``
(``CorrelationEngine()`` takes no arguments; rules auto-load from
``app/rules/`` in ``__init__``; ``evaluate()`` can be awaited immediately, no
``start()``/``register_event_bus()`` call needed). ``tests/integration/
test_ransomware_e2e.py`` does not construct a ``CorrelationEngine`` itself
(it drives a live HTTP backend), so it is used here only as the structural
template (docstrings, section banners, descriptive assertion messages,
``pytest.mark.asyncio``), not for engine wiring.

RULE MATH (read directly off ``app/rules/sigma/web_attacks/*.yaml``, which
``BUILT_IN_RULES`` in ``correlation_engine.py`` mirrors exactly):

* ``sql_injection_chain``: event_type=``sql_injection``, count_threshold=3,
  group_by=``source_ip``, window=300s, NO path filter. The normalizer's
  generic ``sql_injection`` pattern (event_normalizer.py, the catch-all
  regex including the literal ``%27`` alternative) classifies a UNION-SELECT
  probe as event_type ``sql_injection`` -- NOT ``web_request`` -- so this is
  the only SQLi rule reachable through the real pipeline; it needs 3 hits
  from the same source_ip.
* ``sigma_web_path_traversal``: event_type=``web_request``, count_threshold=1,
  filter path_contains ["../", "..\\\\", "%2e%2e", "/etc/passwd",
  "/etc/shadow"]. The normalizer's generic ``path_traversal`` pattern is the
  only one that classifies as event_type ``web_request`` directly, so a
  SINGLE event is enough to fire this rule.
* ``xss_attack_chain``: event_type=``xss``, count_threshold=5, group_by=
  ``source_ip``, window=300s, NO path filter. The normalizer's generic
  ``xss_attempt`` pattern classifies as event_type ``xss`` (not
  ``web_request``), so like SQLi this needs 5 hits from the same source_ip.

NOTE on a rule this test deliberately does NOT exercise:
``sigma_web_sqli_union`` (event_type=``web_request``, filter path_contains
UNION/SELECT) can never fire from the real normalizer's generic SQLi
pattern, because that pattern emits event_type ``sql_injection``, not
``web_request``. That is a separate, pre-existing detection-coverage gap
(not the A1/A3 bug this task targets) -- flagged here rather than forcing a
false-positive assertion against it.

PATH FORMAT CAVEAT: ``_ACCESS_LOG_RE`` captures the path as ``\\S+`` -- a
single token with NO whitespace. A literal "UNION SELECT" (with a real
space) breaks path capture entirely (the whole access-log regex fails to
match that quoted segment, and ``request_path`` stays ``None``). Every raw
line below therefore URL-encodes spaces inside the attack payload (``%20``)
and relies on payload markers that need no whitespace to match the
normalizer patterns (``%27``, ``<script``, ``../``, ``/etc/passwd``).
"""
from __future__ import annotations

import pytest

from app.services import event_normalizer
from app.services.correlation_engine import CorrelationEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches the real PM2 app name in _PROTOCOL_FOR_SOURCE_MAP -> protocol
# "http_api" (event_normalizer.py). Using the real name keeps this test
# honest about what a production log line looks like.
_SOURCE = "cayde6-api"


def _access_log_line(source_ip: str, path: str, *, port: int = 51000, status: int = 200) -> str:
    """Build a raw combined-log-format line, the shape _ACCESS_LOG_RE parses.

    Shape: '<ip>:<port> - - [<date>] "GET <path> HTTP/1.1" <status> <size> "-" "<ua>"'
    `path` MUST be a single whitespace-free token -- see module docstring.
    """
    return (
        f'{source_ip}:{port} - - [18/Jul/2026:12:00:00 +0000] '
        f'"GET {path} HTTP/1.1" {status} 512 "-" "AEGIS-E2E-Test/1.0"'
    )


def _fired_ids(fired: list) -> set[str]:
    """Extract rule ids from a `CorrelationEngine.evaluate()` return value.

    Works whether entries are `Rule` pydantic objects (YAML pack loaded, the
    expected path) or plain dicts (BUILT_IN_RULES fallback) -- both expose a
    compatible `.get()`.
    """
    return {r.get("id") for r in fired if r.get("id")}


def _fired_text(fired: list) -> str:
    """Lowercased id+title+name of every fired rule, for substring assertions."""
    parts: list[str] = []
    for r in fired:
        parts.append(str(r.get("id") or ""))
        parts.append(str(r.get("title") or ""))
        parts.append(str(r.get("name") or ""))
    return " ".join(parts).lower()


@pytest.fixture
def engine() -> CorrelationEngine:
    """A fresh CorrelationEngine per test -- no shared sliding-window/cooldown
    state between tests. Mirrors tests/perf/test_event_throughput.py's
    `_build_engine()`: `CorrelationEngine()` takes no arguments and loads the
    real YAML rule pack (122 sigma + 5 chain rules) from app/rules/ in
    __init__(), falling back to BUILT_IN_RULES only if that load fails.
    """
    return CorrelationEngine()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sql_injection_union_select_fires_chain_rule(engine: CorrelationEngine):
    """Raw UNION-SELECT probes, normalized for real, fire `sql_injection_chain`.

    sql_injection_chain needs count_threshold=3 hits from the same source_ip
    within a 300s window (no path filter) -- so we feed 3 distinct SQLi
    requests through the real normalize() -> evaluate() pipeline and expect
    the rule to fire on the 3rd call, not before.
    """
    source_ip = "203.0.113.11"
    fired_per_call: list[list] = []

    for i in range(1, 4):
        # Realistic UNION-based SQLi probe. Space -> %20 so the access-log
        # regex can still capture a single-token path; "%27" (URL-encoded
        # single quote) is what actually trips event_normalizer's generic
        # sql_injection pattern (its "%27" alternative needs no whitespace).
        path = f"/index.php?id=-{i}%27%20UNION%20SELECT%20username,password%20FROM%20users--%20-"
        line = _access_log_line(source_ip, path)

        event = event_normalizer.normalize(line, source=_SOURCE)
        assert event is not None, f"normalize() dropped a well-formed SQLi access line: {line!r}"
        assert event["event_type"] == "sql_injection", (
            f"Expected the generic sql_injection pattern to classify this UNION SELECT "
            f"probe as event_type='sql_injection', got {event['event_type']!r}. "
            f"event={event}"
        )
        assert event["source_ip"] == source_ip
        # This is the A1/A3 regression surface: the payload must survive into
        # request_path (NOT a 'path' key) for downstream rule filters to see it.
        assert event["request_path"] is not None and "UNION" in event["request_path"], (
            f"Expected request_path to carry the UNION SELECT payload, got "
            f"{event['request_path']!r}"
        )
        assert "%27" in event["request_path"]

        fired_per_call.append(await engine.evaluate(event))

    assert _fired_ids(fired_per_call[0]).isdisjoint({"sql_injection_chain"}), (
        "sql_injection_chain fired on the 1st SQLi event -- expected it to require 3 hits."
    )
    assert _fired_ids(fired_per_call[1]).isdisjoint({"sql_injection_chain"}), (
        "sql_injection_chain fired on the 2nd SQLi event -- expected it to require 3 hits."
    )
    fired_third = fired_per_call[2]
    assert "sql_injection_chain" in _fired_ids(fired_third), (
        f"Expected 'sql_injection_chain' to fire on the 3rd SQLi event from the same "
        f"source_ip within its 300s window. Fired rule ids on call 3: "
        f"{sorted(_fired_ids(fired_third))}"
    )
    assert "sql injection" in _fired_text(fired_third)


@pytest.mark.asyncio
async def test_path_traversal_fires_single_shot_web_rule(engine: CorrelationEngine):
    """A single ../../etc/passwd probe fires `sigma_web_path_traversal` immediately.

    sigma_web_path_traversal has count_threshold=1 and a path_contains filter
    that includes "../" and "/etc/passwd" -- both present in the payload --
    and, unlike the generic SQLi/XSS patterns, event_normalizer's generic
    path_traversal pattern classifies straight to event_type='web_request',
    which is exactly what this rule's condition listens for. One evaluate()
    call is enough.
    """
    source_ip = "203.0.113.21"
    path = "/download?file=../../../../etc/passwd"
    line = _access_log_line(source_ip, path)

    event = event_normalizer.normalize(line, source=_SOURCE)
    assert event is not None, f"normalize() dropped a well-formed path-traversal line: {line!r}"
    assert event["event_type"] == "web_request", (
        f"Expected the generic path_traversal pattern to classify this probe as "
        f"event_type='web_request', got {event['event_type']!r}. event={event}"
    )
    assert event["request_path"] == path, (
        f"Expected request_path to carry the traversal payload verbatim, got "
        f"{event['request_path']!r}"
    )

    fired = await engine.evaluate(event)

    assert "sigma_web_path_traversal" in _fired_ids(fired), (
        f"Expected 'sigma_web_path_traversal' to fire on the first ../../etc/passwd "
        f"probe (count_threshold=1). Fired rule ids: {sorted(_fired_ids(fired))}"
    )
    assert "path traversal" in _fired_text(fired) or "traversal" in _fired_text(fired)


@pytest.mark.asyncio
async def test_xss_script_tag_fires_chain_rule(engine: CorrelationEngine):
    """Five <script> probes, normalized for real, fire `xss_attack_chain`.

    xss_attack_chain needs count_threshold=5 hits from the same source_ip
    within a 300s window (no path filter) -- event_normalizer's generic
    xss_attempt pattern classifies a <script>/alert( payload as event_type
    'xss', which is what this rule listens for.
    """
    source_ip = "203.0.113.31"
    fired_per_call: list[list] = []

    for i in range(1, 6):
        path = f"/search?q=<script>alert({i})</script>"
        line = _access_log_line(source_ip, path)

        event = event_normalizer.normalize(line, source=_SOURCE)
        assert event is not None, f"normalize() dropped a well-formed XSS access line: {line!r}"
        assert event["event_type"] == "xss", (
            f"Expected the generic xss_attempt pattern to classify this <script> probe "
            f"as event_type='xss', got {event['event_type']!r}. event={event}"
        )
        assert event["request_path"] is not None and "<script" in event["request_path"], (
            f"Expected request_path to carry the <script> payload, got "
            f"{event['request_path']!r}"
        )

        fired_per_call.append(await engine.evaluate(event))

    for call_index in range(4):
        assert _fired_ids(fired_per_call[call_index]).isdisjoint({"xss_attack_chain"}), (
            f"xss_attack_chain fired on XSS event #{call_index + 1} -- expected it to "
            f"require 5 hits."
        )
    fired_fifth = fired_per_call[4]
    assert "xss_attack_chain" in _fired_ids(fired_fifth), (
        f"Expected 'xss_attack_chain' to fire on the 5th XSS event from the same "
        f"source_ip within its 300s window. Fired rule ids on call 5: "
        f"{sorted(_fired_ids(fired_fifth))}"
    )
    assert "xss" in _fired_text(fired_fifth)
