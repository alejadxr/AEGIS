"""Every ENABLED YAML rule must be reachable from a real event producer.

The product advertises its enabled-rule count, so a rule that can never fire is
a false claim about what it detects. Before v1.7.1 roughly a quarter of the
shipped rules sat on event types no producer emits (`connection`, `dns_query`,
`cloud_api`, ...) or filtered on fields no producer populates (`parent_process`,
`csrf_valid`, `service`, ...). They loaded, counted, and could not match.

The set of producers is derived from the code that publishes into the engine,
not from a hand-kept list of rule types, so it moves with the code:

  * log pipeline  -- event_normalizer.PATTERNS plus every type
                     _refine_auth_failure can return; fields from a real
                     normalize() result
  * EDR           -- what translate_edr_event yields for real agent payloads
                     (tests/unit/edr_payloads.py), sent through the real routes
  * dos_shield    -- _DOS_EVENT_TYPES
  * honeypots     -- honeypot_interaction
  * connection_monitor -- the event_type of build_event()

Reachability then goes through the engine's own _event_type_satisfies and
_FIELD_ALIASES, so an alias that genuinely widens what a rule receives counts.

To revive a disabled rule, wire a producer for its event type / field and flip
`enabled: true`; this test then holds it to that.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
import yaml

SIGMA_PATH = Path(__file__).parent.parent.parent / "app" / "rules" / "sigma"

# host_monitor publishes kind=network_anomaly on `edr.suspicious_process`, a
# topic the engine does not subscribe to (and its psutil.net_connections source
# needs root on macOS), so _EDR_EVENT_MAP's `connection` entry never receives
# an event even though the map lists it.
_UNSUBSCRIBED_EDR_KINDS = {"network_anomaly"}


def _refine_auth_types() -> set[str]:
    from app.services import event_normalizer

    tree = ast.parse(inspect.getsource(event_normalizer._refine_auth_failure))
    types: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Tuple)
            and node.value.elts
            and isinstance(node.value.elts[0], ast.Constant)
        ):
            types.add(node.value.elts[0].value)
    return types


def _log_fields() -> set[str]:
    from app.services.event_normalizer import normalize

    event = normalize(
        '203.0.113.9 - - [01/Jan/2026:00:00:00 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "-" "curl/8.0"',
        source="cayde6-frontend",
    )
    assert event, "normalizer produced nothing for a plain access-log line"
    return set(event) | {"timestamp"}  # log_watcher stamps timestamp before publishing


def _edr_producers() -> dict[str, set[str]]:
    """event_type -> fields, from real agent payloads run through the real routes
    and the real translator (tests/unit/edr_payloads.py)."""
    from app.services.edr_events import EDR_EVENT_MAP, translate_edr_event
    from . import edr_payloads

    out: dict[str, set[str]] = {}
    for bus_event in edr_payloads.all_bus_events():
        for event in translate_edr_event(bus_event, default_host="h"):
            out.setdefault(event["event_type"], set()).update(event)
    missing = {
        t for kind, t in EDR_EVENT_MAP.items()
        if kind not in _UNSUBSCRIBED_EDR_KINDS
    } - set(out)
    assert not missing, (
        f"EDR_EVENT_MAP maps to {sorted(missing)} but no sample payload in "
        "edr_payloads.py produces them; add one so the rules on them are checked"
    )
    return out


def _producers() -> dict[str, set[str] | None]:
    """event_type -> populated fields (None = not modelled, accept any field)."""
    from app.modules.network.connection_monitor import ConnectionMonitor
    from app.services.correlation_engine import _DOS_EVENT_TYPES
    from app.services.event_normalizer import PATTERNS

    out: dict[str, set[str] | None] = {}
    log_types = {p.event_type for p in PATTERNS} | _refine_auth_types() | {"http_request"}
    for t in log_types:
        out[t] = _log_fields()
    out.update(_edr_producers())
    for t in _DOS_EVENT_TYPES:
        out[t] = None
    out["honeypot_interaction"] = None
    conn = ConnectionMonitor().build_event({"remote_ip": "203.0.113.9", "remote_port": 443})
    out[conn["event_type"]] = set(conn)
    return out


def _enabled_rules() -> list[tuple[Path, dict]]:
    rules = []
    for path in sorted(SIGMA_PATH.rglob("*.yaml")):
        rule = yaml.safe_load(path.read_text())
        if rule.get("enabled", True):
            rules.append((path, rule))
    return rules


def _fields_reaching(producers: dict, rule_type: str) -> list[set[str] | None]:
    from app.services.correlation_engine import _event_type_satisfies

    return [f for t, f in producers.items() if _event_type_satisfies(t, rule_type)]


def test_every_enabled_rule_sits_on_an_event_type_something_produces():
    producers = _producers()
    unreachable = [
        f"{rule['id']} ({rule['condition']['event_type']})"
        for _, rule in _enabled_rules()
        if not _fields_reaching(producers, rule["condition"]["event_type"])
    ]
    assert not unreachable, (
        f"{len(unreachable)} enabled rule(s) sit on an event type no producer "
        "emits, so they can never fire and inflate the advertised rule count. "
        "Set `enabled: false` (with a description saying what would revive "
        "them) or wire a producer:\n  " + "\n  ".join(unreachable)
    )


def test_every_enabled_rule_filters_only_on_fields_its_producers_populate():
    from app.services.correlation_engine import (
        _FIELD_ALIASES,
        _OP_EQ,
        _OP_EXCLUDES,
        _parse_filter_key,
    )

    producers = _producers()
    dead = []
    for _, rule in _enabled_rules():
        cond = rule["condition"]
        sources = _fields_reaching(producers, cond["event_type"])
        if not sources or any(s is None for s in sources):
            continue  # type test reports unreachable; None = unmodelled producer
        for key in cond.get("filter") or {}:
            op, field = _parse_filter_key(key)
            if op == _OP_EXCLUDES:
                continue  # an absent field satisfies an exclusion
            field = key if op == _OP_EQ else field
            names = {field, *_FIELD_ALIASES.get(field, ())}
            if field.startswith("path"):
                names |= {"path", "request_path", "url"}
            if not any(names & s for s in sources):
                dead.append(f"{rule['id']}: `{key}`")
    assert not dead, (
        "enabled rule(s) filter on a field no producer of their event type "
        "populates, so the clause can never match:\n  " + "\n  ".join(dead)
    )


@pytest.mark.parametrize("event_type", ["connection", "dns_query", "cloud_api"])
def test_reachability_check_would_catch_the_known_dead_types(event_type):
    # Guards the guard: if _producers() ever starts claiming these, the test
    # above has silently stopped testing anything.
    assert not _fields_reaching(_producers(), event_type)
