"""Static validation for rules authored at runtime.

A rule is refused BEFORE it is written when it is malformed, collides with an
existing id, or is shaped like the rules that have already hurt this platform:

* a path filter generic enough to match ordinary traffic (``/api/``, a bare
  ``/admin``, a lone ``localhost``) -- the cause of the /actuator and
  /localhost.key false positives;
* a regex that can backtrack catastrophically (a rule is evaluated on EVERY
  event against every candidate, so one bad pattern stalls the event loop for
  the whole pipeline);
* a high/critical rule that fires on a single ordinary request. The AI engine
  already overrides rule severity upward, so a "critical" with
  ``count_threshold: 1`` and a loose filter is a permanent block waiting for a
  customer.

"Too generic" is NOT decided by a list of forbidden strings. A list only knows
yesterday's mistakes. The filter is EXECUTED, through the correlation engine's
own ``_matches_filter``, against synthetic requests an ordinary visitor makes
(``/``, ``/api/``, ``/login`` ...). A filter that matches any of them is too
generic by definition. The dry-run (rule_dryrun) applies the same idea to the
owner's real recent traffic.

The schema is NOT re-invented here: ``app.schemas.rule.Rule`` is the loader's
own model, and ``correlation_engine.validate_filter`` is the loader's own
filter-vocabulary check. This module only adds what a hand-edited YAML pack
never needed: refusal instead of a log warning.
"""
from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import ValidationError

from app.schemas.rule import Rule
from app.services import authored_rules_registry as registry

MAX_REGEX_LEN = 300
# Compile + match budget for the probe run, in seconds. A healthy pattern takes
# microseconds; 0.25s over ~50KB of adversarial input is already pathological.
REGEX_PROBE_TIMEOUT_S = 0.5

# Requests an ordinary visitor makes. These are probes, not a blocklist: the
# filter is run against them and refused if it matches. Chosen to include the
# shapes the owner named (/, /api/, /api/v1/, a bare /admin) plus common
# first-party paths a too-loose substring catches.
BENIGN_PROBE_PATHS: tuple[str, ...] = (
    "/", "/index.html", "/api/", "/api/v1/", "/api/v1/users", "/admin",
    "/login", "/health", "/static/app.js", "/favicon.ico", "/robots.txt",
    "/dashboard", "/docs", "/assets/logo.png",
)

_HIGH = ("high", "critical")
# A signature needs at least this many literal characters that are not slashes.
_MIN_SIGNATURE_LITERAL = 8
_STRUCTURAL = re.compile(r"[/.=%?(){}$;|\\\-]")
# Fields whose content carries the attack payload, as opposed to metadata.
_PAYLOAD_FIELDS = frozenset({
    "path", "request_path", "url", "uri", "query", "body", "request_body",
    "cmdline", "command_line", "payload",
})


@dataclass
class Issue:
    code: str
    message: str
    field: str = ""
    severity: str = "error"         # error | warning


@dataclass
class ValidationResult:
    issues: list[Issue] = field(default_factory=list)
    exploit_signature: bool = False
    signature_reason: str = ""
    rule: Optional[Rule] = None     # the parsed loader model when schema passed

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, code: str, message: str, field_: str = "", severity: str = "error") -> None:
        self.issues.append(Issue(code, message, field_, severity))


# ---------------------------------------------------------------------------
# Regex safety
# ---------------------------------------------------------------------------

def _parse(pattern: str):
    import re._parser as _p  # Python >= 3.11
    return _p.parse(pattern)


def regex_static_problem(pattern: str) -> Optional[str]:
    """Reason a pattern is backtracking-prone, judged from its parse tree."""
    try:
        import re._constants as c
        tree = _parse(pattern)
    except Exception as exc:  # re.error and parser internals
        return f"does not compile: {exc}"

    repeats = (c.MAX_REPEAT, c.MIN_REPEAT, getattr(c, "POSSESSIVE_REPEAT", c.MAX_REPEAT))

    def first_literals(seq) -> set:
        out = set()
        for op, av in seq:
            if op == c.LITERAL:
                out.add(av)
            elif op == c.SUBPATTERN:
                out |= first_literals(av[-1])
            elif op in (c.IN, c.ANY):
                out.add(None)            # a class / dot overlaps with anything
            break
        return out

    def walk(seq, in_unbounded: bool) -> Optional[str]:
        for op, av in seq:
            if op in repeats:
                lo, hi, sub = av
                unbounded = hi == c.MAXREPEAT or hi > 64
                if in_unbounded and unbounded:
                    return "nested unbounded quantifiers (e.g. (a+)+) backtrack exponentially"
                found = walk(sub, in_unbounded or unbounded)
                if found:
                    return found
            elif op == c.SUBPATTERN:
                found = walk(av[-1], in_unbounded)
                if found:
                    return found
            elif op == c.BRANCH:
                branches = av[1]
                if in_unbounded:
                    seen: set = set()
                    for b in branches:
                        fl = first_literals(b)
                        if None in fl or (fl & seen):
                            return "alternation with overlapping branches inside a repeat (e.g. (a|aa)+)"
                        seen |= fl
                for b in branches:
                    found = walk(b, in_unbounded)
                    if found:
                        return found
        return None

    return walk(tree, False)


_PROBE_SCRIPT = r"""
import re, sys, time, json
pat = json.loads(sys.stdin.read())
rx = re.compile(pat)
probes = ["a" * 6000 + "!", "/" * 6000 + "!", "a/" * 3000 + "!", " " * 6000 + "!",
          "0" * 6000 + "x", "/api/" + "a" * 6000, ("ab" * 3000) + "!", "A=" + "a" * 6000 + "&"]
t = time.perf_counter()
for p in probes:
    rx.search(p)
print(time.perf_counter() - t)
"""


def regex_timing_problem(pattern: str) -> Optional[str]:
    """Run the pattern over adversarial strings in a throwaway process.

    ``re`` cannot be interrupted from a thread, so a runaway match would freeze
    the API; a subprocess with a hard timeout is the only way to bound it.
    """
    import json
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _PROBE_SCRIPT],
            input=json.dumps(pattern), capture_output=True, text=True,
            timeout=REGEX_PROBE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return f"exceeded {REGEX_PROBE_TIMEOUT_S}s on probe strings (catastrophic backtracking)"
    if proc.returncode != 0:
        return f"failed on probe strings: {proc.stderr.strip()[-120:]}"
    return None


def check_regex(pattern: Any) -> Optional[str]:
    if not isinstance(pattern, str):
        return "pattern must be a string"
    if len(pattern) > MAX_REGEX_LEN:
        return f"longer than {MAX_REGEX_LEN} characters"
    return regex_static_problem(pattern) or regex_timing_problem(pattern)


# ---------------------------------------------------------------------------
# Filter analysis
# ---------------------------------------------------------------------------

def _split_key(key: str) -> tuple[str, str]:
    from app.services.correlation_engine import _parse_filter_key, _OP_EQ
    op, fld = _parse_filter_key(key)
    return op, fld


def positive_fragments(filt: dict) -> list[tuple[str, str]]:
    """(field, literal) pairs the filter REQUIRES to be present."""
    from app.services.correlation_engine import _OP_CONTAINS, _OP_CONTAINS_ALL, _OP_REGEX, _OP_EQ
    out: list[tuple[str, str]] = []
    for key, val in (filt or {}).items():
        op, fld = _split_key(key)
        vals = val if isinstance(val, (list, tuple)) else [val]
        if op in (_OP_CONTAINS, _OP_CONTAINS_ALL):
            out += [(fld, str(v)) for v in vals if isinstance(v, str)]
        elif op == _OP_REGEX and isinstance(val, str):
            # literal runs inside the regex are what make it specific
            out += [(fld, run) for run in re.findall(r"[A-Za-z0-9_./%=\-]{3,}", val)]
        elif op == _OP_EQ and isinstance(val, str) and fld in _PAYLOAD_FIELDS:
            out.append((fld, val))
    return out


def exploit_signature(filt: dict) -> tuple[bool, str]:
    """Is this filter a signature of an exploit, as opposed to a topic?

    A signature names something an ordinary request does not contain: a literal
    of real length that also carries structure (a path separator, dot, equals,
    percent-encoding...) inside a payload-bearing field. ``localhost`` is a
    word, not a signature; ``/solr/admin/cores?action=`` is one. This is a
    necessary condition only -- the empirical tests (probes + dry-run) are what
    prove it does not hit legitimate traffic.
    """
    for fld, lit in positive_fragments(filt):
        if fld not in _PAYLOAD_FIELDS:
            continue
        core = lit.replace("/", "")
        if len(core) >= _MIN_SIGNATURE_LITERAL and _STRUCTURAL.search(lit):
            return True, f"{fld} requires {lit!r}"
    return False, "no payload field requires a specific literal of 8+ characters with structure"


def matches_benign_probe(event_type: str, filt: dict) -> Optional[str]:
    """The first ordinary request the filter matches, if any."""
    from app.services.correlation_engine import _matches_filter
    for path in BENIGN_PROBE_PATHS:
        ev = {
            "event_type": event_type, "source_ip": "192.0.2.1", "path": path,
            "request_path": path, "request_method": "GET", "response_status": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
        }
        try:
            if _matches_filter(ev, filt or {}):
                return path
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"^authored_[a-z0-9][a-z0-9_]{2,60}$")


def known_event_types() -> set[str]:
    from app.services.correlation_engine import _EVENT_TYPE_ALIASES, correlation_engine
    types = set(correlation_engine._rules_by_type) | set(_EVENT_TYPE_ALIASES)
    for alts in _EVENT_TYPE_ALIASES.values():
        types |= set(alts)
    return types


def existing_rule_ids() -> set[str]:
    from app.services.correlation_engine import correlation_engine
    ids = {r["id"] for r in correlation_engine._rules}
    ids |= {c["id"] for c in correlation_engine._chain_rules}
    ids |= set(registry.states())
    return ids


def validate(
    data: dict,
    *,
    existing_id_ok: bool = False,
    event_types: Optional[set[str]] = None,
    taken_ids: Optional[set[str]] = None,
) -> ValidationResult:
    """Validate a rule dict. ``existing_id_ok`` is set when updating a rule."""
    res = ValidationResult()
    if not isinstance(data, dict):
        res.add("schema", "rule must be a mapping")
        return res

    # --- id: identifier, namespace, collision --------------------------------
    rid = data.get("id")
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        res.add(
            "bad_id",
            f"id must match {_ID_RE.pattern} -- the 'authored_' namespace keeps runtime "
            f"rules from ever colliding with the CONFIRMED ids/prefixes in block_policy",
            "id",
        )
    elif not existing_id_ok and rid in (taken_ids if taken_ids is not None else existing_rule_ids()):
        res.add("id_collision", f"a rule with id '{rid}' already exists", "id")

    if data.get("kind", "sigma") != "sigma":
        res.add("schema", "only kind: sigma rules can be authored at runtime (chains are not supported)", "kind")
        return res

    # --- schema: the loader's own model --------------------------------------
    try:
        rule = Rule.model_validate({k: v for k, v in data.items() if k != "authoring"})
    except ValidationError as exc:
        for e in exc.errors():
            res.add("schema", e["msg"], ".".join(str(p) for p in e["loc"]))
        return res
    res.rule = rule

    cond = rule.condition
    filt = cond.filter or {}

    # The loader only WARNS about a filter clause the engine cannot honour and
    # keeps the rule (a dead clause degrades into an equality on a field nobody
    # emits). A rule authored at runtime has no one reading logs: refuse it.
    from app.services.correlation_engine import validate_filter
    for key, reason in validate_filter(filt):
        res.add("filter_vocabulary", f"filter key '{key}': {reason}", f"condition.filter.{key}")

    types = event_types if event_types is not None else known_event_types()
    if cond.event_type not in types:
        res.add(
            "unknown_event_type",
            f"event_type '{cond.event_type}' is not produced by any known source; "
            f"the rule would never receive an event",
            "condition.event_type",
        )

    # --- regex safety ---------------------------------------------------------
    for key, val in filt.items():
        if key.endswith("_regex"):
            problem = check_regex(val)
            if problem:
                res.add("unsafe_regex", f"{key}: {problem}", f"condition.filter.{key}")

    # --- genericity, by execution --------------------------------------------
    sev = rule.severity
    if not filt and sev in _HIGH:
        res.add("no_filter", f"a {sev} rule with no filter matches every {cond.event_type} event", "condition.filter")
    hit = matches_benign_probe(cond.event_type, filt)
    if hit is not None and not any(i.code == "no_filter" for i in res.issues):
        res.add(
            "too_generic",
            f"filter matches the ordinary request GET {hit} -- a rule that fires on a "
            f"normal visit will block normal visitors",
            "condition.filter",
        )

    # --- severity vs. evidence ------------------------------------------------
    sig, why = exploit_signature(filt)
    res.exploit_signature, res.signature_reason = sig, why
    threshold = cond.count_threshold if cond.count_threshold is not None else 1
    if sev in _HIGH and threshold <= 1 and not sig:
        res.add(
            "single_hit_severity",
            f"{sev} with count_threshold {threshold} needs an exploit-signature filter "
            f"({why}); one ordinary request must not earn a {sev}. Use a threshold >= 3 "
            f"or lower the severity",
            "severity",
        )
    if rule.chain_only:
        res.add("schema", "chain_only is not supported on authored rules", "chain_only", "warning")
    if not rule.description:
        res.add("no_description", "add a description saying what this detects and why", "description", "warning")
    return res
