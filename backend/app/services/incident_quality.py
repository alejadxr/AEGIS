"""Incident quality: burst merging, evidence-gated wording, evidence-gated severity.

Three problems share this module because they share one input, the alert as the
detectors saw it:

1. One attacker burst became 5-15 incidents. `merge_into_incident` folds a new
   match into the burst's incident (lookup: firewall_sync.find_mergeable_incident).
2. Titles/descriptions claimed success ("successfully accessed the metadata
   endpoint") with nothing behind it. `describe_without_overclaim` only lets a
   success claim through when a 2xx response status backs it.
3. Probes for software that is not installed were rated CRITICAL.
   `apply_probe_evidence` drops the severity one level when the response status
   proves the probe could not have worked.

The evidence is the HTTP response status of the probed request. AEGIS has no
usable software inventory to cross-check against: `Asset.technologies` is
filled by nmap/nuclei fingerprinting of scanned hosts, not by what each PM2 app
actually ships, so "product X is absent" cannot be derived from it. The status
signal is therefore the only one used, and a missing status is never a signal.
"""

import asyncio
import copy
import re
from datetime import datetime
from typing import Optional

_LADDER = ("low", "medium", "high", "critical")

# Rule titles kept per incident. A wide scanner can match dozens of rules; the
# list stays bounded so the JSON column does not grow with the attack.
MAX_MATCHED_RULES = 50
_DESC_MARKER = "Matched rules"
_DESC_SHOWN = 20


def _severity_rank(severity: Optional[str]) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity or "", 0)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------

def _context(alert: Optional[dict]) -> dict:
    """The alert flattened with its triggering event, event fields winning.

    Correlation alerts nest the raw event under `triggering_event`; log_watcher
    and fast_triage carry the request fields at the top level.
    """
    alert = alert or {}
    event = alert.get("triggering_event")
    if isinstance(event, dict):
        return {**alert, **event}
    return alert


def response_status(alert: Optional[dict]) -> Optional[int]:
    """HTTP status of the probed request, or None when it is not known."""
    ctx = _context(alert)
    for key in ("response_status", "status_code"):
        value = ctx.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def is_http_probe(alert: Optional[dict]) -> bool:
    ctx = _context(alert)
    return bool(ctx.get("request_path") or ctx.get("request_method"))


def is_host_incident(alert: Optional[dict]) -> bool:
    """EDR / host-attributed detections. They have no HTTP status to judge."""
    ctx = _context(alert)
    if str(ctx.get("source") or "").lower() == "edr":
        return True
    return bool((ctx.get("host") or ctx.get("hostname")) and not ctx.get("source_ip"))


def probe_failed(alert: Optional[dict]) -> bool:
    """True only when the response proves the probe could not have worked.

    404/410 mean the requested path does not exist on the target. A missing
    status is NOT failure evidence (absence of evidence is not evidence), and a
    2xx is the opposite, so neither downgrades.
    """
    if is_host_incident(alert):
        return False
    return response_status(alert) in (404, 410)


def incident_target(alert: Optional[dict]) -> Optional[str]:
    """What is being attacked: the host, else the app that logged the request."""
    ctx = _context(alert)
    for key in ("host", "hostname", "target", "app"):
        value = ctx.get(key)
        if value:
            return str(value)
    value = ctx.get("source")
    # `source` doubles as the detector name on alert_data; only the raw event's
    # `source` (the PM2 app) names a target.
    if value and value not in ("correlation_engine", "correlation_engine_chain", "log_watcher", "fast_triage"):
        return str(value)
    return None


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def downgrade_severity(severity: str) -> str:
    """One level down, never below low. Unknown levels are returned as is."""
    if severity not in _LADDER:
        return severity
    return _LADDER[max(0, _LADDER.index(severity) - 1)]


def apply_probe_evidence(alert: Optional[dict], severity: str, description: str) -> tuple[str, str]:
    """Lower `severity` one level when the response shows the probe failed.

    Returns (severity, description) with the reason appended, so the operator
    sees both the lower rating and why it is not the rule's static one.
    """
    if not probe_failed(alert) or severity not in _LADDER or severity == "low":
        return severity, description
    status = response_status(alert)
    lowered = downgrade_severity(severity)
    note = (
        f"Severity lowered {severity} -> {lowered}: the target answered {status}, "
        f"so the probed path does not exist there and the attempt did not reach "
        f"a live endpoint."
    )
    return lowered, f"{description} {note}".strip()


def retitle_severity(title: str, old: str, new: str) -> str:
    """Swap the leading 'SEVERITY: ' prefix the detectors put on titles."""
    prefix = f"{old.upper()}: "
    if title.startswith(prefix):
        return f"{new.upper()}: {title[len(prefix):]}"
    return title


# ---------------------------------------------------------------------------
# Wording
# ---------------------------------------------------------------------------

# Past-tense success verbs -> the attempt wording. The model is told not to
# claim success without evidence, but it does not always obey, so this is the
# backstop that runs on whatever text comes back.
_VERB_TO_ATTEMPT = {
    "accessed": "attempted to access", "exploited": "attempted to exploit",
    "compromised": "attempted to compromise", "executed": "attempted to execute",
    "retrieved": "attempted to retrieve", "obtained": "attempted to obtain",
    "uploaded": "attempted to upload", "bypassed": "attempted to bypass",
    "gained": "attempted to gain", "read": "attempted to read",
    "extracted": "attempted to extract", "authenticated": "attempted to authenticate",
    "deployed": "attempted to deploy", "installed": "attempted to install",
    "injected": "attempted to inject", "triggered": "attempted to trigger",
}
_SUCCESSFULLY_VERB = re.compile(
    r"\bsuccessfully\s+(" + "|".join(_VERB_TO_ATTEMPT) + r")\b", re.IGNORECASE
)
_SUCCESSFULLY_ANY = re.compile(r"\bsuccessfully\s+", re.IGNORECASE)
_SUCCESSFUL_STATUS = re.compile(
    r"\b(?:a\s+)?successful\s+(?:HTTP\s+)?(?:status\s+)?(?:code\s+)?\d{3}(?:\s+(?:OK|response|status))?",
    re.IGNORECASE,
)
_SUCCESSFUL_ANY = re.compile(r"\bsuccessful(?:ly)?\b", re.IGNORECASE)


def _is_2xx(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


def claims_success(text: Optional[str]) -> bool:
    return bool(text and _SUCCESSFUL_ANY.search(text))


def describe_without_overclaim(text: Optional[str], alert: Optional[dict]) -> Optional[str]:
    """Strip success claims the evidence does not support.

    Applies to HTTP probes only: "successful login after brute force" on SSH or
    an auth chain is a different claim, backed by auth events rather than a
    response status, and must not be rewritten. For a probe, success is
    evidenced by a 2xx response on the probed path and nothing else. A missing
    status therefore reads as an attempt, the same as a 404.
    """
    if not text or not is_http_probe(alert) or _is_2xx(response_status(alert)):
        return text
    if not claims_success(text):
        return text
    status = response_status(alert)
    out = _SUCCESSFULLY_VERB.sub(lambda m: _VERB_TO_ATTEMPT[m.group(1).lower()], text)
    out = _SUCCESSFUL_STATUS.sub(f"a {status} response" if status else "a response", out)
    out = _SUCCESSFULLY_ANY.sub("", out)
    out = _SUCCESSFUL_ANY.sub("attempted", out)
    return out


# Added to the AI prompts (triage and classification) so the model is told the
# rule up front; describe_without_overclaim still runs on what comes back.
EVIDENCE_PROMPT_RULE = (
    "Wording rule: describe an HTTP probe as an attempt unless the alert's "
    "response_status is a 2xx on the probed path. Never write 'successfully', "
    "'successful', 'compromised' or 'exploited' for a request whose "
    "response_status is missing, 4xx or 5xx; say 'attempted' or 'probed'. A "
    "404/410 means the probed software or path is not present."
)


# ---------------------------------------------------------------------------
# Burst merging
# ---------------------------------------------------------------------------

# One lock per attacker key. The rules of a burst fire within milliseconds of
# each other, each in its own asyncio task; without serialising the
# find-then-create step, all of them would look, find nothing, and each open an
# incident, which is exactly the split being fixed.
_locks: dict[str, asyncio.Lock] = {}


def burst_lock(source_ip: Optional[str], host: Optional[str]) -> asyncio.Lock:
    key = f"{source_ip or ''}|{host or ''}"
    lock = _locks.get(key)
    if lock is None:
        if len(_locks) > 2048:
            for k in [k for k, v in _locks.items() if not v.locked()]:
                del _locks[k]
        lock = _locks[key] = asyncio.Lock()
    return lock


def last_activity(incident) -> datetime:
    """When the incident last absorbed a match (its detection time before any)."""
    last = ((incident.ai_analysis or {}).get("dedup") or {}).get("last_seen")
    if last:
        try:
            return datetime.fromisoformat(last)
        except (TypeError, ValueError):
            pass
    return incident.detected_at or datetime.utcnow()


def _title_of(incident) -> str:
    title = incident.title or ""
    return re.sub(r"^(?:CRITICAL|HIGH|MEDIUM|LOW|INFO):\s*", "", title)


def _render_matched(matched: list[dict]) -> str:
    shown = "; ".join(m["title"] or m["id"] for m in matched[:_DESC_SHOWN])
    more = f" (+{len(matched) - _DESC_SHOWN} more)" if len(matched) > _DESC_SHOWN else ""
    return f"{_DESC_MARKER} ({len(matched)}): {shown}{more}"


def merge_into_incident(
    incident,
    *,
    rule_id: Optional[str],
    rule_title: Optional[str],
    severity: Optional[str],
) -> None:
    """Fold one more match into an existing incident (caller commits).

    Never loses information and never lowers urgency:
    - the matched rule ids/titles accumulate in ai_analysis.matched_rules and
      are echoed in the description, so a merge cannot hide which CVEs were
      probed;
    - severity only goes up (a critical after a high upgrades, the reverse is
      ignored), and the title's severity prefix follows it.

    ai_analysis is rebuilt as a NEW dict: the JSON column is not a mutable
    type, so editing the loaded dict in place and assigning it back looks like
    "no change" to SQLAlchemy and the UPDATE is silently skipped.
    """
    now = datetime.utcnow()
    analysis = copy.deepcopy(incident.ai_analysis or {})

    dedup = analysis.get("dedup") or {
        "count": 1,
        "first_seen": (incident.detected_at or now).isoformat(),
    }
    dedup["count"] = dedup.get("count", 1) + 1
    dedup["last_seen"] = now.isoformat()
    dedup["last_rule"] = rule_id
    analysis["dedup"] = dedup

    matched = analysis.get("matched_rules")
    if not matched:
        # Seed with what the incident was opened for, so the list is complete
        # even for incidents created before this existed.
        first_id = (
            (incident.raw_alert or {}).get("pattern")
            or analysis.get("rule_id")
            or (analysis.get("_origin") or {}).get("rule")
        )
        # The rule's own title, not the incident title: on the AI path the
        # incident title is the model's free-text summary.
        first_title = (incident.raw_alert or {}).get("rule_title") or _title_of(incident)
        matched = [{"id": first_id, "title": first_title, "severity": incident.severity, "hits": 1}]
    known = next((m for m in matched if m["id"] == rule_id and rule_id), None)
    if known is not None:
        known["hits"] = known.get("hits", 1) + 1
        if _severity_rank(severity) > _severity_rank(known.get("severity")):
            known["severity"] = severity
    elif len(matched) < MAX_MATCHED_RULES:
        matched.append({"id": rule_id, "title": rule_title or rule_id, "severity": severity, "hits": 1})
    analysis["matched_rules"] = matched
    incident.ai_analysis = analysis

    if severity and _severity_rank(severity) > _severity_rank(incident.severity):
        incident.title = retitle_severity(incident.title or "", incident.severity, severity)
        incident.severity = severity

    base = incident.description or ""
    if _DESC_MARKER in base:
        base = base[: base.index(_DESC_MARKER)].rstrip()
    incident.description = f"{base}\n\n{_render_matched(matched)}".strip()
