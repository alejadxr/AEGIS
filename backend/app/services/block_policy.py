"""Block permanence policy: which blocks are forever and which expire.

The owner's rule is "if the attack is real, it should never be unblocked". A
block is therefore either

* CONFIRMED  -- exploit signatures and unambiguous malice. No legitimate user
  produces a web shell upload, a CVE exploit request or a read of /.env, so the
  block is permanent: no ``provisional`` flag, no ``expires_at``, no ``duration``
  sent to the Pi, never released by the retention job or the AI investigator.
* AMBIGUOUS  -- behavioural heuristics that real people trip: HTTP 401 brute
  force (a mistyped password behind an office NAT), request rate, port scans,
  DoS-shield rate blocks. These keep expiring, because they are the detections
  that have wrongly blocked the owner's own staff.

This module is the ONE place the split lives. ai_engine, retention,
ip_investigator and attack_detector all import it; do not copy the sets.

Unknown reasons default to AMBIGUOUS. A new rule or pattern that nobody has
classified yet must fail on the side the owner has actually been hurt on (a
wrong permanent block on his own people), not on the side that merely needs a
manual re-block. Adding a reason to CONFIRMED is a deliberate act.

An AMBIGUOUS block escalates to permanent once the source has been blocked
before (see ``escalate_after_prior``): a guess that repeats stops being a guess.
"""
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Iterable, NamedTuple, Optional

logger = logging.getLogger("cayde6.block_policy")

CONFIRMED = "confirmed"
AMBIGUOUS = "ambiguous"

# --- CONFIRMED -------------------------------------------------------------
# Exact identifiers, lowercased. Each comes from code that emits it:
CONFIRMED_IDS = frozenset({
    # attack_detector MEGA_PATTERN group names (the `name` in "name (severity)")
    "sql_injection", "command_injection", "path_traversal", "ssrf",
    # attack_detector breadcrumb trap: a planted credential was used
    "breadcrumb_credential_used",
    # playbook_engine.CONFIRMED_EXPLOIT_RULES / chain rule ids in app/rules
    "sql_injection_chain", "web_shell_activity", "rce", "rce_attempt",
    # honeypot: any interaction is malicious by definition
    # (playbook_engine rules + log_watcher label for port 2222)
    "ssh_honeypot_attempt", "ssh_honeypot_failure", "ssh_honeypot_brute",
    # Sigma rules (app/rules/sigma): exploit signatures, one match is enough
    "sigma_persist_webshell", "sigma_cloud_metadata_ssrf",
    "sigma_web_command_injection", "sigma_web_path_traversal", "sigma_web_ssrf",
    "sigma_web_file_upload", "sigma_web_sensitive_file_probe",
    "sigma_web_secret_harvest_instant",
    "sigma_web_deserialization", "sigma_web_xxe",
    "sigma_web_sqli_blind", "sigma_web_sqli_time", "sigma_web_sqli_union",
    "sigma_web_aver_ptc_cgi_rce", "sigma_web_baforms_upload_rce",
    "sigma_web_cpanel_whm_crlf", "sigma_web_drupal_jsonapi_sqli",
    "sigma_web_ghost_content_api_sqli", "sigma_web_icagenda_upload_rce",
    "sigma_web_ivanti_sentry_cmdinject", "sigma_web_jce_joomla_rce",
    "sigma_web_marimo_terminal_rce", "sigma_web_metabase_reset_sqli",
    "sigma_web_mirasvit_cachewarmer_deser", "sigma_web_nextjs_image_ssrf",
    "sigma_web_nextjs_rsc_rce", "sigma_web_nextjs_segment_prefetch_bypass",
    "sigma_web_nextjs_ws_ssrf", "sigma_web_panos_globalprotect_bypass",
    "sigma_web_pickle_rce_endpoint", "sigma_web_schneider_saitel_path_traversal",
    "sigma_web_splunk_postgres_recovery_rce", "sigma_web_vite_fs_disclosure",
    "sigma_web_vllm_ssrf_bypass",
})

# Whole families whose every rule is a named-vulnerability exploit signature.
CONFIRMED_PREFIXES = ("sigma_cve_", "sigma_ai_")

# ai_engine / block_ttl threat_type vocabulary (RESPONSE_ACTIONS keys,
# SIGMA_TO_THREAT_TYPE values, block_ttl._EXPLOIT_THREAT_TYPES).
CONFIRMED_THREAT_TYPES = frozenset({
    "sql_injection", "rce", "web_shell", "webshell", "command_injection",
    "path_traversal", "ssrf", "honeypot_recon",
})

# --- AMBIGUOUS (known) -----------------------------------------------------
# Not consulted by classify() -- anything not CONFIRMED is ambiguous -- but kept
# explicit so a reader can see these were decided, and so the test over
# app/rules can tell "decided" from "forgotten".
AMBIGUOUS_KNOWN = frozenset({
    "http_auth_brute", "ssh_real_brute", "http_auth_brute_force",
    "brute_force_ssh", "brute_force", "credential_stuffing", "rdp_brute_force",
    "generic_credential_attack", "auth_failure",
    "high_request_rate", "port_scan", "scanner",
    "xss", "xss_attack_chain", "sigma_web_xss_reflected", "sigma_web_xss_stored",
    "sigma_web_api_abuse", "sigma_web_csrf", "sigma_web_php_probe", "sigma_web_open_redirect",
    # Framework/debug endpoint recon (/actuator, /swagger, /graphql, /_cat/indices).
    # Low-severity visibility only: monitoring agents and API explorers hit these
    # legitimately, so a single request must never earn a permanent block. The
    # endpoints that actually disclose data (/actuator/env, /actuator/heapdump)
    # are CONFIRMED through sigma_cve_versa_concerto_2025_34026 instead.
    "sigma_web_framework_probe",
    "sigma_web_parametric_brute", "sigma_web_request_smuggling",
    "c2_beacon", "dns_tunneling", "data_exfiltration", "privilege_escalation",
    "lateral_movement",
})

_PREFIX_NOISE = ("aegis_auto_block:", "playbook:", "dos:")


class Classification(NamedTuple):
    kind: str            # CONFIRMED | AMBIGUOUS
    matched: str         # the identifier that decided it ("" when ambiguous by default)


def _tokens_from_reason(reason: Optional[str]) -> list[str]:
    """Identifiers inside a free-text block reason.

    attack_detector reasons look like "sql_injection (high)",
    "breadcrumb_credential_used (critical)", "brute_force (5 attempts)",
    "scanner User-Agent: ...", "firewall_rule:<name>".
    """
    if not reason or not isinstance(reason, str):
        return []
    text = reason.strip().lower()
    for noise in _PREFIX_NOISE:
        if text.startswith(noise):
            text = text[len(noise):].strip()
    base = text.split("(")[0].strip()
    return [base] if base else []


def classify(
    reason: Optional[str] = None,
    rule_ids: Iterable[str] = (),
    threat_type: Optional[str] = None,
) -> Classification:
    """CONFIRMED when ANY signal is a confirmed one, else AMBIGUOUS.

    One piece of exploit evidence outweighs any number of soft signals: an IP
    that tripped a rate limit AND fired a CVE rule is a CVE exploiter.
    """
    for token in (*_tokens_from_reason(reason), *(r.lower() for r in rule_ids if isinstance(r, str))):
        if token in CONFIRMED_IDS or token.startswith(CONFIRMED_PREFIXES):
            return Classification(CONFIRMED, token)
    tt = (threat_type or "").lower()
    if tt in CONFIRMED_THREAT_TYPES:
        return Classification(CONFIRMED, tt)
    return Classification(AMBIGUOUS, "")


def classify_alert(alert_data: Optional[dict], threat_type: Optional[str] = None) -> Classification:
    """Classify from an alert dict (pattern / rule_id / sigma_matches / threat_type)."""
    from app.services.block_ttl import collect_rule_ids
    alert = alert_data or {}
    return classify(
        reason=None,
        rule_ids=collect_rule_ids(alert),
        threat_type=threat_type or alert.get("threat_type"),
    )


# --- operator knobs --------------------------------------------------------

def _setting(name: str) -> str:
    """os.environ first (PM2), then pydantic settings (backend/.env never lands in os.environ)."""
    val = os.environ.get(name)
    if val is None:
        try:
            from app.config import settings
            val = getattr(settings, name, "") or ""
        except Exception:
            val = ""
    return val.strip()


def force_permanent() -> bool:
    """AEGIS_BLOCKS_PERMANENT=1: no block ever auto-releases. Read per call."""
    return _setting("AEGIS_BLOCKS_PERMANENT").lower() in ("1", "true", "yes", "on")


def escalate_after_prior() -> int:
    """How many earlier blocks (within the repeat window) make a block permanent.

    Default 1: the SECOND block of the same IP inside 30 days is permanent. The
    first ambiguous block is a guess and expires so a wrongly blocked colleague
    recovers on their own. A source that gets blocked, comes back after the
    release (or keeps firing while blocked), and trips a detector again is not
    a typo -- two independent triggers inside a month is the evidence the first
    block lacked. 30 days is block_ttl.REPEAT_WINDOW_DAYS, so repeat-offender
    accounting and escalation share one window. Raise it only if second-strike
    false positives show up in practice.
    """
    try:
        return max(1, int(_setting("AEGIS_BLOCK_ESCALATE_AFTER") or "1"))
    except ValueError:
        return 1


def decide_permanence(cls: Classification, prior_blocks: int) -> tuple[bool, str]:
    """(permanent, why) for a new block."""
    if force_permanent():
        return True, "AEGIS_BLOCKS_PERMANENT"
    if cls.kind == CONFIRMED:
        return True, f"confirmed:{cls.matched}"
    if prior_blocks >= escalate_after_prior():
        return True, f"escalated:{prior_blocks}_prior_blocks"
    return False, "ambiguous"


# --- exploit-probe evidence ------------------------------------------------
# Request-path evidence that someone went looking for secrets or tried an
# exploit. Used to veto a release even when the block REASON looked ambiguous
# (a 401 brute-forcer that also fetched /.env is not a typo).
_EXPLOIT_PROBE_RE = re.compile(
    r"/\.env\b|/\.git(?:/|-credentials)|/\.aws/|/\.ssh/|/\.npmrc|/\.htpasswd"
    r"|wp-config|/phpunit|eval-stdin|/etc/passwd|\.\./|%2e%2e"
    r"|169\.254\.169\.254|metadata\.google\.internal|\$\{jndi:"
    r"|(?:c99|r57|b374k|wso)\.php|/api/v1/validate/code|/secrets\.json",
    re.IGNORECASE,
)
_PROBE_LOOKBACK_DAYS = 90
_PROBE_MAX_INCIDENTS = 200
_PATH_KEYS = ("request_path", "path", "url", "log_line", "uri")


def probe_text_matches(text: str) -> Optional[str]:
    m = _EXPLOIT_PROBE_RE.search(text or "")
    return m.group(0) if m else None


def _incident_evidence(incident) -> Optional[str]:
    """Why this incident proves exploit activity, or None."""
    raw = incident.raw_alert if isinstance(incident.raw_alert, dict) else {}
    cls = classify_alert(raw)
    if cls.kind == CONFIRMED:
        return f"incident rule {cls.matched}"
    triage = (incident.ai_analysis or {}).get("triage") if isinstance(incident.ai_analysis, dict) else None
    if isinstance(triage, dict) and (triage.get("threat_type") or "").lower() in CONFIRMED_THREAT_TYPES:
        return f"incident threat_type {triage['threat_type']}"
    for key in _PATH_KEYS:
        hit = probe_text_matches(str(raw.get(key) or ""))
        if hit:
            return f"request {hit!r}"
    hit = probe_text_matches(f"{incident.title or ''} {incident.description or ''}")
    return f"incident text {hit!r}" if hit else None


async def probe_evidence(db, ip: str) -> Optional[str]:
    """Observed exploit activity on record for `ip`, or None.

    Looks at past block actions (a CONFIRMED class already stamped) and past
    incidents (rule ids, threat type, request paths). An LLM verdict must never
    override this.
    """
    from sqlalchemy import select
    from app.models.action import Action
    from app.models.incident import Incident

    actions = (await db.execute(
        select(Action).where(Action.action_type == "block_ip", Action.target == ip)
    )).scalars().all()
    for a in actions:
        if (a.parameters or {}).get("block_class") == CONFIRMED:
            return f"prior block classified confirmed ({a.parameters.get('block_class_reason', '')})"

    since = datetime.utcnow() - timedelta(days=_PROBE_LOOKBACK_DAYS)
    incidents = (await db.execute(
        select(Incident)
        .where(Incident.source_ip == ip, Incident.detected_at >= since)
        .order_by(Incident.detected_at.desc())
        .limit(_PROBE_MAX_INCIDENTS)
    )).scalars().all()
    for inc in incidents:
        why = _incident_evidence(inc)
        if why:
            return why
    return None


# --- live-action bookkeeping ----------------------------------------------

def action_is_live(action, now: Optional[datetime] = None) -> bool:
    """True when this block_ip Action currently covers its IP."""
    if action.status not in ("approved", "executed"):
        return False
    params = action.parameters or {}
    if params.get("expired_at"):
        return False
    if not params.get("provisional"):
        return True     # permanent (or legacy unstamped) block
    raw = params.get("expires_at")
    if not raw:
        return True
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "")) > (now or datetime.utcnow())
    except (ValueError, TypeError):
        return True     # unparseable expiry: never treat as lapsed


async def live_block_actions(db, ip: str, exclude_id: Optional[str] = None) -> list:
    """block_ip Actions that currently cover `ip`, oldest first."""
    from sqlalchemy import select
    from app.models.action import Action

    rows = (await db.execute(
        select(Action)
        .where(Action.action_type == "block_ip", Action.target == ip,
               Action.status.in_(("approved", "executed")))
        .order_by(Action.created_at.asc())
    )).scalars().all()
    now = datetime.utcnow()
    return [a for a in rows if str(a.id) != str(exclude_id) and action_is_live(a, now)]


def make_permanent(action, why: str, kind: str = CONFIRMED) -> None:
    """Strip the expiry from `action` in place (caller commits)."""
    params = dict(action.parameters or {})
    for k in ("provisional", "expires_at", "ttl_hours"):
        params.pop(k, None)
    params.update({"permanent": True, "block_class": kind, "block_class_reason": why})
    action.parameters = params     # reassign so SQLAlchemy sees the JSON change
