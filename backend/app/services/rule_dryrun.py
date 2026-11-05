"""Replay a candidate rule over recent real traffic before it may be enabled.

THIS IS THE CORE SAFETY FEATURE of rule authoring. It exists because this
platform has blocked its own operator and his customers more than once: his
home and office IPs for months, five WARP / Private Relay addresses carrying
thousands of users each, and ordinary requests that a loose CVE rule or a bare
``localhost`` substring happened to match. A rule that is merely well-formed
can still be the next one. So before a rule may be enabled we answer, from
data, "who would this have caught in the last few hours?" -- and refuse when
the answer includes someone AEGIS must never act against.

Where the events come from (cheapest honest sources, in priority order)
----------------------------------------------------------------------
1. ``pm2_logs`` -- a bounded tail of the same PM2 log files ``log_watcher``
   reads, run through ``event_normalizer.normalize``. This is the ONLY source
   that still contains the owner's and customers' own requests: ``log_watcher``
   drops safelisted/internal IPs BEFORE the event reaches the correlation
   engine, so the engine never sees them. Replaying only the engine's feed
   would make every owner IP invisible and the check vacuous.
2. ``live_window`` -- ``correlation_engine._window`` (<= 10k events, already
   gated). Used only when no PM2 logs are readable (journalctl hosts, dev).
3. ``incidents`` -- ``raw_alert`` of incidents from the last 30 days. Long
   memory, but biased to attacks and it only holds what already alerted. It
   covers days where the log tail covers hours, and it is where the old
   "owner IP raised incidents for months" evidence lives.

Every report states each source's event count and time span, so a reviewer can
see how much evidence stands behind "clean".

What counts as a protected IP
-----------------------------
Existing predicates, no new policy: ``AEGIS_INTERNAL_IPS`` (owner/customer
addresses an operator listed), ``attack_detector.is_shared_egress`` (WARP /
Private Relay / ``AEGIS_SHARED_EGRESS_IPS``), and ``attack_detector._is_safe_ip``
(``AEGIS_SAFE_IPS``, RFC1918/CGNAT/Tailscale, published crawler ranges).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from app.schemas.rule_authoring import (
    BaselineOut, CorpusOut, DryRunOut, FlaggedIpOut, SampleMatchOut, TopIpOut,
)

logger = logging.getLogger("aegis.rule_dryrun")

# Below this many primary events "nothing matched" proves nothing: refuse to
# call it clean rather than report a green light backed by 12 log lines.
MIN_EVIDENCE_EVENTS = 50
TAIL_BYTES_PER_FILE = 2_000_000
MAX_LOG_LINES = 20_000
INCIDENT_LOOKBACK_DAYS = 30
INCIDENT_LIMIT = 1500
# Empirical genericity: a filter that hits this share of ordinary traffic (and
# at least BASELINE_MIN_HITS requests) is describing normal visits, not attacks.
BASELINE_MAX_RATIO = 0.01
BASELINE_MIN_HITS = 5
SAMPLE_LIMIT = 10
FLAGGED_LIMIT = 25

_CLF_TS = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
_ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")


# ---------------------------------------------------------------------------
# IP classification (existing predicates only)
# ---------------------------------------------------------------------------

def _owner_lists():
    from app.core.attack_detector import _parse_ip_safelist_env
    return _parse_ip_safelist_env("AEGIS_INTERNAL_IPS")


def categorize_ip(ip: Optional[str]) -> Optional[str]:
    """owner_or_customer | shared_egress | safelisted | None (an ordinary IP)."""
    if not ip or not isinstance(ip, str):
        return None
    import ipaddress
    from app.core.attack_detector import _is_safe_ip, is_shared_egress

    literals, nets = _owner_lists()
    if ip in literals:
        return "owner_or_customer"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    if addr is not None and any(addr in n for n in nets):
        return "owner_or_customer"
    # Addresses the operator put in AEGIS_SHARED_EGRESS_IPS are his customers'
    # and staff; the built-in WARP / Private Relay ranges are anonymous crowds.
    # Hitting the first is "this rule would act on a CUSTOMER", a different
    # decision from hitting a WARP exit, so they are reported apart.
    from app.core import attack_detector as _ad
    if ip in _ad._shared_egress_literals:
        return "customer"
    if addr is not None and any(addr in n for n in _ad._shared_egress_env_nets):
        return "customer"
    if is_shared_egress(ip):
        return "shared_egress"
    if _is_safe_ip(ip):
        return "safelisted"
    return None


def _redact_path(path: Optional[str]) -> Optional[str]:
    """Keep parameter names, drop values: tokens ride in query strings."""
    if not path:
        return path
    base, sep, query = str(path).partition("?")
    if not sep:
        return base[:300]
    names = [p.split("=", 1)[0] for p in query.split("&") if p]
    return (base + "?" + "&".join(f"{n}=***" for n in names))[:300]


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------

class _Ev:
    __slots__ = ("ev", "ts", "source")

    def __init__(self, ev: dict, ts: Optional[float], source: str):
        self.ev, self.ts, self.source = ev, ts, source


def _line_ts(line: str) -> Optional[float]:
    m = _CLF_TS.search(line)
    if m:
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%d/%b/%Y:%H:%M:%S %z").timestamp()
        except ValueError:
            return None
    m = _ISO_TS.search(line)
    if m:
        try:
            return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    return None


def _tail_lines(path: Path, max_bytes: int) -> list[str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()           # drop the partial first line
            data = fh.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def load_pm2_events(logs_dir: Optional[str] = None) -> tuple[list[_Ev], str]:
    """Normalized events from a bounded tail of the PM2 logs. Blocking I/O."""
    from app.services.event_normalizer import normalize

    d = Path(os.path.expanduser(logs_dir or os.environ.get("AEGIS_PM2_LOGS_DIR", "~/.pm2/logs")))
    if not d.is_dir():
        return [], f"no PM2 log directory at {d}"
    apps = [a.strip() for a in (os.environ.get("AEGIS_MONITORED_APPS") or "").split(",") if a.strip()]
    files = sorted(d.glob("*-out.log")) + sorted(d.glob("*-error.log"))
    if apps:
        files = [f for f in files if any(f.name.startswith(f"{a}-") for a in apps)]
    out: list[_Ev] = []
    for f in files:
        app = f.name.rsplit("-", 1)[0]
        for line in _tail_lines(f, TAIL_BYTES_PER_FILE)[-MAX_LOG_LINES:]:
            if len(out) >= MAX_LOG_LINES * 2:
                break
            try:
                ev = normalize(line, source=app)
            except Exception:
                continue
            if ev:
                out.append(_Ev(ev, _line_ts(line), "pm2_logs"))
    note = f"tail of {len(files)} PM2 log file(s), up to {TAIL_BYTES_PER_FILE // 1000} KB each"
    return out, note


def load_window_events() -> list[_Ev]:
    from app.services.correlation_engine import correlation_engine
    return [_Ev(dict(ev), ts, "live_window") for ts, ev in list(correlation_engine._window)]


async def load_incident_events(db, client_id: Optional[str] = None) -> list[_Ev]:
    from sqlalchemy import select
    from app.models.incident import Incident

    since = datetime.utcnow() - timedelta(days=INCIDENT_LOOKBACK_DAYS)
    q = select(Incident).where(Incident.detected_at >= since)
    if client_id:
        q = q.where(Incident.client_id == client_id)
    rows = (await db.execute(q.order_by(Incident.detected_at.desc()).limit(INCIDENT_LIMIT))).scalars().all()
    out: list[_Ev] = []
    for inc in rows:
        raw = inc.raw_alert if isinstance(inc.raw_alert, dict) else {}
        trig = raw.get("triggering_event")
        ev = dict(trig) if isinstance(trig, dict) else dict(raw)
        ev.setdefault("source_ip", inc.source_ip)
        ev.setdefault("event_type", raw.get("event_type") or "http_request")
        ts = inc.detected_at.replace(tzinfo=timezone.utc).timestamp() if inc.detected_at else None
        out.append(_Ev(ev, ts, "incidents"))
    return out


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def _fields(ev: dict) -> tuple[Optional[str], Optional[str], Optional[int]]:
    path = ev.get("request_path") or ev.get("path") or ev.get("url")
    method = ev.get("request_method") or ev.get("method")
    status = ev.get("response_status") if ev.get("response_status") is not None else ev.get("status")
    return path, method, status if isinstance(status, int) else None


def _is_baseline(e: _Ev) -> bool:
    """A request nothing suggests is hostile (or one from a protected IP)."""
    if categorize_ip(e.ev.get("source_ip")):
        return True
    _, _, status = _fields(e.ev)
    return e.ev.get("pattern_name") is None and (status is None or status < 400) and e.source != "incidents"


def _replay(rule: Any, events: list[_Ev]) -> tuple[list[_Ev], dict[str, int]]:
    """(filter matches, {ip: events} for groups that would raise an incident).

    Uses the engine's own ``_matches_filter`` / ``_event_type_satisfies`` so the
    replay cannot disagree with production about what a filter means. Cooldown
    is ignored: a dry run should over-report, never under-report.
    """
    from app.services.correlation_engine import _event_type_satisfies, _matches_filter

    cond = rule.condition
    filt = cond.filter or {}
    threshold = cond.count_threshold if cond.count_threshold is not None else 1
    window = cond.time_window_seconds or 60
    group_by = cond.group_by or "source_ip"
    uniq = cond.unique_field

    matched: list[_Ev] = []
    for e in events:
        if not _event_type_satisfies(e.ev.get("event_type", ""), cond.event_type):
            continue
        try:
            if filt and not _matches_filter(e.ev, filt):
                continue
        except Exception:
            continue
        matched.append(e)

    firing: dict[str, int] = {}
    if threshold <= 1:
        for e in matched:
            ip = e.ev.get("source_ip")
            if ip:
                firing[ip] = firing.get(ip, 0) + 1
        return matched, firing

    groups: dict[str, deque] = defaultdict(deque)
    fired: set[str] = set()
    ordered = sorted(matched, key=lambda e: (e.ts is None, e.ts or 0))
    for e in ordered:
        key = e.ev.get(group_by) if isinstance(group_by, str) else None
        if key is None:
            continue
        key = str(key)
        dq = groups[key]
        dq.append((e.ts, e.ev.get(uniq) if uniq else id(e)))
        if e.ts is not None:
            while dq and dq[0][0] is not None and e.ts - dq[0][0] > window:
                dq.popleft()
        if len({v for _, v in dq}) >= threshold:
            fired.add(key)
    for e in matched:
        ip = e.ev.get("source_ip")
        k = e.ev.get(group_by) if isinstance(group_by, str) else None
        if ip and k is not None and str(k) in fired:
            firing[ip] = firing.get(ip, 0) + 1
    return matched, firing


def _corpus_info(source: str, events: list[_Ev], note: str = "") -> CorpusOut:
    stamps = [e.ts for e in events if e.ts]
    # correlation_engine stamps with naive-UTC .timestamp() (local-interpreted),
    # so fromtimestamp() round-trips it; other sources are true UTC epochs.
    conv = (datetime.fromtimestamp if source == "live_window"
            else (lambda t: datetime.fromtimestamp(t, timezone.utc).replace(tzinfo=None)))
    oldest = conv(min(stamps)) if stamps else None
    newest = conv(max(stamps)) if stamps else None
    if not stamps and events:
        note = (note + "; " if note else "") + "lines carry no timestamp, time span unknown"
    return CorpusOut(
        source=source, events=len(events), oldest=oldest, newest=newest,
        covers_seconds=(max(stamps) - min(stamps)) if stamps else None, note=note,
    )


def run_replay(rule: Any, corpora: dict[str, list[_Ev]], notes: Optional[dict[str, str]] = None) -> DryRunOut:
    """Pure function: replay ``rule`` over already-loaded corpora."""
    notes = notes or {}
    primary_name = "pm2_logs" if corpora.get("pm2_logs") else "live_window"
    primary = corpora.get(primary_name, [])
    seen = {(e.ev.get("source_ip"), _fields(e.ev)[0], _fields(e.ev)[1]) for e in primary}
    incidents = [e for e in corpora.get("incidents", [])
                 if (e.ev.get("source_ip"), _fields(e.ev)[0], _fields(e.ev)[1]) not in seen]

    used = [(primary_name, primary)] + [("incidents", incidents)]
    all_events: list[_Ev] = []
    matches: list[_Ev] = []
    firing: Counter = Counter()
    for name, evs in used:
        all_events += evs
        m, f = _replay(rule, evs)
        matches += m
        firing.update(f)

    ips = Counter(e.ev.get("source_ip") for e in matches if e.ev.get("source_ip"))
    cats = {ip: categorize_ip(ip) for ip in set(ips) | set(firing)}

    flagged: list[FlaggedIpOut] = []
    flagged_matches = 0
    for ip, n in firing.most_common():
        cat = cats.get(ip)
        if not cat:
            continue
        paths = []
        for e in matches:
            if e.ev.get("source_ip") == ip:
                p = _redact_path(_fields(e.ev)[0])
                if p and p not in paths:
                    paths.append(p)
            if len(paths) >= 3:
                break
        flagged.append(FlaggedIpOut(ip=ip, category=cat, matches=n, sample_paths=paths))
        flagged_matches += n

    baseline_events = [e for e in (primary + incidents) if _is_baseline(e)]
    baseline_matched = sum(1 for e in matches if _is_baseline(e))
    ratio = (baseline_matched / len(baseline_events)) if baseline_events else 0.0
    too_generic = baseline_matched >= BASELINE_MIN_HITS and ratio > BASELINE_MAX_RATIO

    reasons: list[str] = []
    overridable = True
    verdict = "clean"
    if too_generic:
        verdict, overridable = "blocked", False
        reasons.append(
            f"matches {baseline_matched} of {len(baseline_events)} ordinary requests "
            f"({ratio:.1%}): the filter describes normal traffic, not an attack"
        )
    if flagged:
        verdict = "blocked"
        by_cat = Counter(f.category for f in flagged)
        reasons.append(
            "would have matched protected addresses: "
            + ", ".join(f"{n} {c}" for c, n in by_cat.items())
            + " -- AEGIS has blocked its own operator and shared-egress users this way before"
        )
    if len(primary) < MIN_EVIDENCE_EVENTS and verdict == "clean":
        verdict = "insufficient_evidence"
        reasons.append(
            f"only {len(primary)} recent events available (< {MIN_EVIDENCE_EVENTS}); "
            f"'no protected IP matched' proves nothing on so little traffic"
        )

    cond = rule.condition
    thr = cond.count_threshold if cond.count_threshold is not None else 1
    note = (
        "single-event rule: every match would raise an incident" if thr <= 1 else
        f"needs {thr} hits per {cond.group_by or 'source_ip'} within {cond.time_window_seconds or 60}s; "
        f"flagged/firing figures count only groups that reach it"
    )

    samples = []
    for e in matches[:SAMPLE_LIMIT]:
        p, mth, st = _fields(e.ev)
        ip = e.ev.get("source_ip")
        ts = None
        if e.ts:
            ts = datetime.fromtimestamp(e.ts) if e.source == "live_window" \
                else datetime.fromtimestamp(e.ts, timezone.utc).replace(tzinfo=None)
        samples.append(SampleMatchOut(
            source=e.source, source_ip=ip, category=cats.get(ip), method=mth,
            path=_redact_path(p), status=st, user_agent=(e.ev.get("user_agent") or None), timestamp=ts,
        ))

    infos = [_corpus_info(primary_name, primary, notes.get(primary_name, ""))]
    if corpora.get("incidents") is not None:
        infos.append(_corpus_info("incidents", incidents,
                                  f"{INCIDENT_LOOKBACK_DAYS}-day incident history, deduplicated against {primary_name}"))

    return DryRunOut(
        verdict=verdict,
        can_enable=verdict == "clean",
        overridable=overridable and verdict != "clean",
        reasons=reasons,
        events_scanned=len(all_events),
        corpora=infos,
        matches=len(matches),
        distinct_ips=len(ips),
        firing_ips=len(firing),
        threshold_note=note,
        flagged_ips=flagged[:FLAGGED_LIMIT],
        flagged_matches=flagged_matches,
        baseline=BaselineOut(events=len(baseline_events), matched=baseline_matched,
                             ratio=round(ratio, 4), too_generic=too_generic),
        top_ips=[TopIpOut(ip=ip, matches=n, category=cats.get(ip)) for ip, n in ips.most_common(10)],
        sample_matches=samples,
        generated_at=datetime.utcnow(),
    )


async def dry_run(rule: Any, db=None, client_id: Optional[str] = None) -> DryRunOut:
    """Load the corpora and replay. ``rule`` is a validated ``Rule``."""
    pm2, pm2_note = await asyncio.to_thread(load_pm2_events)
    corpora: dict[str, list[_Ev]] = {}
    notes: dict[str, str] = {}
    if pm2:
        corpora["pm2_logs"], notes["pm2_logs"] = pm2, pm2_note
    else:
        corpora["live_window"] = load_window_events()
        notes["live_window"] = f"in-memory engine window (post-safelist: owner IPs are absent); {pm2_note}"
    if db is not None:
        try:
            corpora["incidents"] = await load_incident_events(db, client_id)
        except Exception as exc:
            logger.warning(f"dry-run could not read incident history: {exc}")
            corpora["incidents"] = []
    return run_replay(rule, corpora, notes)
