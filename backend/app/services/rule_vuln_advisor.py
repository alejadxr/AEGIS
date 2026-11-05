"""\"Protect me from this vulnerability\": from a CVE or a description to a rule.

Most of this estate's incidents are probes for software the owner does not run.
A detection rule for absent software is pure noise (and noise is what produced
the false positives this whole capability is fenced against), so the FIRST
question is "does this even apply to me?", and "not applicable" is a first-class
answer that produces no rule.

Nothing here invents advisory content. There is no advisory feed in this build,
so the only verified source is the rule pack itself: if a shipped rule already
names the CVE, its filter is verified detection logic. Everything derived from
the caller's own text (paths, methods, parameters, software names) is labelled
UNVERIFIED in the response and in the audit record, because AEGIS cannot tell a
careful advisory paste from a rumour. A CVE id with no local rule and no
description yields "unknown" and asks for the advisory, rather than guessing a
product from the number.

Only HTTP-log-visible indicators become rule clauses. AEGIS' normalized web
event carries method, path (with query string), status and User-Agent -- not
arbitrary request headers or bodies -- so a header or body indicator is listed
as NOT detectable instead of silently dropped or, worse, written into a filter
that can never match.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from app.schemas.rule_authoring import (
    ConditionIn, IndicatorOut, ProposalOut, ProtectIn, ProtectOut, RuleDraft,
)
from app.services import authored_rules_registry as registry
from app.services import rule_authoring, rule_validation

_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")
_PATH_RE = re.compile(r"(?<![\w:/.\-])(/[A-Za-z0-9_\-./%{}~]{2,}(?:\?[A-Za-z0-9_\-=&%]*)?)")
_HEADER_RE = re.compile(r"\b(X-[A-Za-z0-9\-]+|Authorization|Cookie|Content-Type|Host|Referer|Transfer-Encoding|Origin)\b")
_PARAM_RE = re.compile(r"\bparam(?:eter)?\s+(?:named\s+)?[`'\"]?([A-Za-z_][A-Za-z0-9_]{1,40})|\?([A-Za-z_][A-Za-z0-9_]{1,40})=")

UNVERIFIED_NOTICE = (
    "UNVERIFIED: these indicators come from text you supplied, not from a verified "
    "advisory (this build has no advisory feed). Check the vendor advisory before "
    "enabling anything derived from them."
)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9.]+", " ", s.lower()).strip()


async def stack_inventory(db, client_id: Optional[str], override: Optional[list[str]]) -> list[str]:
    """Names of software the owner runs: explicit list, else assets + AEGIS_STACK."""
    if override is not None:
        return sorted({_norm(s) for s in override if s and _norm(s)})
    names: set[str] = set()
    for raw in (os.environ.get("AEGIS_STACK") or "").split(","):
        if _norm(raw):
            names.add(_norm(raw))
    if db is not None and client_id:
        try:
            from sqlalchemy import select
            from app.models.asset import Asset
            rows = (await db.execute(select(Asset.technologies).where(Asset.client_id == client_id))).scalars().all()
            for techs in rows:
                for t in techs or []:
                    nm = t.get("name") if isinstance(t, dict) else t
                    if isinstance(nm, str) and _norm(nm):
                        names.add(_norm(nm))
        except Exception:
            pass
    return sorted(names)


def _stack_hits(stack: list[str], haystack: str) -> list[str]:
    hay = _norm(haystack)
    hits = []
    for name in stack:
        if len(name) < 3:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(name) + r"(?![a-z0-9])", hay):
            hits.append(name)
    return hits


def _covering_rules(cve_id: str) -> list:
    """Shipped/authored rules that already name this CVE."""
    from app.services.correlation_engine import correlation_engine as eng
    needle_us = cve_id.lower().replace("-", "_")
    needle = cve_id.lower()
    out = []
    for r in eng._rules:
        blob = " ".join(str(x) for x in (
            r["id"], r.get("name") or r.get("title") or "", r.get("description") or "",
            " ".join(r.get("references") or []),
        )).lower()
        if needle in blob or needle_us in blob:
            out.append(r)
    return out


def _indicators(text: str, known_paths: list[str], local_rules: list) -> list[IndicatorOut]:
    out: list[IndicatorOut] = []
    seen: set[tuple[str, str]] = set()

    def add(kind, value, ok, why):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append(IndicatorOut(kind=kind, value=value, detectable_in_http_logs=ok, why=why))

    for p in known_paths:
        add("path", p.strip(), True, "request path (supplied by caller)")
    for r in local_rules:
        filt = (r.get("condition") or {}).get("filter") or {}
        for fld, lit in rule_validation.positive_fragments(filt):
            if fld in ("path", "request_path", "url"):
                add("path", lit, True, f"from shipped rule {r['id']}")
    for m in _PATH_RE.findall(text or ""):
        m = m.rstrip(".,;:)")
        if re.search(r"[A-Za-z]", m) and len(m) >= 4:
            add("path", m, True, "path mentioned in the description")
    for meth in _METHODS:
        if re.search(rf"\b{meth}\b", text or ""):
            add("method", meth, True, "HTTP method is part of the normalized event")
    for h in _HEADER_RE.findall(text or ""):
        add("header", h, False, "AEGIS' web events carry method, path, status and User-Agent only; "
                               "this header is not in the event, so no rule can match it")
    for a, b in _PARAM_RE.findall(text or ""):
        name = a or b
        add("parameter", name, True, "visible only when the access log records the query string")
    return out


def _build_draft(body: ProtectIn, paths: list[str], methods: list[str], software_label: str,
                 unverified: bool) -> RuleDraft:
    label = body.cve_id or "described vulnerability"
    # One non-GET method narrows the rule; GET is on every ordinary request.
    filt: dict = {"path_contains": paths}
    nonget = [m for m in methods if m != "GET"]
    if len(nonget) == 1:
        filt["method"] = nonget[0]
    desc = (f"Detects HTTP requests matching the exploitation pattern of {label}"
            f"{' in ' + software_label if software_label else ''}. Exposure checked against the owner's stack "
            f"before this rule was proposed.")
    if unverified:
        desc += " UNVERIFIED: indicators were derived from a caller-supplied description, not a verified advisory."
    return RuleDraft(
        id=("authored_" + body.cve_id.lower().replace("-", "_")) if body.cve_id else None,
        name=f"Protect: {label}" + (f" ({software_label})" if software_label else ""),
        severity=body.severity, description=desc,
        references=[f"https://nvd.nist.gov/vuln/detail/{body.cve_id}"] if body.cve_id else [],
        condition=ConditionIn(event_type="web_request", count_threshold=1, time_window_seconds=300,
                              group_by="source_ip", filter=filt),
    )


async def protect(db, actor, body: ProtectIn) -> ProtectOut:
    if not (body.cve_id or body.description or body.known_paths or body.software):
        raise rule_authoring.RuleRefused("nothing_to_analyse", "give a cve_id, a description, software or known_paths")

    local = _covering_rules(body.cve_id) if body.cve_id else []
    stack = await stack_inventory(db, actor.client_id, body.stack)
    text = " ".join([body.description or ""] + [str(r.get("description") or "") for r in local])
    targeted = list(body.software) or [str(r.get("name") or r.get("title") or r["id"]) for r in local[:1]]
    haystack = " ".join(list(body.software) + [body.description or ""] +
                        [f"{r['id']} {r.get('name') or r.get('title') or ''} {r.get('description') or ''}" for r in local])

    hits = _stack_hits(stack, haystack) if haystack.strip() else []
    if not haystack.strip():
        app, reason = "unknown", ("no advisory data for this CVE is available locally and no description or "
                                  "software was given; supply the vendor advisory text or the product name")
    elif hits:
        app, reason = "applicable", f"your stack includes {', '.join(hits)}, which this vulnerability targets"
    elif stack:
        app, reason = "not_applicable", (f"this targets {', '.join(targeted) or 'software named in the description'}; "
                                         f"your stack ({', '.join(stack[:12])}{'...' if len(stack) > 12 else ''}) "
                                         f"contains none of it. A rule would only record probes for software you do not run")
    else:
        app, reason = "unknown", ("your stack inventory is empty (no assets with technologies, no AEGIS_STACK), "
                                  "so absence cannot be shown")

    verified = bool(local)
    unverified = not verified and bool(body.description or body.known_paths or body.software)
    verification = "verified_local_rule" if verified else ("unverified_description" if unverified else "none")

    inds = _indicators(text, body.known_paths, local)
    covered = [r["id"] for r in local]

    proposal: Optional[ProposalOut] = None
    created = None
    if app == "not_applicable":
        summary = f"Not applicable: {reason}. No rule proposed."
    elif covered:
        summary = f"Already covered by shipped rule(s) {', '.join(covered)}; no new rule proposed."
    else:
        paths = [i.value for i in inds if i.kind == "path" and i.detectable_in_http_logs]
        if not paths:
            summary = ("No HTTP-log-detectable path indicator found, so no rule can be written honestly. "
                       "Header/body-only exploits need a WAF or host telemetry, not a log rule.")
        else:
            methods = [i.value for i in inds if i.kind == "method"]
            draft = _build_draft(body, paths, methods, ", ".join(targeted), unverified)
            proposal = await rule_authoring.propose(draft, db, actor.client_id)
            summary = (f"Applicability {app}. Proposed rule {proposal.rule_id}"
                       f"{' (valid)' if proposal.can_create else ' is REFUSED by validation'}; "
                       f"{'UNVERIFIED indicators. ' if unverified else ''}Nothing was written.")
            if body.create and app == "applicable" and proposal.can_create:
                created = await rule_authoring.create(
                    db, actor, draft, enable=False,
                    request_text=f"protect: {body.cve_id or ''} {body.description or ''}".strip()[:500],
                    unverified=unverified,
                )
                summary += " Created DISABLED and alert-only; enabling goes through the dry-run gate."
            elif body.create and app != "applicable":
                summary += " Not created: applicability is not confirmed."

    from app.models.audit_log import AuditLog
    row = AuditLog(
        client_id=actor.client_id, action="rule_protect", model_used=actor.model or actor.kind,
        input_summary=f"protect {body.cve_id or ''} {(body.description or '')[:300]}".strip(),
        ai_reasoning=UNVERIFIED_NOTICE if unverified else (f"verified against local rule(s) {covered}" if verified else "no advisory data"),
        decision=json.dumps({
            "applicability": app, "reason": reason, "verification": verification,
            "unverified": unverified, "covered_by": covered, "stack_matched": hits,
            "indicators": [i.model_dump() for i in inds], "proposal_rule_id": proposal.rule_id if proposal else None,
            "created": bool(created), "actor": actor.label,
        }, default=str),
    )
    db.add(row)
    await db.commit()

    return ProtectOut(
        applicability=app, applicability_reason=reason, targeted_software=targeted, stack_matched=hits,
        stack_known=bool(stack), verification=verification,
        unverified_notice=UNVERIFIED_NOTICE if unverified else None,
        already_covered_by=covered, indicators=inds, proposal=proposal, created=created,
        audit_id=str(row.id), summary=summary,
    )
