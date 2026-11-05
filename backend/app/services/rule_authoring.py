"""Create, change, enable, revert and delete detection rules at runtime.

The guardrails ARE the feature. A system that writes its own rules, on a
platform that has already blocked its own operator and customers, must make the
dangerous outcome hard to reach by accident. So:

* nothing is written without passing ``rule_validation`` (schema, namespace,
  genericity by execution, ReDoS, single-hit severity);
* nothing is ENABLED without a dry run over recent real traffic that matched no
  owner / customer / shared-egress / safelisted address (``rule_dryrun``). An
  operator may override that, with a written reason that lands in the audit
  trail. The AI path may not override at all;
* an AI-authored rule is alert-only: it detects and raises incidents but can
  never auto-block (``authored_rules_registry`` -> ``guardrails`` / ``ai_engine``
  / ``responder``). Blocking needs an operator ``promote``, and that approval is
  bound to the rule's exact content hash: any later edit, by anyone, drops the
  rule back to alert-only;
* every change is recoverable (history beside the rule) and audited.

Where things live
-----------------
* Rules:    ``authored_rules_registry.authored_dir()`` -- outside ``app/rules``
  because deploys rsync that tree with ``--delete``.
* History:  ``<authored_dir>/.history/<rule_id>/vNNNN.yaml``, the previous body
  of each version (its own ``authoring`` block records who/when). Files, not
  DB: rule loading must work with the DB down, a history file is the exact
  artifact that can be restored, and it diffs with plain tools. The DB holds the
  *audit* (``audit_log``), which is the record of decisions, not of contents.
* Audit:    ``audit_log`` -- the existing columns fit: ``action`` = rule_<change>,
  ``model_used`` = who asked, ``input_summary`` = the natural-language request,
  ``ai_reasoning`` = provenance/unverified label, ``decision`` = JSON with the
  rule, validation, dry run, approval and override.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

from app.schemas.rule import Rule
from app.schemas.rule_authoring import (
    DryRunOut, IssueOut, ProposalOut, RuleDetailOut, RuleDraft, RuleSummaryOut,
    RuleVersionOut, ValidationOut, WriteOut,
)
from app.services import authored_rules_registry as registry
from app.services import rule_dryrun, rule_validation
from app.services.rule_validation import ValidationResult

logger = logging.getLogger("aegis.rule_authoring")


class RuleRefused(Exception):
    """A change was refused. Carries what a UI needs to explain why."""

    def __init__(self, code: str, message: str, *, status: int = 422,
                 validation: Optional[ValidationOut] = None, dry_run: Optional[DryRunOut] = None):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.validation, self.dry_run = validation, dry_run


@dataclass
class Actor:
    kind: str                       # "operator" | "ai"
    id: str                         # operator identity or agent name
    client_id: str
    model: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.id}"


# ---------------------------------------------------------------------------
# Draft -> dict, YAML
# ---------------------------------------------------------------------------

def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:50].strip("_")
    return s if len(s) >= 3 else "rule"


def draft_to_dict(draft: RuleDraft, taken: Optional[set[str]] = None) -> dict:
    d = draft.model_dump(exclude_none=True)
    d["condition"] = {k: v for k, v in d["condition"].items() if v is not None}
    if not d.get("id"):
        taken = taken if taken is not None else rule_validation.existing_rule_ids()
        base = f"{registry.AUTHORED_PREFIX}{_slug(d['name'])}"
        rid, n = base, 2
        while rid in taken:
            rid, n = f"{base}_{n}", n + 1
        d["id"] = rid
    d.setdefault("kind", "sigma")
    d.setdefault("entityMappings", [{"type": "IP", "field": "source_ip"}])
    return d


def _yaml(data: dict) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)


def _validation_out(res: ValidationResult) -> ValidationOut:
    conv = lambda i: IssueOut(code=i.code, message=i.message, field=i.field, severity=i.severity)
    return ValidationOut(
        ok=res.ok, errors=[conv(i) for i in res.errors], warnings=[conv(i) for i in res.warnings],
        exploit_signature=res.exploit_signature, signature_reason=res.signature_reason,
    )


# ---------------------------------------------------------------------------
# Check = validation + dry run
# ---------------------------------------------------------------------------

async def check(data: dict, db, client_id: Optional[str], *, existing_id_ok: bool = False,
                run_dry: bool = True) -> tuple[ValidationResult, Optional[DryRunOut]]:
    res = rule_validation.validate(data, existing_id_ok=existing_id_ok)
    dry = None
    # Never replay a rule whose regex failed the safety check, or whose schema
    # did not parse: the replay would run it over tens of thousands of events
    # on the API event loop's thread pool.
    replayable = res.rule is not None and not any(i.code == "unsafe_regex" for i in res.errors)
    if run_dry and replayable:
        dry = await rule_dryrun.dry_run(res.rule, db, client_id)
        if dry.baseline.too_generic:
            res.add(
                "too_generic_empirical",
                "; ".join(dry.reasons) or "matches ordinary traffic",
                "condition.filter",
            )
    return res, dry


def _enable_gate(dry: Optional[DryRunOut], actor: Actor, override: bool, reason: Optional[str],
                 validation: ValidationOut) -> bool:
    """Return True if the gate was passed ONLY thanks to an override."""
    if dry is None:
        raise RuleRefused("no_dry_run", "cannot enable a rule that has not been dry-run", validation=validation)
    if dry.baseline.too_generic:
        raise RuleRefused("too_generic_empirical", "; ".join(dry.reasons), validation=validation, dry_run=dry)
    if dry.verdict == "clean":
        return False
    if not override:
        raise RuleRefused(
            "dry_run_blocked",
            "dry run blocks enabling: " + "; ".join(dry.reasons) + " -- fix the rule, or an operator may "
            "pass override with a reason",
            status=409, validation=validation, dry_run=dry,
        )
    if actor.kind != "operator":
        raise RuleRefused(
            "override_not_allowed",
            "only an operator may override the dry-run gate; an AI-authored change cannot",
            status=403, validation=validation, dry_run=dry,
        )
    if not (reason or "").strip():
        raise RuleRefused("override_reason_required", "override requires a written reason", validation=validation, dry_run=dry)
    return True


# ---------------------------------------------------------------------------
# Files, history, engine
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _hist(rule_id: str) -> Path:
    return registry.history_dir() / rule_id


def _read_live(rule_id: str) -> Optional[dict]:
    p = registry.rule_path(rule_id)
    if not p.exists():
        return None
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def _history_entries(rule_id: str) -> list[tuple[int, bool, Path]]:
    d = _hist(rule_id)
    out = []
    if d.is_dir():
        for f in d.glob("v*.yaml"):
            m = re.match(r"v(\d+)(\.deleted)?\.yaml$", f.name)
            if m:
                out.append((int(m.group(1)), bool(m.group(2)), f))
    return sorted(out)


def _current_version(rule_id: str, live: Optional[dict]) -> int:
    v = int(((live or {}).get("authoring") or {}).get("version", 0))
    hist = _history_entries(rule_id)
    return max([v] + [h[0] for h in hist])


def _engine_sync(rule_id: str, data: Optional[dict]) -> None:
    """Make the running correlation engine agree with the file on disk."""
    try:
        from app.services.correlation_engine import correlation_engine as eng
        rules = [r for r in eng._rules if r["id"] != rule_id]
        if data is not None:
            rules.append(Rule.model_validate({k: v for k, v in data.items() if k != "authoring"}))
        eng._rules = rules
        eng._rules_by_type = eng._build_type_index(rules)
        pack = getattr(eng, "_rule_pack", None)
        if pack is not None:
            pack.by_id.pop(rule_id, None)
            for lst in pack.rules.values():
                lst[:] = [r for r in lst if r["id"] != rule_id]
            if data is not None:
                new = next(r for r in rules if r["id"] == rule_id)
                pack.rules.setdefault(new.condition.event_type, []).append(new)
                pack.by_id[rule_id] = new
    except Exception as exc:
        # The file is the source of truth and loads on the next restart; a sync
        # failure must be loud but must not undo an audited change.
        logger.error(f"engine sync for {rule_id} failed: {exc}")
    registry.invalidate()


def _authoring_block(prev: Optional[dict], actor: Actor, change: str, *, request_text: Optional[str],
                     unverified: bool, version: int) -> dict:
    now = _now()
    base = dict(prev or {})
    base.update({
        "origin": base.get("origin") or actor.kind,
        "version": version,
        "created_at": base.get("created_at") or now,
        "created_by": base.get("created_by") or actor.label,
        "updated_at": now,
        "updated_by": actor.label,
        "last_change": change,
        "unverified": bool(unverified or base.get("unverified", False)),
        "mode": base.get("mode") or registry.MODE_ALERT_ONLY,
        "block_class": base.get("block_class") or registry.CLASS_AMBIGUOUS,
    })
    if request_text:
        base["request"] = request_text[:500]
    return base


async def _audit(db, actor: Actor, change: str, rule_id: str, *, rule: Optional[dict],
                 validation: Optional[ValidationOut], dry: Optional[DryRunOut], request_text: Optional[str],
                 approval: Optional[dict] = None, override: Optional[dict] = None, unverified: bool = False,
                 extra: Optional[dict] = None):
    from app.models.audit_log import AuditLog

    decision = {
        "rule_id": rule_id, "change": change, "actor": actor.label,
        "rule_yaml": _yaml(rule) if rule else None,
        "validation": validation.model_dump(mode="json") if validation else None,
        "dry_run": _dry_summary(dry),
        "approval": approval, "override": override, **(extra or {}),
    }
    row = AuditLog(
        client_id=actor.client_id,
        action=f"rule_{change}",
        model_used=actor.model or actor.kind,
        input_summary=request_text or f"{actor.label} {change} {rule_id}",
        ai_reasoning=("UNVERIFIED: derived from a caller-supplied description, not from a verified advisory"
                      if unverified else f"{actor.kind}-authored; see decision"),
        decision=json.dumps(decision, default=str),
    )
    db.add(row)
    await db.flush()
    return row


def _dry_summary(dry: Optional[DryRunOut]) -> Optional[dict]:
    if dry is None:
        return None
    return {
        "verdict": dry.verdict, "reasons": dry.reasons, "events_scanned": dry.events_scanned,
        "matches": dry.matches, "distinct_ips": dry.distinct_ips, "firing_ips": dry.firing_ips,
        "flagged_ips": [f.model_dump() for f in dry.flagged_ips],
        "corpora": [c.model_dump(mode="json") for c in dry.corpora],
        "baseline": dry.baseline.model_dump(),
    }


async def _commit(db, *, rule_id: str, new: Optional[dict], old: Optional[dict], audit_row, change: str) -> None:
    """Write history + live file, sync the engine, then commit the audit row.

    Order matters: the audit row is flushed first and the DB commit comes last,
    so a failed file write rolls the audit back (no audit of a change that did
    not happen) and a failed commit restores the files (no change without an
    audit).
    """
    live_path = registry.rule_path(rule_id)
    prev_text = live_path.read_text(encoding="utf-8") if live_path.exists() else None
    hist_files: list[Path] = []
    try:
        if old is not None:
            hp = _hist(rule_id) / f"v{int(old.get('authoring', {}).get('version', 0)):04d}.yaml"
            _atomic_write(hp, _yaml(old))
            hist_files.append(hp)
        if new is None:
            if live_path.exists():
                live_path.unlink()
                ver = _current_version(rule_id, None) + 1
                tomb = _hist(rule_id) / f"v{ver:04d}.deleted.yaml"
                _atomic_write(tomb, _yaml(old or {}))
                hist_files.append(tomb)
        else:
            _atomic_write(live_path, _yaml(new))
        await db.commit()
    except Exception:
        await db.rollback()
        if prev_text is not None:
            _atomic_write(live_path, prev_text)
        elif live_path.exists():
            live_path.unlink()
        for hp in hist_files:
            hp.unlink(missing_ok=True)
        registry.invalidate()
        raise
    _engine_sync(rule_id, new)


def _approval_for(actor: Actor, data: dict, block_class: str, note: Optional[str]) -> dict:
    return {
        "approved_hash": registry.content_hash(data), "approved_by": actor.label,
        "approved_at": _now(), "block_class": block_class, "note": note,
    }


# ---------------------------------------------------------------------------
# Public operations
# ---------------------------------------------------------------------------

async def propose(draft: RuleDraft, db, client_id: Optional[str]) -> ProposalOut:
    """Validate and dry-run. Writes nothing -- no file, no audit row."""
    data = draft_to_dict(draft)
    res, dry = await check(data, db, client_id)
    v = _validation_out(res)
    blockers = [f"{e.code}: {e.message}" for e in v.errors]
    if dry and dry.verdict != "clean":
        blockers += dry.reasons
    return ProposalOut(
        rule_id=data["id"], yaml=_yaml(data), validation=v, dry_run=dry,
        can_create=v.ok, can_enable=v.ok and bool(dry and dry.can_enable), blockers=blockers,
    )


async def create(db, actor: Actor, draft: RuleDraft, *, enable: bool = False, blocking: bool = False,
                 override: bool = False, override_reason: Optional[str] = None,
                 request_text: Optional[str] = None, unverified: bool = False) -> WriteOut:
    data = draft_to_dict(draft)
    rid = data["id"]
    res, dry = await check(data, db, actor.client_id)
    v = _validation_out(res)
    if not res.ok:
        raise RuleRefused("validation_failed", "; ".join(f"{e.code}: {e.message}" for e in v.errors),
                          validation=v, dry_run=dry)

    # An AI request for "blocking" is not an error, it is simply not granted:
    # the rule is created alert-only and the response says so.
    want_block = blocking and actor.kind == "operator"
    overridden = False
    if enable or want_block:
        overridden = _enable_gate(dry, actor, override, override_reason, v)

    data["enabled"] = bool(enable)
    meta = _authoring_block(None, actor, "create", request_text=request_text, unverified=unverified, version=1)
    data["authoring"] = meta
    approval = None
    if want_block:
        approval = _approval_for(actor, data, registry.CLASS_AMBIGUOUS, "approved at creation")
        meta.update(mode=registry.MODE_BLOCKING, **{k: approval[k] for k in ("approved_hash", "approved_by", "approved_at")})

    override_rec = {"reason": override_reason, "by": actor.label, "flagged": _dry_summary(dry)["flagged_ips"] if dry else []} if overridden else None
    row = await _audit(db, actor, "create", rid, rule=data, validation=v, dry=dry, request_text=request_text,
                       approval=approval, override=override_rec, unverified=unverified)
    await _commit(db, rule_id=rid, new=data, old=None, audit_row=row, change="create")
    return await _write_out(data, v, dry, overridden, row.id,
                            "created" + (" and enabled" if enable else " (disabled)") +
                            ("" if want_block else "; alert-only until an operator approves blocking"))


async def update(db, actor: Actor, rule_id: str, draft: RuleDraft, *, override: bool = False,
                 override_reason: Optional[str] = None, request_text: Optional[str] = None,
                 unverified: bool = False) -> WriteOut:
    live = _require_live(rule_id)
    data = draft_to_dict(draft.model_copy(update={"id": rule_id}))
    res, dry = await check(data, db, actor.client_id, existing_id_ok=True)
    v = _validation_out(res)
    if not res.ok:
        raise RuleRefused("validation_failed", "; ".join(f"{e.code}: {e.message}" for e in v.errors),
                          validation=v, dry_run=dry)

    enabled = bool(live.get("enabled", True))
    overridden = _enable_gate(dry, actor, override, override_reason, v) if enabled else False
    data["enabled"] = enabled
    prev_meta = dict(live.get("authoring") or {})
    ver = _current_version(rule_id, live) + 1
    meta = _authoring_block(prev_meta, actor, "update", request_text=request_text, unverified=unverified, version=ver)
    # An AI edit also scrubs the recorded mode; the content-hash binding would
    # already neutralise a stale approval, this just keeps the file honest.
    if actor.kind == "ai":
        meta["mode"] = registry.MODE_ALERT_ONLY
    data["authoring"] = meta
    override_rec = {"reason": override_reason, "by": actor.label} if overridden else None
    row = await _audit(db, actor, "update", rule_id, rule=data, validation=v, dry=dry, request_text=request_text,
                       override=override_rec, unverified=unverified,
                       extra={"previous_version": ver - 1})
    await _commit(db, rule_id=rule_id, new=data, old=live, audit_row=row, change="update")
    st = registry.state_from_dict(data)
    return await _write_out(data, v, dry, overridden, row.id,
                            f"updated to v{ver}" + ("; blocking approval was dropped, re-approve to block"
                                                    if prev_meta.get("approved_hash") and not (st and st.approved_valid) else ""))


async def set_enabled(db, actor: Actor, rule_id: str, enabled: bool, *, override: bool = False,
                      override_reason: Optional[str] = None, note: Optional[str] = None) -> WriteOut:
    live = _require_live(rule_id)
    data = {k: v for k, v in live.items()}
    v: Optional[ValidationOut] = None
    dry = None
    overridden = False
    if enabled:
        # Re-run everything: the traffic (and the owner's IP lists) changed
        # since the rule was written, and this is the moment it starts to act.
        res, dry = await check({k: x for k, x in live.items() if k != "authoring"}, db, actor.client_id, existing_id_ok=True)
        v = _validation_out(res)
        if not res.ok:
            raise RuleRefused("validation_failed", "; ".join(f"{e.code}: {e.message}" for e in v.errors),
                              validation=v, dry_run=dry)
        overridden = _enable_gate(dry, actor, override, override_reason, v)
    data["enabled"] = enabled
    ver = _current_version(rule_id, live) + 1
    change = "enable" if enabled else "disable"
    data["authoring"] = _authoring_block(live.get("authoring"), actor, change, request_text=note, unverified=False, version=ver)
    override_rec = {"reason": override_reason, "by": actor.label,
                    "flagged": _dry_summary(dry)["flagged_ips"] if dry else []} if overridden else None
    row = await _audit(db, actor, change, rule_id, rule=data, validation=v, dry=dry, request_text=note, override=override_rec)
    await _commit(db, rule_id=rule_id, new=data, old=live, audit_row=row, change=change)
    return await _write_out(data, v, dry, overridden, row.id, change + "d")


async def promote(db, actor: Actor, rule_id: str, *, block_class: str = "ambiguous", note: Optional[str] = None,
                  override: bool = False, override_reason: Optional[str] = None) -> WriteOut:
    """Operator approval for an authored rule to auto-block."""
    if actor.kind != "operator":
        raise RuleRefused("operator_only", "only an operator can approve a rule for blocking", status=403)
    live = _require_live(rule_id)
    body = {k: v for k, v in live.items() if k != "authoring"}
    res, dry = await check(body, db, actor.client_id, existing_id_ok=True)
    v = _validation_out(res)
    if not res.ok:
        raise RuleRefused("validation_failed", "; ".join(f"{e.code}: {e.message}" for e in v.errors),
                          validation=v, dry_run=dry)
    if block_class == registry.CLASS_CONFIRMED:
        # CONFIRMED = permanent block from the first match. That is only
        # defensible for an exploit signature, and never on an override.
        if not res.exploit_signature:
            raise RuleRefused("not_a_signature", "confirmed (permanent) blocking needs an exploit-signature "
                              f"filter: {res.signature_reason}", validation=v, dry_run=dry)
        override = False
    overridden = _enable_gate(dry, actor, override, override_reason, v)
    meta = dict(live.get("authoring") or {})
    approval = _approval_for(actor, live, block_class, note)
    ver = _current_version(rule_id, live) + 1
    data = dict(live)
    data["authoring"] = _authoring_block(meta, actor, "promote", request_text=note, unverified=False, version=ver)
    data["authoring"].update(mode=registry.MODE_BLOCKING, block_class=block_class,
                             **{k: approval[k] for k in ("approved_hash", "approved_by", "approved_at")})
    override_rec = {"reason": override_reason, "by": actor.label} if overridden else None
    row = await _audit(db, actor, "promote", rule_id, rule=data, validation=v, dry=dry, request_text=note,
                       approval=approval, override=override_rec)
    await _commit(db, rule_id=rule_id, new=data, old=live, audit_row=row, change="promote")
    return await _write_out(data, v, dry, overridden, row.id, f"approved for blocking ({block_class})")


async def demote(db, actor: Actor, rule_id: str, note: Optional[str] = None) -> WriteOut:
    live = _require_live(rule_id)
    data = dict(live)
    ver = _current_version(rule_id, live) + 1
    meta = _authoring_block(live.get("authoring"), actor, "demote", request_text=note, unverified=False, version=ver)
    meta["mode"] = registry.MODE_ALERT_ONLY
    for k in ("approved_hash", "approved_by", "approved_at"):
        meta.pop(k, None)
    data["authoring"] = meta
    row = await _audit(db, actor, "demote", rule_id, rule=data, validation=None, dry=None, request_text=note)
    await _commit(db, rule_id=rule_id, new=data, old=live, audit_row=row, change="demote")
    return await _write_out(data, None, None, False, row.id, "back to alert-only")


async def delete(db, actor: Actor, rule_id: str, note: Optional[str] = None) -> WriteOut:
    live = _require_live(rule_id)
    row = await _audit(db, actor, "delete", rule_id, rule=live, validation=None, dry=None, request_text=note)
    await _commit(db, rule_id=rule_id, new=None, old=live, audit_row=row, change="delete")
    out = await _write_out(live, None, None, False, row.id, "deleted (revertable from history)")
    return out


async def revert(db, actor: Actor, rule_id: str, *, to_version: Optional[int] = None, override: bool = False,
                 override_reason: Optional[str] = None) -> WriteOut:
    live = _read_live(rule_id)
    hist = [h for h in _history_entries(rule_id) if not h[1]]
    if live is not None:
        hist = [h for h in hist if h[0] < int((live.get("authoring") or {}).get("version", 0))]
    if to_version is not None:
        hist = [h for h in hist if h[0] == to_version]
    if not hist:
        raise RuleRefused("no_history", "no earlier version to restore", status=404)
    target_ver, _, tpath = hist[-1]
    restored = yaml.safe_load(tpath.read_text(encoding="utf-8"))

    # The restored body must still pass today's validator, and if the rule is
    # currently enabled it re-faces the dry run: a revert is a way to put a
    # body back into service, so it gets no exemption from the gate.
    enabled = bool(live.get("enabled", False)) if live is not None else False
    res, dry = await check({k: x for k, x in restored.items() if k != "authoring"}, db, actor.client_id,
                           existing_id_ok=True, run_dry=enabled)
    v = _validation_out(res)
    if not res.ok:
        raise RuleRefused("validation_failed", "restored version no longer passes validation: " +
                          "; ".join(f"{e.code}: {e.message}" for e in v.errors), validation=v)
    overridden = _enable_gate(dry, actor, override, override_reason, v) if enabled else False
    restored["enabled"] = enabled
    ver = _current_version(rule_id, live) + 1
    restored["authoring"] = _authoring_block(restored.get("authoring"), actor, "revert", request_text=f"revert to v{target_ver}",
                                             unverified=False, version=ver)
    if actor.kind == "ai":
        restored["authoring"]["mode"] = registry.MODE_ALERT_ONLY
    override_rec = {"reason": override_reason, "by": actor.label} if overridden else None
    row = await _audit(db, actor, "revert", rule_id, rule=restored, validation=v, dry=dry,
                       request_text=f"revert to v{target_ver}", override=override_rec,
                       extra={"restored_version": target_ver})
    await _commit(db, rule_id=rule_id, new=restored, old=live, audit_row=row, change="revert")
    return await _write_out(restored, v, dry, overridden, row.id, f"reverted to the content of v{target_ver} (now v{ver})")


def _require_live(rule_id: str) -> dict:
    if not rule_id.startswith(registry.AUTHORED_PREFIX):
        raise RuleRefused("not_authored", "only runtime-authored rules can be changed here; shipped rules "
                          "are edited in the repo", status=403)
    live = _read_live(rule_id)
    if live is None:
        raise RuleRefused("not_found", f"no authored rule '{rule_id}'", status=404)
    return live


# ---------------------------------------------------------------------------
# Read side
# ---------------------------------------------------------------------------

def _versions(rule_id: str, live: Optional[dict]) -> list[RuleVersionOut]:
    out = []
    for ver, deleted, p in _history_entries(rule_id):
        try:
            meta = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("authoring") or {}
        except (OSError, yaml.YAMLError):
            meta = {}
        saved = meta.get("updated_at") or _now()
        out.append(RuleVersionOut(
            version=ver, saved_at=datetime.fromisoformat(saved.rstrip("Z")), saved_by=meta.get("updated_by", "?"),
            change="delete" if deleted else meta.get("last_change", "update"), deleted=deleted,
        ))
    return out


def _summary_from_authored(data: dict) -> RuleSummaryOut:
    st = registry.state_from_dict(data)
    meta = data.get("authoring") or {}
    updated = meta.get("updated_at")
    return RuleSummaryOut(
        id=data["id"], name=data.get("name", ""), severity=data.get("severity", "low"),
        event_type=(data.get("condition") or {}).get("event_type"), enabled=bool(data.get("enabled", True)),
        origin=("ai" if (st and st.origin == "ai") else "operator"),
        classification=st.effective_class if st else "ambiguous",
        mode=st.effective_mode if st else "alert_only",
        awaiting_approval=bool(st and st.effective_mode == registry.MODE_ALERT_ONLY),
        unverified=bool(st and st.unverified), version=meta.get("version"),
        updated_at=datetime.fromisoformat(updated.rstrip("Z")) if updated else None,
    )


async def _write_out(data: dict, v: Optional[ValidationOut], dry: Optional[DryRunOut], overridden: bool,
                     audit_id: Any, message: str) -> WriteOut:
    detail = detail_from_dict(data)
    return WriteOut(
        rule=detail, validation=v or ValidationOut(ok=True), dry_run=dry, override_applied=overridden,
        audit_id=str(audit_id) if audit_id else None, message=message,
    )


def detail_from_dict(data: dict) -> RuleDetailOut:
    base = _summary_from_authored(data)
    st = registry.state_from_dict(data)
    body = {k: v for k, v in data.items() if k != "authoring"}
    return RuleDetailOut(
        **base.model_dump(), yaml=_yaml(body), description=data.get("description"),
        history=_versions(data["id"], data), approved=bool(st and st.approved_valid),
        block_class_recorded=(data.get("authoring") or {}).get("block_class"),
    )


def get_detail(rule_id: str) -> Optional[RuleDetailOut]:
    live = _read_live(rule_id)
    if live is not None:
        return detail_from_dict(live)
    hist = _versions(rule_id, None)
    if hist and rule_id.startswith(registry.AUTHORED_PREFIX):
        return None
    shipped = _shipped_summary(rule_id)
    if shipped is None:
        return None
    from app.services.correlation_engine import correlation_engine as eng
    r = next(r for r in eng._rules if r["id"] == rule_id)
    body = r.model_dump(exclude_none=True) if hasattr(r, "model_dump") else dict(r)
    return RuleDetailOut(**shipped.model_dump(), yaml=_yaml(body), description=body.get("description"))


def _shipped_summary(rule_id: str) -> Optional[RuleSummaryOut]:
    from app.services.correlation_engine import correlation_engine as eng
    for r in eng._rules:
        if r["id"] == rule_id:
            return _engine_summary(r)
    return None


def _engine_summary(r: Any) -> RuleSummaryOut:
    from app.services import block_policy
    cond = r.get("condition") or {}
    rid = r["id"]
    live = _read_live(rid) if rid.startswith(registry.AUTHORED_PREFIX) else None
    if live is not None:
        return _summary_from_authored(live)
    return RuleSummaryOut(
        id=rid, name=r.get("name") or r.get("title") or rid, severity=r.get("severity", "low"),
        event_type=cond.get("event_type") if hasattr(cond, "get") else None,
        enabled=bool(r.get("enabled", True)), origin="shipped",
        classification=block_policy.classify(rule_ids=[rid]).kind,
    )


def list_rules(source: str = "all") -> list[RuleSummaryOut]:
    from app.services.correlation_engine import correlation_engine as eng
    out = [_engine_summary(r) for r in eng._rules]
    seen = {r.id for r in out}
    # Authored rules that exist on disk but not in the engine (a failed sync).
    for rid in registry.states():
        if rid not in seen:
            live = _read_live(rid)
            if live:
                out.append(_summary_from_authored(live))
    if source == "authored":
        out = [r for r in out if r.origin != "shipped"]
    elif source == "shipped":
        out = [r for r in out if r.origin == "shipped"]
    return sorted(out, key=lambda r: (r.origin == "shipped", r.id))
