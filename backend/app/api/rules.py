"""
Rule authoring API -- create and change detection rules safely.

Endpoints (all admin; reads are viewer)
---------------------------------------
GET    /rules                     → every rule with state + block classification
GET    /rules/{id}                → one rule: YAML, history, approval state
POST   /rules/propose             → validate + dry-run a draft; writes NOTHING
POST   /rules                     → create (disabled by default)
PUT    /rules/{id}                → update (previous version kept)
POST   /rules/{id}/dry-run        → re-run the dry run for a stored rule
POST   /rules/{id}/enable         → enable (dry-run gate; override is audited)
POST   /rules/{id}/disable        → disable
POST   /rules/{id}/promote        → operator approval to auto-block
POST   /rules/{id}/demote         → back to alert-only
POST   /rules/{id}/revert         → restore an earlier version
DELETE /rules/{id}                → delete (revertable)
POST   /rules/protect             → "protect me from this vulnerability"

A refused change returns 422 (validation), 409 (dry run blocks enabling) or
403 (not allowed for this actor), always with {code, message, validation,
dry_run} so a UI can render the reason and the evidence.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthContext, require_admin, require_viewer
from app.database import get_db
from app.schemas.rule_authoring import (
    CreateIn, DryRunOut, EnableIn, ProposalOut, ProposeIn, PromoteIn, ProtectIn,
    ProtectOut, RevertIn, RuleDetailOut, RuleSummaryOut, UpdateIn, WriteOut,
)
from app.services import rule_authoring as svc
from app.services import rule_dryrun, rule_vuln_advisor
from app.services.rule_authoring import Actor, RuleRefused

router = APIRouter(prefix="/rules", tags=["rules"])


def _actor(auth: AuthContext, origin: str = "operator") -> Actor:
    who = getattr(auth, "email", None) or getattr(auth, "user_id", None) or "api-key"
    return Actor(kind=origin, id=str(who) if origin == "operator" else "ai-agent",
                 client_id=auth.client_id, model=None if origin == "operator" else "ai")


def _refusal(exc: RuleRefused) -> JSONResponse:
    body = {
        "code": exc.code, "message": exc.message,
        "validation": exc.validation.model_dump(mode="json") if exc.validation else None,
        "dry_run": exc.dry_run.model_dump(mode="json") if exc.dry_run else None,
    }
    return JSONResponse(status_code=exc.status, content=body)


@router.get("", response_model=list[RuleSummaryOut])
async def list_rules(
    source: str = Query("all", pattern="^(all|authored|shipped)$"),
    auth: AuthContext = Depends(require_viewer),
):
    return svc.list_rules(source)


@router.post("/propose", response_model=ProposalOut)
async def propose(body: ProposeIn, auth: AuthContext = Depends(require_admin),
                  db: AsyncSession = Depends(get_db)):
    """Validate and dry-run a draft. Nothing is written, nothing is audited."""
    return await svc.propose(body.rule, db, auth.client_id)


@router.post("/protect", response_model=ProtectOut)
async def protect(body: ProtectIn, auth: AuthContext = Depends(require_admin),
                  db: AsyncSession = Depends(get_db)):
    try:
        return await rule_vuln_advisor.protect(db, _actor(auth, body.origin), body)
    except RuleRefused as exc:
        return _refusal(exc)


@router.get("/{rule_id}", response_model=RuleDetailOut)
async def get_rule(rule_id: str, auth: AuthContext = Depends(require_viewer)):
    detail = svc.get_detail(rule_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return detail


@router.post("", response_model=WriteOut, status_code=201)
async def create_rule(body: CreateIn, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.create(
            db, _actor(auth, body.origin), body.rule, enable=body.enable, blocking=body.blocking,
            override=body.override, override_reason=body.override_reason, request_text=body.request_text,
        )
    except RuleRefused as exc:
        return _refusal(exc)


@router.put("/{rule_id}", response_model=WriteOut)
async def update_rule(rule_id: str, body: UpdateIn, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.update(
            db, _actor(auth, body.origin), rule_id, body.rule, override=body.override,
            override_reason=body.override_reason, request_text=body.request_text,
        )
    except RuleRefused as exc:
        return _refusal(exc)


@router.post("/{rule_id}/dry-run", response_model=DryRunOut)
async def dry_run_rule(rule_id: str, auth: AuthContext = Depends(require_admin),
                       db: AsyncSession = Depends(get_db)):
    live = svc._read_live(rule_id)
    if live is None:
        raise HTTPException(status_code=404, detail="Authored rule not found")
    _, dry = await svc.check({k: v for k, v in live.items() if k != "authoring"}, db, auth.client_id,
                             existing_id_ok=True)
    if dry is None:
        raise HTTPException(status_code=422, detail="Rule cannot be replayed (failed validation)")
    return dry


@router.post("/{rule_id}/enable", response_model=WriteOut)
async def enable_rule(rule_id: str, body: EnableIn, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.set_enabled(db, _actor(auth), rule_id, True, override=body.override,
                                     override_reason=body.override_reason, note=body.note)
    except RuleRefused as exc:
        return _refusal(exc)


@router.post("/{rule_id}/disable", response_model=WriteOut)
async def disable_rule(rule_id: str, body: Optional[EnableIn] = None, auth: AuthContext = Depends(require_admin),
                       db: AsyncSession = Depends(get_db)):
    try:
        return await svc.set_enabled(db, _actor(auth), rule_id, False, note=body.note if body else None)
    except RuleRefused as exc:
        return _refusal(exc)


@router.post("/{rule_id}/promote", response_model=WriteOut)
async def promote_rule(rule_id: str, body: PromoteIn, auth: AuthContext = Depends(require_admin),
                       db: AsyncSession = Depends(get_db)):
    """Operator approval to auto-block. Always acts as `operator`; there is no
    `origin` field to claim otherwise."""
    try:
        return await svc.promote(db, _actor(auth), rule_id, block_class=body.block_class, note=body.note,
                                 override=body.override, override_reason=body.override_reason)
    except RuleRefused as exc:
        return _refusal(exc)


@router.post("/{rule_id}/demote", response_model=WriteOut)
async def demote_rule(rule_id: str, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.demote(db, _actor(auth), rule_id)
    except RuleRefused as exc:
        return _refusal(exc)


@router.post("/{rule_id}/revert", response_model=WriteOut)
async def revert_rule(rule_id: str, body: RevertIn, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.revert(db, _actor(auth), rule_id, to_version=body.to_version,
                                override=body.override, override_reason=body.override_reason)
    except RuleRefused as exc:
        return _refusal(exc)


@router.delete("/{rule_id}", response_model=WriteOut)
async def delete_rule(rule_id: str, auth: AuthContext = Depends(require_admin),
                      db: AsyncSession = Depends(get_db)):
    try:
        return await svc.delete(db, _actor(auth), rule_id)
    except RuleRefused as exc:
        return _refusal(exc)
