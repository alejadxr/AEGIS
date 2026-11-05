"""Rule authoring: the guardrails are the feature.

Documentation IPs only (RFC 5737) and example.com.
"""
import json
import re
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core import attack_detector
from app.core.guardrails import guardrail_engine
from app.models.action import Action
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.schemas.rule_authoring import ConditionIn, ProtectIn, RuleDraft
from app.services import authored_rules_registry as registry
from app.services import block_policy as bp
from app.services import rule_authoring as svc
from app.services import rule_dryrun, rule_validation, rule_vuln_advisor
from app.services.ai_engine import ai_engine
from app.services.rule_authoring import Actor, RuleRefused

OWNER_IP = "192.0.2.50"
EGRESS_IP = "198.51.100.77"
CUSTOMER_IP = "198.51.100.20"
ATTACKER = "203.0.113.250"

OP = Actor("operator", "owner@example.com", "c1")
AI = Actor("ai", "ai-agent", "c1", model="ai")


@pytest_asyncio.fixture
async def db(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_AUTHORED_RULES_DIR", str(tmp_path / "authored"))
    monkeypatch.delenv("AEGIS_INTERNAL_IPS", raising=False)
    monkeypatch.delenv("AEGIS_STACK", raising=False)
    registry.invalidate()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = [Client, Asset, Incident, Action, AuditLog]
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=[m.__table__ for m in tables]))
    f = async_sessionmaker(engine, expire_on_commit=False)
    async with f() as s:
        s.add(Client(id="c1", name="t", slug="t", api_key="k"))
        await s.commit()
    async with f() as s:
        yield s
    # leave the process-wide engine as we found it
    for rid in list(registry.states()):
        svc._engine_sync(rid, None)
    registry.invalidate()
    await engine.dispose()


def _ev(ip, path, status=200, pattern=None, ts=1_800_000_000.0, method="GET"):
    return rule_dryrun._Ev({
        "event_type": "http_request", "source_ip": ip, "request_path": path, "request_method": method,
        "response_status": status, "pattern_name": pattern, "user_agent": "Mozilla/5.0",
    }, ts, "pm2_logs")


def _traffic(n=120, extra=()):
    evs = [_ev(f"203.0.113.{i % 200 + 1}", f"/page/{i}", ts=1_800_000_000.0 + i) for i in range(n)]
    return evs + list(extra)


@pytest.fixture
def traffic(monkeypatch):
    """Install a fake PM2 corpus; returns a setter."""
    box = {"events": _traffic()}
    monkeypatch.setattr(rule_dryrun, "load_pm2_events", lambda *a, **k: (box["events"], "test corpus"))
    return lambda events: box.update(events=events)


def draft(name="Debug console probe", filt=None, severity="low", threshold=None, event_type="web_request", **kw):
    cond = {"event_type": event_type, "filter": filt if filt is not None else {"path_contains": ["/debug/console.php"]}}
    if threshold:
        cond.update(count_threshold=threshold, time_window_seconds=300, group_by="source_ip")
    return RuleDraft(name=name, severity=severity, description="test rule", condition=ConditionIn(**cond), **kw)


def codes(res):
    return {i.code for i in res.errors}


def _vd(**over):
    d = {"id": "authored_probe_one", "name": "t", "severity": "low", "description": "d", "kind": "sigma",
         "condition": {"event_type": "web_request", "filter": {"path_contains": ["/debug/console.php"]}}}
    d.update(over)
    return d


# --- 2. validation refuses dangerous shapes ---------------------------------

@pytest.mark.parametrize("bad_id", ["sigma_web_new_rule", "sigma_cve_2026_0001", "authored_", "has space", "AUTHORED_x"])
def test_ids_outside_the_authored_namespace_are_refused(bad_id):
    # The namespace is what keeps a runtime rule from landing in block_policy's
    # CONFIRMED ids/prefixes (permanent block on a single match).
    assert "bad_id" in codes(rule_validation.validate(_vd(id=bad_id)))


@pytest.mark.parametrize("filt", [
    {"path_contains": ["/"]}, {"path_contains": ["/api/"]}, {"path_contains": ["/api/v1/"]},
    {"path_contains": ["/admin"]}, {"path_regex": "^/"},
])
def test_generic_path_filters_are_refused_by_execution(filt):
    res = rule_validation.validate(_vd(condition={"event_type": "web_request", "filter": filt}))
    assert "too_generic" in codes(res)


def test_empty_filter_on_a_high_severity_rule_is_refused():
    res = rule_validation.validate(_vd(severity="high", condition={"event_type": "web_request", "filter": {}}))
    assert "no_filter" in codes(res)


def test_schema_errors_use_the_loaders_own_model():
    assert "schema" in codes(rule_validation.validate(_vd(severity="catastrophic")))
    assert "schema" in codes(rule_validation.validate({"id": "authored_x1", "name": "n"}))
    assert "schema" in codes(rule_validation.validate(_vd(kind="chain")))


def test_filter_clause_the_engine_cannot_honour_is_refused_not_warned():
    res = rule_validation.validate(_vd(condition={"event_type": "web_request", "filter": {"path_startswith": ["/x/yy/zz"]}}))
    assert "filter_vocabulary" in codes(res)


def test_unknown_event_type_is_refused():
    assert "unknown_event_type" in codes(rule_validation.validate(_vd(condition={"event_type": "nope_event", "filter": {"path_contains": ["/debug/console.php"]}})))


@pytest.mark.parametrize("pattern", ["(a+)+$", "(x+x+)+y", "(a|aa)+$", "(.*a){12}x"])
def test_nested_quantifier_regex_is_refused(pattern):
    res = rule_validation.validate(_vd(condition={"event_type": "web_request", "filter": {"path_regex": pattern}}))
    assert "unsafe_regex" in codes(res)


def test_regex_that_only_the_timing_probe_can_catch_is_refused():
    # No nesting, so the static walk passes it; five chained `.*` is O(n^5).
    pattern = r".*.*.*.*.*=x"
    assert rule_validation.regex_static_problem(pattern) is None
    res = rule_validation.validate(_vd(condition={"event_type": "web_request", "filter": {"path_regex": pattern}}))
    assert "unsafe_regex" in codes(res)


def test_a_sound_regex_passes():
    assert rule_validation.check_regex(r"/solr/admin/cores\?action=") is None


def test_single_hit_high_severity_needs_an_exploit_signature():
    loose = _vd(severity="high", condition={"event_type": "web_request", "count_threshold": 1,
                                            "filter": {"path_contains": ["/cgi-bin/"]}})
    assert "single_hit_severity" in codes(rule_validation.validate(loose))
    sig = _vd(severity="critical", condition={"event_type": "web_request", "count_threshold": 1,
                                              "filter": {"path_contains": ["/solr/admin/cores?action="]}})
    res = rule_validation.validate(sig)
    assert res.ok and res.exploit_signature
    # the same loose filter is fine when it must repeat
    repeated = _vd(severity="high", condition={"event_type": "web_request", "count_threshold": 5,
                                               "time_window_seconds": 60, "group_by": "source_ip",
                                               "filter": {"path_contains": ["/cgi-bin/"]}})
    assert "single_hit_severity" not in codes(rule_validation.validate(repeated))


@pytest.mark.asyncio
async def test_id_collision_is_refused(db, traffic):
    await svc.create(db, OP, draft(id="authored_dup_rule"))
    with pytest.raises(RuleRefused) as e:
        await svc.create(db, OP, draft(id="authored_dup_rule"))
    assert "id_collision" in {i.code for i in e.value.validation.errors}


# --- 3. dry run -------------------------------------------------------------

def _actuator_rule():
    return draft(name="Actuator probe", filt={"path_contains": ["/actuator"]})


@pytest.mark.asyncio
async def test_dry_run_flags_an_owner_ip_and_blocks_enabling(db, traffic, monkeypatch):
    monkeypatch.setenv("AEGIS_INTERNAL_IPS", OWNER_IP)
    traffic(_traffic(extra=[_ev(OWNER_IP, "/actuator/health"), _ev(ATTACKER, "/actuator/env", 404)]))
    prop = await svc.propose(_actuator_rule(), db, "c1")
    d = prop.dry_run
    assert d.verdict == "blocked" and not d.can_enable
    assert [(f.ip, f.category) for f in d.flagged_ips] == [(OWNER_IP, "owner_or_customer")]
    assert d.matches == 2 and d.distinct_ips == 2
    assert d.corpora[0].source == "pm2_logs" and d.corpora[0].events >= 120

    with pytest.raises(RuleRefused) as e:
        await svc.create(db, OP, _actuator_rule(), enable=True)
    assert e.value.code == "dry_run_blocked" and e.value.status == 409
    assert not registry.rule_path("authored_actuator_probe").exists()


@pytest.mark.asyncio
async def test_dry_run_separates_customer_from_builtin_shared_egress(db, traffic, monkeypatch):
    import ipaddress
    # built-in crowd range (WARP / Private Relay stand-in) vs the operator's own list
    monkeypatch.setattr(attack_detector, "_SHARED_EGRESS_NETWORKS",
                        list(attack_detector._SHARED_EGRESS_NETWORKS) + [ipaddress.ip_network("198.51.100.64/26")])
    monkeypatch.setattr(attack_detector, "_shared_egress_literals", set(attack_detector._shared_egress_literals) | {CUSTOMER_IP})
    traffic(_traffic(extra=[_ev(EGRESS_IP, "/actuator/health"), _ev(CUSTOMER_IP, "/actuator/health")]))
    d = (await svc.propose(_actuator_rule(), db, "c1")).dry_run
    assert {f.ip: f.category for f in d.flagged_ips} == {EGRESS_IP: "shared_egress", CUSTOMER_IP: "customer"}
    assert d.verdict == "blocked"


@pytest.mark.asyncio
async def test_override_is_operator_only_needs_a_reason_and_is_audited(db, traffic, monkeypatch):
    monkeypatch.setenv("AEGIS_INTERNAL_IPS", OWNER_IP)
    traffic(_traffic(extra=[_ev(OWNER_IP, "/actuator/health")]))
    with pytest.raises(RuleRefused) as e:
        await svc.create(db, AI, _actuator_rule(), enable=True, override=True, override_reason="trust me")
    assert e.value.code == "override_not_allowed" and e.value.status == 403
    with pytest.raises(RuleRefused) as e:
        await svc.create(db, OP, _actuator_rule(), enable=True, override=True)
    assert e.value.code == "override_reason_required"

    out = await svc.create(db, OP, _actuator_rule(), enable=True, override=True,
                           override_reason="that IP is my monitoring box")
    assert out.override_applied and out.rule.enabled
    row = (await db.execute(select(AuditLog).where(AuditLog.id == out.audit_id))).scalar_one()
    dec = json.loads(row.decision)
    assert dec["override"]["reason"] == "that IP is my monitoring box"
    assert dec["override"]["flagged"][0]["ip"] == OWNER_IP
    assert row.action == "rule_create" and dec["actor"] == "operator:owner@example.com"


@pytest.mark.asyncio
async def test_clean_dry_run_lets_a_rule_be_enabled_and_reaches_the_engine(db, traffic):
    traffic(_traffic(extra=[_ev(ATTACKER, "/debug/console.php", 404)]))
    out = await svc.create(db, OP, draft(), enable=True, request_text="alert me on the debug console probe")
    assert out.dry_run.verdict == "clean" and out.dry_run.matches == 1 and not out.override_applied
    from app.services.correlation_engine import correlation_engine
    assert any(r["id"] == out.rule.id for r in correlation_engine._rules_by_type["web_request"])
    row = (await db.execute(select(AuditLog).where(AuditLog.id == out.audit_id))).scalar_one()
    assert row.input_summary == "alert me on the debug console probe"


@pytest.mark.asyncio
async def test_too_little_traffic_is_not_a_green_light(db, traffic):
    traffic(_traffic(n=10))
    d = (await svc.propose(draft(), db, "c1")).dry_run
    assert d.verdict == "insufficient_evidence" and not d.can_enable and d.overridable


@pytest.mark.asyncio
async def test_filter_that_matches_ordinary_traffic_is_refused_empirically(db, traffic):
    # No static rule against "/page/" exists; only the owner's real requests say it is generic.
    with pytest.raises(RuleRefused) as e:
        await svc.create(db, OP, draft(name="Page probe", filt={"path_contains": ["/page/"]}))
    assert "too_generic_empirical" in {i.code for i in e.value.validation.errors}


@pytest.mark.asyncio
async def test_threshold_rule_only_flags_groups_that_would_fire(db, traffic, monkeypatch):
    monkeypatch.setenv("AEGIS_INTERNAL_IPS", OWNER_IP)
    # owner hits once (below threshold 3) -> would NOT raise an incident; attacker hits 3x -> would
    ev = [_ev(OWNER_IP, "/debug/console.php", ts=1_800_000_500.0)] + \
         [_ev(ATTACKER, "/debug/console.php", 404, ts=1_800_000_500.0 + i) for i in range(3)]
    traffic(_traffic(extra=ev))
    d = (await svc.propose(draft(threshold=3), db, "c1")).dry_run
    assert d.firing_ips == 1 and d.flagged_ips == [] and d.verdict == "clean"


# --- 4. AI-authored rules are alert-only ------------------------------------

async def _incident(db, rule_id, ip=ATTACKER):
    inc = Incident(client_id="c1", title="t", severity="medium", source_ip=ip, raw_alert={"rule_id": rule_id, "pattern": rule_id})
    db.add(inc)
    await db.commit()
    return inc


@pytest.mark.asyncio
async def test_ai_rule_is_ambiguous_alert_only_and_cannot_auto_block(db, traffic):
    out = await svc.create(db, AI, draft(), enable=True, blocking=True)   # blocking is simply not granted
    rid = out.rule.id
    assert out.rule.origin == "ai" and out.rule.mode == "alert_only" and out.rule.awaiting_approval
    assert out.rule.classification == "ambiguous"
    assert registry.is_alert_only(rid) and not registry.is_confirmed(rid)
    assert bp.classify(rule_ids=[rid]).kind == bp.AMBIGUOUS

    inc = await _incident(db, rid)
    client = await db.get(Client, "c1")
    action = await guardrail_engine.evaluate_action(client, "block_ip", ATTACKER, "ai wants a block", db, incident_id=inc.id)
    assert action.status == "pending" and action.requires_approval
    assert "alert-only" in action.ai_reasoning

    # the provisional-block path in ai_engine goes through the same gate
    pending = await ai_engine._create_pending_block(
        client=client, target=ATTACKER, ai_reasoning="x", db=db, incident_id=inc.id,
        alert_data={"rule_id": rid, "pattern": rid}, severity="medium", threat_type="unknown")
    assert pending.status == "pending" and pending.requires_approval

    # control: a shipped rule's block is untouched
    inc2 = await _incident(db, "http_auth_brute_force", "203.0.113.99")
    ok = await guardrail_engine.evaluate_action(client, "block_ip", "203.0.113.99", "x", db, incident_id=inc2.id)
    assert ok.status == "approved"


@pytest.mark.asyncio
async def test_only_an_operator_promotes_and_any_edit_revokes_it(db, traffic):
    out = await svc.create(db, AI, draft(), enable=True)
    rid = out.rule.id
    with pytest.raises(RuleRefused) as e:
        await svc.promote(db, AI, rid)
    assert e.value.code == "operator_only"

    promoted = await svc.promote(db, OP, rid, note="looks right")
    assert promoted.rule.mode == "blocking" and promoted.rule.approved and not registry.is_alert_only(rid)
    inc = await _incident(db, rid)
    client = await db.get(Client, "c1")
    assert (await guardrail_engine.evaluate_action(client, "block_ip", ATTACKER, "x", db, incident_id=inc.id)).status == "approved"

    # the AI "improves" the filter: approval was for different content
    edited = await svc.update(db, AI, rid, draft(filt={"path_contains": ["/debug/console.php", "/debug/other.php"]}))
    assert edited.rule.mode == "alert_only" and registry.is_alert_only(rid)
    # a hand edit of the file (operator or not) drops it too
    live = svc._read_live(rid)
    live["authoring"]["mode"] = "blocking"
    live["condition"]["filter"]["path_contains"].append("/debug/third.php")
    registry.rule_path(rid).write_text(yaml.safe_dump(live))
    registry.invalidate()
    assert registry.is_alert_only(rid)


@pytest.mark.asyncio
async def test_confirmed_class_needs_a_signature_and_an_operator(db, traffic):
    weak = await svc.create(db, OP, draft(filt={"path_contains": ["/cgi-bin/"]}), enable=True)
    with pytest.raises(RuleRefused) as e:
        await svc.promote(db, OP, weak.rule.id, block_class="confirmed")
    assert e.value.code == "not_a_signature"

    sig = draft(name="Solr cores exploit", severity="high", filt={"path_contains": ["/solr/admin/cores?action="]}, threshold=1)
    out = await svc.create(db, OP, sig, enable=True)
    assert bp.classify(rule_ids=[out.rule.id]).kind == bp.AMBIGUOUS         # before approval
    await svc.promote(db, OP, out.rule.id, block_class="confirmed")
    assert bp.classify(rule_ids=[out.rule.id]).kind == bp.CONFIRMED          # classification recorded in the file
    await svc.demote(db, OP, out.rule.id)
    assert bp.classify(rule_ids=[out.rule.id]).kind == bp.AMBIGUOUS


# --- 5. versioning and rollback --------------------------------------------

@pytest.mark.asyncio
async def test_revert_restores_the_previous_version_and_is_itself_revertable(db, traffic):
    v1 = await svc.create(db, OP, draft(), enable=False)
    rid = v1.rule.id
    orig = svc._read_live(rid)["condition"]["filter"]
    await svc.update(db, OP, rid, draft(filt={"path_contains": ["/debug/changed.php"]}))
    assert svc._read_live(rid)["condition"]["filter"] != orig

    back = await svc.revert(db, OP, rid)
    live = svc._read_live(rid)
    assert live["condition"]["filter"] == orig
    assert live["authoring"]["version"] == 3 and live["authoring"]["last_change"] == "revert"
    versions = {h.version: h for h in back.rule.history}
    assert set(versions) == {1, 2} and versions[2].saved_by == "operator:owner@example.com"

    # the version we reverted away from is still there: revert the revert
    await svc.revert(db, OP, rid, to_version=2)
    assert svc._read_live(rid)["condition"]["filter"] == {"path_contains": ["/debug/changed.php"]}


@pytest.mark.asyncio
async def test_delete_is_revertable_and_revert_does_not_skip_the_gate(db, traffic, monkeypatch):
    out = await svc.create(db, OP, draft(), enable=True)
    rid = out.rule.id
    await svc.delete(db, OP, rid)
    assert not registry.rule_path(rid).exists() and svc.get_detail(rid) is None
    restored = await svc.revert(db, OP, rid)
    assert restored.rule.id == rid and registry.rule_path(rid).exists() and not restored.rule.enabled   # never resurrected enabled

    # an enabled rule reverted onto a body that now matches the owner is stopped
    await svc.set_enabled(db, OP, rid, True)
    await svc.update(db, OP, rid, draft(filt={"path_contains": ["/debug/second.php"]}))
    monkeypatch.setenv("AEGIS_INTERNAL_IPS", OWNER_IP)
    traffic(_traffic(extra=[_ev(OWNER_IP, "/debug/console.php")]))
    with pytest.raises(RuleRefused) as e:
        await svc.revert(db, OP, rid)
    assert e.value.code == "dry_run_blocked"


@pytest.mark.asyncio
async def test_every_change_is_audited(db, traffic):
    out = await svc.create(db, OP, draft())
    rid = out.rule.id
    await svc.update(db, OP, rid, draft(filt={"path_contains": ["/debug/changed.php"]}))
    await svc.set_enabled(db, OP, rid, True)
    await svc.set_enabled(db, OP, rid, False)
    await svc.revert(db, OP, rid)
    acts = [r.action for r in (await db.execute(select(AuditLog).order_by(AuditLog.timestamp))).scalars()]
    assert sorted(acts) == sorted(["rule_create", "rule_update", "rule_enable", "rule_disable", "rule_revert"])


# --- 6. block_policy classification is not a code edit ----------------------

@pytest.mark.asyncio
async def test_runtime_rules_do_not_touch_the_classification_test(db, traffic):
    out = await svc.create(db, OP, draft(), enable=True)
    rules_tree = Path(__file__).resolve().parents[2] / "app" / "rules"
    assert registry.authored_dir().resolve() not in rules_tree.resolve().parents
    assert registry.rule_path(out.rule.id).exists()
    # the existing test scans app/rules for sigma_web_* ids: nothing new appears there
    ids = {m.group(1) for f in rules_tree.rglob("*.yaml")
           for m in [re.search(r"^id:\s*(\S+)", f.read_text(), re.M)] if m and m.group(1).startswith("sigma_web_")}
    assert not (ids - bp.CONFIRMED_IDS - bp.AMBIGUOUS_KNOWN)
    assert out.rule.id.startswith("authored_") and bp.classify(rule_ids=[out.rule.id]).kind == bp.AMBIGUOUS


def test_default_rule_pack_loads_authored_rules_from_outside_the_repo(tmp_path, monkeypatch):
    d = tmp_path / "authored"
    d.mkdir()
    (d / "authored_x_probe.yaml").write_text(yaml.safe_dump(_vd(id="authored_x_probe")))
    (d / "authored_dup.yaml").write_text(yaml.safe_dump(_vd(id="sigma_web_xss_reflected")))   # id of a shipped rule
    monkeypatch.setenv("AEGIS_AUTHORED_RULES_DIR", str(d))
    from app.services.rules_loader import load_rules
    pack = load_rules()
    assert "authored_x_probe" in pack.by_id
    assert pack.by_id["sigma_web_xss_reflected"].id == "sigma_web_xss_reflected"
    assert getattr(pack.by_id["sigma_web_xss_reflected"], "name", "") != "t"       # the shipped rule won


# --- 7. vulnerability flow --------------------------------------------------

STRUTS_TEXT = ("Apache Struts allows remote code execution through a crafted POST to /struts2-showcase/upload.action "
               "using the parameter filename and an X-Forwarded-Host header.")


@pytest.mark.asyncio
async def test_not_applicable_when_the_software_is_absent(db, traffic):
    out = await rule_vuln_advisor.protect(db, OP, ProtectIn(
        description=STRUTS_TEXT, software=["Apache Struts"], stack=["next.js", "postgresql", "nginx"]))
    assert out.applicability == "not_applicable"
    assert out.proposal is None and out.created is None
    assert "Not applicable" in out.summary
    row = (await db.execute(select(AuditLog).where(AuditLog.action == "rule_protect"))).scalar_one()
    assert json.loads(row.decision)["applicability"] == "not_applicable"


@pytest.mark.asyncio
async def test_applicable_flow_labels_unverified_and_lists_undetectable_indicators(db, traffic):
    out = await rule_vuln_advisor.protect(db, OP, ProtectIn(
        description=STRUTS_TEXT, software=["Apache Struts"], stack=["struts", "nginx"]))
    assert out.applicability == "applicable" and out.verification == "unverified_description"
    assert out.unverified_notice and "UNVERIFIED" in out.unverified_notice
    by_kind = {(i.kind, i.value): i for i in out.indicators}
    assert by_kind[("path", "/struts2-showcase/upload.action")].detectable_in_http_logs
    assert by_kind[("method", "POST")].detectable_in_http_logs
    assert not by_kind[("header", "X-Forwarded-Host")].detectable_in_http_logs
    assert out.proposal and out.proposal.can_create and "UNVERIFIED" in out.proposal.yaml
    assert out.created is None                                       # nothing written unless asked
    assert not registry.states()

    row = (await db.execute(select(AuditLog).where(AuditLog.action == "rule_protect"))).scalar_one()
    assert "UNVERIFIED" in row.ai_reasoning and json.loads(row.decision)["unverified"] is True


@pytest.mark.asyncio
async def test_protect_create_writes_a_disabled_alert_only_unverified_rule(db, traffic):
    out = await rule_vuln_advisor.protect(db, AI, ProtectIn(
        cve_id="CVE-2099-0001", description=STRUTS_TEXT, software=["Apache Struts"], stack=["struts"], create=True))
    assert out.created and not out.created.rule.enabled and out.created.rule.mode == "alert_only"
    assert out.created.rule.unverified
    row = (await db.execute(select(AuditLog).where(AuditLog.action == "rule_create"))).scalar_one()
    assert "UNVERIFIED" in row.ai_reasoning


@pytest.mark.asyncio
async def test_unknown_when_nothing_is_known_and_no_invented_product(db, traffic):
    out = await rule_vuln_advisor.protect(db, OP, ProtectIn(cve_id="CVE-2099-0002", stack=["nginx"]))
    assert out.applicability == "unknown" and out.proposal is None and out.verification == "none"
    empty_stack = await rule_vuln_advisor.protect(db, OP, ProtectIn(description=STRUTS_TEXT, software=["Apache Struts"], stack=[]))
    assert empty_stack.applicability == "unknown" and not empty_stack.stack_known


@pytest.mark.asyncio
async def test_a_cve_already_covered_by_a_shipped_rule_gets_no_duplicate(db, traffic):
    out = await rule_vuln_advisor.protect(db, OP, ProtectIn(cve_id="CVE-2025-34026", stack=["versa concerto"]))
    assert out.already_covered_by and out.proposal is None
    assert out.verification == "verified_local_rule"


def test_router_is_mounted():
    from app.api.rules import router
    paths = {(m, r.path) for r in router.routes for m in r.methods}
    assert ("POST", "/rules/propose") in paths and ("POST", "/rules/protect") in paths
    assert ("POST", "/rules/{rule_id}/revert") in paths and ("POST", "/rules/{rule_id}/promote") in paths


# --- strongest signal wins; escalation cannot reach an alert-only rule -------

async def _ai_rule(db):
    return (await svc.create(db, AI, draft(), enable=True)).rule.id


@pytest.mark.asyncio
async def test_alert_only_rule_never_vetoes_a_confirmed_block(db, traffic):
    rid = await _ai_rule(db)
    client = await db.get(Client, "c1")
    cve = "sigma_cve_versa_concerto_2025_34026"
    alert = {"rule_id": cve, "pattern": cve, "sigma_matches": [{"id": rid}, {"id": cve}]}
    inc = Incident(client_id="c1", title="t", severity="high", source_ip=ATTACKER, raw_alert=alert)
    db.add(inc)
    await db.commit()
    a = await ai_engine._create_pending_block(
        client=client, target=ATTACKER, ai_reasoning="x", db=db, incident_id=inc.id,
        alert_data=alert, severity="high", threat_type="rce")
    assert a.status == "approved" and not a.requires_approval
    assert a.parameters.get("permanent") and a.parameters.get("block_class") == bp.CONFIRMED
    # and through the guardrail path
    g = await guardrail_engine.evaluate_action(client, "block_ip", "203.0.113.8", "x", db, incident_id=inc.id)
    assert g.status == "approved"
    # an alert-only rule alongside a merely AMBIGUOUS shipped rule does not veto either
    assert registry.blocking_held_by([rid, "http_auth_brute_force"]) == []
    assert registry.blocking_held_by([rid]) == [rid]


@pytest.mark.asyncio
async def test_repeat_firing_of_an_alert_only_rule_never_escalates_to_a_block(db, traffic, monkeypatch):
    """The boundary between an AI-authored rule and a permanent block."""
    monkeypatch.setenv("AEGIS_BLOCK_ESCALATE_AFTER", "1")
    rid = await _ai_rule(db)
    client = await db.get(Client, "c1")
    # a prior executed block inside the 30-day window: the escalation trigger
    db.add(Action(incident_id="", client_id="c1", action_type="block_ip", target=ATTACKER,
                  parameters={"provisional": True}, status="executed", requires_approval=False))
    await db.commit()
    alert = {"rule_id": rid, "pattern": rid}
    results = []
    for threat in ("unknown", "sql_injection", "rce"):         # AI mislabelling must not matter
        for sev in ("medium", "critical"):
            inc = Incident(client_id="c1", title="t", severity=sev, source_ip=ATTACKER, raw_alert=alert)
            db.add(inc)
            await db.commit()
            results.append(await ai_engine._create_pending_block(
                client=client, target=ATTACKER, ai_reasoning="x", db=db, incident_id=inc.id,
                alert_data=alert, severity=sev, threat_type=threat))
            results.append(await guardrail_engine.evaluate_action(
                client, "block_ip", ATTACKER, "x", db, incident_id=inc.id))
    assert results and all(r.status == "pending" and r.requires_approval for r in results)
    assert not any((r.parameters or {}).get("permanent") for r in results)
    # nothing it produced is live: only the pre-seeded provisional block covers the IP
    live = await bp.live_block_actions(db, ATTACKER)
    assert [a.id for a in live] == [a.id for a in live if (a.parameters or {}) == {"provisional": True}]
    # the responder refuses it too, even if an action were somehow approved without operator_approved
    from app.modules.response.responder import ActiveResponder
    out = await ActiveResponder()._block_ip("203.0.113.9", {"rule_id": rid})
    assert out.get("skipped") == "alert_only_rule"
