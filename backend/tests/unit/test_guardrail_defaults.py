from app.core.guardrails import DEFAULT_GUARDRAILS


def test_destructive_actions_require_approval():
    for action in ("isolate_host", "disable_account", "shutdown_service",
                   "network_segment", "revoke_creds", "quarantine_file",
                   "kill_process", "counter_attack", "recon_attacker"):
        assert DEFAULT_GUARDRAILS[action] == "require_approval", action


def test_block_ip_stays_auto():
    assert DEFAULT_GUARDRAILS["block_ip"] == "auto_approve"
