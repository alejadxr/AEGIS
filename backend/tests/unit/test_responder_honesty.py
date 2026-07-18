import pytest
from app.modules.response.responder import ActiveResponder

@pytest.mark.asyncio
@pytest.mark.parametrize("method", [
    "_isolate_host", "_kill_process", "_quarantine_file", "_revoke_credentials",
    "_disable_account", "_shutdown_service", "_network_segment",
])
async def test_unimplemented_actions_report_not_implemented(method):
    r = ActiveResponder()
    result = await getattr(r, method)("1.2.3.4", {})
    assert result["success"] is False
    assert result.get("status") == "not_implemented"
