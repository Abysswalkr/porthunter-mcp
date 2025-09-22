import pytest
from ._mcp_client import call_tool

TOKEN = "TEST_TOKEN"

@pytest.mark.asyncio
async def test_enrich_rejects_invalid_ip():
    data = await call_tool("enrich_ip", {"ip": "999.999.1.1", "auth_token": TOKEN})
    assert isinstance(data, dict)
    assert data.get("ok") is False
    assert data.get("error") == "invalid_ip"
