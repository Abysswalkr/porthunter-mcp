import os, pytest
from pathlib import Path
from ._mcp_client import call_tool

TOKEN = "TEST_TOKEN"

@pytest.mark.asyncio
async def test_overview_rejects_bad_extension(tmp_path):
    bad = tmp_path / "malicioso.zip"
    bad.write_bytes(b"not a pcap")
    # Limitar sandbox al tmp para esta prueba
    os.environ["PORT_HUNTER_ALLOWED_DIR"] = str(tmp_path)
    data = await call_tool("scan_overview", {"path": str(bad), "auth_token": TOKEN})
    assert isinstance(data, dict)
    assert data.get("ok") is False
    assert data.get("error") == "unsupported_file_type"
