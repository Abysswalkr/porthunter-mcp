import os
import sys
import time
import json
import asyncio
from pathlib import Path
from typing import Any, Dict

from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PCAP_DIR = ROOT_DIR / "captures"

TOKEN = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", str(DEFAULT_PCAP_DIR))).resolve()

SERVER_ENV = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "PORT_HUNTER_REQUIRE_TOKEN": os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true"),
    "PORT_HUNTER_MAX_PCAP_MB": os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200"),
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
}

PORT_HUNTER = StdioServerParameters(
    command=sys.executable,
    args=["-m", "porthunter.server"],   # <- lo mismo que usa tu CLI
    env=SERVER_ENV,
)

async def _call_tool(name: str, arguments: Dict[str, Any], timeout_s: float = 30.0) -> Any:
    async with stdio_client(PORT_HUNTER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            rsp = await asyncio.wait_for(
                session.call_tool(name=name, arguments=arguments),
                timeout=timeout_s,
            )
            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict):
                return sc
            if rsp.content:
                txt = ""
                for block in rsp.content:
                    if isinstance(block, types.TextContent):
                        txt += block.text
                if txt:
                    try:
                        return json.loads(txt)
                    except Exception:
                        return txt
            return None

def _abs_pcap(path: str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (PCAP_DIR / p).resolve()
    return str(p)

async def run_bench(pcap_name: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {"pcap": pcap_name}

    t0 = time.perf_counter()
    info = await _call_tool("get_info", {"auth_token": TOKEN})
    t1 = time.perf_counter()

    p = _abs_pcap(pcap_name)
    ov0 = time.perf_counter()
    overview = await _call_tool("scan_overview", {"path": p, "auth_token": TOKEN})
    ov1 = time.perf_counter()

    fe0 = time.perf_counter()
    first = await _call_tool("first_scan_event", {"path": p, "auth_token": TOKEN})
    fe1 = time.perf_counter()

    results["get_info_s"] = round(t1 - t0, 3)
    results["overview_s"] = round(ov1 - ov0, 3)
    results["first_event_s"] = round(fe1 - fe0, 3)

    try:
        ov = overview.get("overview", {})
        results["total_pkts"] = ov.get("total_pkts")
        results["interval_s"] = ov.get("interval_s")
        results["suspected_patterns"] = ov.get("suspected_patterns", [])
        results["scanners_count"] = len(ov.get("scanners", []))
    except Exception:
        pass

    results["ok"] = bool(overview and first)
    return results

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Benchmark PortHunter (MCP stdio)")
    ap.add_argument("pcap", help="Archivo .pcap o .pcapng dentro de PORT_HUNTER_ALLOWED_DIR")
    args = ap.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(run_bench(args.pcap))
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
