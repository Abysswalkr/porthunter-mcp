from __future__ import annotations
import os, requests
from typing import Dict, Any, Optional
from urllib.parse import quote

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators/IPv4"

def otx_enrich(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    url = f"{OTX_BASE}/{quote(ip)}/general"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 401:
            return {"enabled": False, "error": "unauthorized"}
        r.raise_for_status()
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulses = [p.get("name") for p in pulse_info.get("pulses", []) if isinstance(p, dict)]
        return {
            "enabled": True,
            "pulse_count": pulse_info.get("count", 0),
            "pulses": pulses[:10],
            "indicator": data.get("indicator"),
            "country": (data.get("country_code") or data.get("country")),
            "raw_excerpt": {"sections": list(data.keys())[:10]}  # info superficial sin sobrecargar
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}
