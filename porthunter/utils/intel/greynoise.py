from __future__ import annotations
import os, requests
from typing import Dict, Any

def greynoise_enrich(ip: str, api_key: str | None) -> Dict[str, Any]:
    if not api_key:
        return {"enabled": False}
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"Accept": "application/json", "key": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 401:
            return {"enabled": False, "error": "unauthorized"}
        if r.status_code == 404:
            return {"enabled": True, "found": False}
        r.raise_for_status()
        data = r.json()
        # Campos típicos: classification, name, last_seen, link, etc.
        return {
            "enabled": True,
            "found": True,
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "link": data.get("link")
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}
