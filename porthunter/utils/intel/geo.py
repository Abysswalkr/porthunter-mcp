from __future__ import annotations
from typing import Optional, Dict, Any

def geo_lookup(ip: str, db_path: Optional[str]) -> Dict[str, Any]:
    if not db_path:
        return {"enabled": False}
    try:
        import geoip2.database  # type: ignore
    except Exception:
        return {"enabled": False, "error": "geoip2 not installed"}
    try:
        with geoip2.database.Reader(db_path) as reader:
            resp = reader.city(ip)
            return {
                "enabled": True,
                "country": getattr(resp.country, "iso_code", None),
                "city": (resp.city.names or {}).get("en")
            }
    except Exception as e:
        return {"enabled": True, "error": str(e)}
