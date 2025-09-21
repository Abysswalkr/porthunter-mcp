from __future__ import annotations
from ipwhois import IPWhois

def asn_lookup(ip: str) -> dict:
    """
    RDAP lookup sin llaves. Útil para obtener ASN y organización.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "asn": res.get("asn"),
            "org": res.get("asn_description") or res.get("network", {}).get("name"),
            "source": "rdap"
        }
    except Exception as e:
        return {"error": str(e)}
