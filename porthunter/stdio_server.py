from __future__ import annotations

import os
import sys
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import re
from datetime import datetime, UTC
from ipaddress import ip_address, ip_network

logging.basicConfig(
    level=os.getenv("PORT_HUNTER_LOG_LEVEL", "WARNING"),
    stream=sys.stderr,
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("porthunter.stdio_server")

APP_NAME = "PortHunter MCP (stdio)"
ENV_TOKEN = os.getenv("PORT_HUNTER_TOKEN")
ALLOWED_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")).resolve()
ALLOW_PRIVATE = os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false").lower() in {"1", "true", "yes"}
CACHE_DIR = Path(os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
try:
    _ttl_days = int(os.getenv("PORT_HUNTER_CACHE_TTL_DAYS", "7"))
except Exception:
    _ttl_days = 7

from .utils.pcap import analyze_pcap   # devuelve (overview, first_event)
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

CACHE_FILE = CACHE_DIR / "intel_cache.json"
cache = SimpleCache(CACHE_FILE, ttl_seconds=_ttl_days * 24 * 3600)

# --- NUEVOS límites y banderas de seguridad (configurables por .env) ---
REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true").lower() in {"1", "true", "yes"}
MAX_PCAP_MB   = int(os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200"))  # tamaño duro por archivo
ALLOWED_EXTS  = {".pcap", ".pcapng"}
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# -----------------------------------------------------------------------

_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

# --- reemplazada (igual forma pero explícita) ---
def _now() -> str:
    return datetime.now(UTC).isoformat()  # timezone-aware, sin warning

def _is_private_ip(ip: str) -> bool:
    try:
        a = ip_address(ip)
        return any(a in n for n in _PRIVATE_NETS)
    except Exception:
        return True

# --- helper nuevo: validar IP (v4/v6) ---
def _is_valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)  # acepta v4/v6
        return True
    except Exception:
        return False

# --- reemplazada: ahora respeta REQUIRE_TOKEN y valida configuración ---
def _require_token(auth: Optional[str]) -> None:
    """
    Si REQUIRE_TOKEN=true, rechaza todas las llamadas sin un token que
    coincida con PORT_HUNTER_TOKEN.
    """
    if not REQUIRE_TOKEN:
        return
    if not ENV_TOKEN:
        raise PermissionError("server_misconfigured: missing PORT_HUNTER_TOKEN")
    if auth != ENV_TOKEN:
        raise PermissionError("authentication_required")

# --- reemplazada: ahora fuerza extensión válida y tamaño máximo ---
def _sanitize_path(path: str) -> Path:
    """
    1) normaliza y restringe a ALLOWED_DIR
    2) obliga a extensión permitida
    3) limita tamaño de archivo (MAX_PCAP_MB)
    """
    p = (Path(path).expanduser()).resolve()
    if not str(p).startswith(str(ALLOWED_DIR)):
        raise ValueError("path_outside_allowed_dir")
    if not p.exists():
        raise FileNotFoundError("path_not_found")
    if not p.is_file():
        raise ValueError("path_not_a_file")
    if p.suffix.lower() not in ALLOWED_EXTS:
        raise ValueError("unsupported_file_type")
    try:
        size_mb = p.stat().st_size / (1024 * 1024)
    except Exception:
        size_mb = MAX_PCAP_MB + 1  # fuerza rechazo si falla
    if size_mb > MAX_PCAP_MB:
        raise ValueError(f"file_too_large:{int(size_mb)}MB>{MAX_PCAP_MB}MB")
    return p

def _safe_enrich_ip(ip: str) -> Dict[str, Any]:
    if _is_private_ip(ip) and not ALLOW_PRIVATE:
        return {"ip": ip, "skipped": True, "reason": "private_or_local_ip", "generated_at": _now()}
    cache_key = f"enrich:{ip}"
    c = cache.get(cache_key)
    if c:
        return c
    otx_key = os.getenv("OTX_API_KEY", "")
    gn_key  = os.getenv("GREYNOISE_API_KEY", "")
    geo_db  = os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH")
    out = {
        "ip": ip,
        "generated_at": _now(),
        "otx": otx_enrich(ip, otx_key),
        "greynoise": greynoise_enrich(ip, gn_key),
        "asn": asn_lookup(ip),
        "geo": geo_lookup(ip, geo_db),
    }
    cache.set(cache_key, out)
    return out

# ---------- Framing JSON-RPC (LSP-like) ----------
def _read_headers(fin) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    line = b""
    while True:
        ch = fin.read(1)
        if not ch:
            return {}
        line += ch
        if line.endswith(b"\r\n"):
            s = line.decode("utf-8", "replace").strip("\r\n")
            line = b""
            if s == "":
                return headers
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip().lower()] = v.strip()

def _read_msg(fin) -> Optional[Dict[str, Any]]:
    headers = _read_headers(fin)
    if not headers:
        return None
    try:
        clen = int(headers.get("content-length", "0"))
    except Exception:
        return None
    if clen <= 0:
        return None
    body = fin.read(clen)
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None

def _write_msg(fout, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = (
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"\r\n"
    ).encode("ascii")
    fout.write(header)
    fout.write(body)
    fout.flush()

# ---------- Tools ----------
TOOLS_SPEC = [
    {"name": "get_info", "description": "Estado del servidor PortHunter y capacidades."},
    {"name": "scan_overview", "description": "Resumen de actividad (scanners, puertos, targets)."},
    {"name": "first_scan_event", "description": "Primer evento de escaneo detectado en el PCAP."},
    {"name": "list_suspects", "description": "Lista de IPs sospechosas por umbrales básicos."},
    {"name": "enrich_ip", "description": "Enriquecimiento OTX, GreyNoise, ASN, Geo de una IP."},
    {"name": "correlate", "description": "Puntaje simple 0–100 por IP a partir de enriquecimientos."},
]

def _handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": APP_NAME, "version": "1.0"},
        "capabilities": {"tools": True},
    }

def _handle_tools_list(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"tools": TOOLS_SPEC}

def _handle_tools_call(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}

    if name == "get_info":
        try:
            _require_token(arguments.get("auth_token"))
            data = {
                "ok": True,
                "serverInfo": {"name": APP_NAME, "version": "1.0"},
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": True},
                "secure_mode": bool(ENV_TOKEN),
                "allow_private": ALLOW_PRIVATE,
                "allowed_dir": str(ALLOWED_DIR),
                "cache_file": str(CACHE_FILE),
                "ttl_days": _ttl_days,
                "generated_at": _now(),
            }
        except PermissionError as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    if name == "scan_overview":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            tw = int(arguments.get("time_window_s", 60))
            tk = int(arguments.get("top_k", 20))
            overview, first_event = analyze_pcap(str(p), time_window_s=tw, top_k=tk)
            data = {"ok": True, "overview": overview, "first_event": first_event, "generated_at": _now()}
        except Exception as e:
            log.exception("scan_overview error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    if name == "first_scan_event":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            _, fe = analyze_pcap(str(p), time_window_s=60, top_k=50)
            data = {"ok": True, "first_event": fe, "generated_at": _now()}
        except Exception as e:
            log.exception("first_scan_event error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    if name == "list_suspects":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            overview, _ = analyze_pcap(str(p), time_window_s=60, top_k=200)
            interval = max(1, int(overview.get("interval_s", 0)) or 1)
            suspects: List[Dict[str, Any]] = []
            for s in overview.get("scanners", []):
                pkts = int(s.get("pkts", 0))
                dp = int(s.get("distinct_ports", 0))
                dh = int(s.get("distinct_hosts", 0))
                rate = pkts / float(interval)
                if dp >= int(arguments.get("min_ports", 2)) and rate >= float(arguments.get("min_rate_pps", 1.0)):
                    suspects.append({
                        "scanner": s.get("ip"),
                        "pattern": s.get("pattern") or "mixed",
                        "rate_pps": round(rate, 2),
                        "evidence": {
                            "first_t": s.get("first_t"),
                            "pkts": pkts,
                            "unique_ports": dp,
                            "unique_targets": dh,
                            "flag_stats": s.get("flag_stats", {}),
                        },
                    })
            data = {"ok": True, "suspects": suspects, "generated_at": _now()}
        except Exception as e:
            log.exception("list_suspects error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    if name == "enrich_ip":
        # --- reemplazado: valida token + IP antes de enriquecer ---
        try:
            _require_token(arguments.get("auth_token"))
            ip = str(arguments.get("ip", "")).strip()
            if not _is_valid_ip(ip):
                raise ValueError("invalid_ip")
            data = {"ok": True, "enrichment": _safe_enrich_ip(ip), "generated_at": _now()}
        except Exception as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    if name == "correlate":
        # --- reemplazado: valida IPs, marca inválidas con ok:false, conserva rationale ---
        try:
            _require_token(arguments.get("auth_token"))
            ips_in = list(arguments.get("ips") or [])
            out: List[Dict[str, Any]] = []
            for ip in ips_in:
                ip = str(ip).strip()
                if not _is_valid_ip(ip):
                    out.append({"ip": ip, "ok": False, "error": "invalid_ip"})
                    continue
                enr = _safe_enrich_ip(ip)
                if enr.get("skipped"):
                    out.append({
                        "ip": ip,
                        "skipped": True,
                        "reason": enr.get("reason"),
                        "threat_score": 0,
                        "rationale": ["private_ip"],
                    })
                    continue
                score = 0
                rationale: List[str] = []
                otx = enr.get("otx", {})
                if otx.get("enabled") and otx.get("pulse_count", 0) > 0:
                    score += min(40, 10 + otx["pulse_count"] * 2)
                    rationale.append(f"otx:pulses={otx['pulse_count']}")
                gn = enr.get("greynoise", {})
                if gn.get("enabled") and gn.get("found"):
                    score += 20
                    rationale.append(f"greynoise:{gn.get('classification')}")
                asn = enr.get("asn", {})
                org = (asn.get("org") or "").lower()
                if any(k in org for k in ["cloud", "aws", "azure", "google", "digitalocean", "hosting"]):
                    score += 10
                    rationale.append("asn:cloud")
                geo = enr.get("geo", {})
                if geo.get("enabled") and geo.get("country"):
                    rationale.append(f"geo:{geo.get('country')}")
                out.append({"ip": ip, "threat_score": min(100, score), "rationale": rationale})
            data = {"ok": True, "results": out, "generated_at": _now()}
        except Exception as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return {"content": [{"type": "json", "data": data}]}

    return {"content": [{"type": "json", "data": {"ok": False, "error": "unknown_tool"}}]}

# ---------- Bucle principal ----------
def _handle_request(req: Dict[str, Any]) -> Dict[str, Any]:
    rid = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    try:
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_initialize(params)}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_tools_list(params)}
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_tools_call(params)}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
    except Exception as e:
        log.exception("error at handling request")
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}}

def main() -> None:
    fin = sys.stdin.buffer
    fout = sys.stdout.buffer
    while True:
        req = _read_msg(fin)
        if req is None:
            break
        resp = _handle_request(req)
        _write_msg(fout, resp)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
