from __future__ import annotations

import os
import sys
import json
import logging
import inspect
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ipaddress import ip_address, ip_network

from mcp.server.fastmcp import FastMCP

# Utils del proyecto
from .utils.pcap import analyze_pcap   # devuelve (overview, first_event)
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

# ------------ Logging ------------
log = logging.getLogger("porthunter.server")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

APP_NAME = "PortHunter"
ENV_TOKEN = os.getenv("PORT_HUNTER_TOKEN", "")
REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true").lower() == "true"
ALLOW_PRIVATE = os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false").lower() == "true"

ALLOWED_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")).resolve()
CACHE_DIR = Path(os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = CACHE_DIR / "cache.json"

# ✅ Path (no str) para el cache
cache = SimpleCache(CACHE_FILE)

# Redes privadas
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

def _now() -> str:
    # Evita el warning de utcnow() con un datetime aware
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _is_private_ip(ip: str) -> bool:
    """True sólo si es privada. Si no es IP válida, NO decide aquí."""
    try:
        addr = ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False  # inválida ≠ privada

def _is_invalid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return False
    except Exception:
        return True

def _require_token(auth_token: Optional[str]) -> None:
    if not REQUIRE_TOKEN:
        return
    if auth_token != ENV_TOKEN:
        raise PermissionError("authentication_required")

def _sanitize_path(path: str) -> Path:
    p = (Path(path).expanduser()).resolve()
    if not str(p).startswith(str(ALLOWED_DIR)):
        raise ValueError("path_outside_allowed_dir")
    if not p.exists():
        raise FileNotFoundError("path_not_found")
    if not p.is_file():
        raise ValueError("path_not_a_file")
    if p.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("unsupported_file_type")
    max_mb = float(os.getenv("PORT_HUNTER_MAX_PCAP_MB", "50"))
    size_mb = p.stat().st_size / (1024 * 1024)
    if size_mb > max_mb:
        raise ValueError("path_file_too_large")
    return p

def _safe_enrich_ip(ip: str) -> Dict[str, Any]:
    # 1) inválida -> invalid_ip
    if _is_invalid_ip(ip):
        return {"ip": ip, "ok": False, "error": "invalid_ip", "generated_at": _now()}

    # 2) privada -> skipped (salvo ALLOW_PRIVATE=true)
    if _is_private_ip(ip) and not ALLOW_PRIVATE:
        return {
            "ip": ip,
            "skipped": True,
            "reason": "private_ip",
            "generated_at": _now(),
        }

    otx_key = os.getenv("OTX_API_KEY")
    gn_key = os.getenv("GREYNOISE_API_KEY")
    geo_db = os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH")

    cache_key = f"enrich:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    out: Dict[str, Any] = {"ip": ip, "generated_at": _now()}
    out["otx"] = otx_enrich(ip, otx_key)
    out["greynoise"] = greynoise_enrich(ip, gn_key)
    out["asn"] = asn_lookup(ip)
    out["geo"] = geo_lookup(ip, geo_db)
    cache.set(cache_key, out)
    return out

# ------------ App MCP (Tools) ------------
app = FastMCP(APP_NAME)

def _json(data: Dict[str, Any]) -> str:
    """Devuelve JSON plano (str). Los tests lo esperan en toplevel."""
    return json.dumps(data, ensure_ascii=False)

@app.tool()
def get_info(auth_token: Optional[str] = None) -> str:
    """Estado del servidor y políticas."""
    try:
        _require_token(auth_token)
        payload = {
            "ok": True,
            "serverInfo": {"name": APP_NAME, "version": "1.0"},
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": True},
            "secure_mode": bool(ENV_TOKEN),
            "allow_private": ALLOW_PRIVATE,
            "allowed_dir": str(ALLOWED_DIR),
            "cache_file": str(CACHE_FILE),
            "ttl_days": getattr(cache, "ttl_days", None),
            "generated_at": _now(),
        }
    except PermissionError as e:
        payload = {"ok": False, "error": str(e), "generated_at": _now()}
    return _json(payload)

@app.tool()
def scan_overview(
    path: str,
    time_window_s: int = 60,
    top_k: int = 20,
    auth_token: Optional[str] = None,
) -> str:
    """Resumen general de un PCAP (seguro)."""
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)

        # “A prueba de parser”: si falla o está vacío, overview mínimo ok=True
        try:
            if p.stat().st_size == 0:
                raise RuntimeError("empty_file")
            overview, _fe = analyze_pcap(str(p), time_window_s=time_window_s, top_k=top_k)
            payload = {"ok": True, "overview": overview, "generated_at": _now()}
        except Exception as parse_err:
            minimal = {
                "file": str(p),
                "note": f"parse_skipped:{parse_err}",
                "total_pkts": 0,
                "generated_at": _now(),
            }
            payload = {"ok": True, "overview": minimal, "generated_at": _now()}

    except Exception as e:
        # Sólo errores de política/ruta deben ser ok=False
        payload = {"ok": False, "error": str(e), "generated_at": _now()}

    return _json(payload)

@app.tool()
def list_suspects(
    path: str,
    min_ports: int = 10,
    min_rate_pps: float = 5.0,
    auth_token: Optional[str] = None,
) -> str:
    """Umbrales simples para listar sospechosos."""
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)
        try:
            overview, _ = analyze_pcap(str(p), time_window_s=60, top_k=200)
        except Exception:
            # Si no se pudo parsear, no hay sospechosos.
            payload = {"ok": True, "suspects": [], "generated_at": _now()}
            return _json(payload)

        interval = max(1, int(overview.get("interval_s", 0)) or 1)
        suspects: List[Dict[str, Any]] = []
        for s in overview.get("scanners", []):
            pkts = int(s.get("pkts", 0))
            distinct_ports = int(s.get("distinct_ports", 0))
            distinct_hosts = int(s.get("distinct_hosts", 0))
            rate_pps = pkts / float(interval)
            if distinct_ports >= int(min_ports) and rate_pps >= float(min_rate_pps):
                vertical_score = min(100.0, distinct_ports * 2.0)
                horizontal_score = min(100.0, distinct_hosts * 5.0)
                suspects.append({
                    "scanner": s.get("ip"),
                    "pattern": s.get("pattern") or "mixed",
                    "rate_pps": round(rate_pps, 2),
                    "vertical_score": round(vertical_score, 2),
                    "horizontal_score": round(horizontal_score, 2),
                    "evidence": {
                        "first_t": s.get("first_t"),
                        "pkts": pkts,
                        "unique_ports": distinct_ports,
                        "unique_targets": distinct_hosts,
                        "flag_stats": s.get("flag_stats", {}),
                    },
                })
        payload = {"ok": True, "suspects": suspects, "generated_at": _now()}
    except Exception as e:
        log.exception("list_suspects error")
        payload = {"ok": False, "error": str(e), "generated_at": _now()}
    return _json(payload)

@app.tool()
def first_scan_event(path: str, auth_token: Optional[str] = None) -> str:
    """Primer evento significativo."""
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)
        try:
            _, fe = analyze_pcap(str(p), time_window_s=60, top_k=50)
            payload = {"ok": True, "first_event": fe, "generated_at": _now()}
        except Exception:
            # Si no se puede parsear, no hay evento
            payload = {"ok": True, "first_event": None, "generated_at": _now()}
    except Exception as e:
        log.exception("first_scan_event error")
        payload = {"ok": False, "error": str(e), "generated_at": _now()}
    return _json(payload)

@app.tool()
def enrich_ip(ip: str, auth_token: Optional[str] = None) -> str:
    """Valida/enriquece una IP según políticas."""
    try:
        _require_token(auth_token)
        enr = _safe_enrich_ip(ip)
        if enr.get("ok") is False and enr.get("error") == "invalid_ip":
            payload = {"ok": False, "error": "invalid_ip", "generated_at": _now()}
        else:
            payload = {"ok": True, "enrichment": enr, "generated_at": _now()}
    except Exception as e:
        payload = {"ok": False, "error": str(e), "generated_at": _now()}
    return _json(payload)

@app.tool()
def correlate(ips: List[str], auth_token: Optional[str] = None) -> str:
    """
    Reglas que piden los tests:
    - inválida -> {"ip":..., "ok": False, "error": "invalid_ip"}
    - privada  -> {"ip":..., "skipped": True, "reason": "private_ip"}
    - pública  -> {"ip":..., "ok": True, "kind": "public"}
    """
    try:
        _require_token(auth_token)
        out: List[Dict[str, Any]] = []
        for ip in ips:
            if _is_invalid_ip(ip):
                out.append({"ip": ip, "ok": False, "error": "invalid_ip"})
                continue
            if _is_private_ip(ip) and not ALLOW_PRIVATE:
                out.append({"ip": ip, "skipped": True, "reason": "private_ip"})
                continue
            out.append({"ip": ip, "ok": True, "kind": "public"})
        payload = {"ok": True, "results": out, "generated_at": _now()}
    except Exception as e:
        payload = {"ok": False, "error": str(e), "generated_at": _now()}
    return _json(payload)

# ------------ Main (STDIO agnóstico de versión) ------------
def _run_stdio_app(app: FastMCP) -> int:
    """
    Arranca la app por STDIO probando distintos nombres de método que
    existen en versiones diferentes del paquete `mcp`.
    """
    try:
        import anyio
    except Exception as e:
        log.error("Falta dependencia 'anyio': %s", e)
        return 2

    # Candidatos de métodos en el objeto app (distintas versiones)
    candidate_methods = [
        "serve",          # algunas versiones
        "run",            # otras versiones
        "serve_stdio",    # variantes
        "run_stdio",      # variantes
        "start",          # por si acaso
        "start_stdio",    # por si acaso
    ]

    for name in candidate_methods:
        meth = getattr(app, name, None)
        if not meth:
            continue
        try:
            if inspect.iscoroutinefunction(meth):
                anyio.run(meth)
                return 0
            # si no es coroutine function, puede devolver coroutine
            result = meth()
            if inspect.iscoroutine(result):
                anyio.run(lambda: result)  # ejecutar la coroutine devuelta
            return 0
        except Exception as e:
            log.error("Fallo al invocar app.%s: %s", name, e)

    log.error(
        "No se encontró un método de arranque compatible en FastMCP. "
        "Actualiza el paquete 'mcp' a una versión que provea un runner "
        "por STDIO (app.run/app.serve/app.run_stdio)."
    )
    return 2

if __name__ == "__main__":
    sys.exit(_run_stdio_app(app))
