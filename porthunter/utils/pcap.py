from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -------------------------------------------------
#  Carga perezosa de Scapy
# -------------------------------------------------
_SCAPY = None

def _get_scapy():
    """Importa scapy solo cuando se necesita y desactiva backends pcap para lectura de archivos."""
    global _SCAPY
    if _SCAPY is None:
        import warnings
        warnings.filterwarnings("ignore")
        import scapy.all as sc  # type: ignore
        try:
            sc.conf.use_pcap = False
        except Exception:
            pass
        _SCAPY = sc
    return _SCAPY

def _resolve_layers(sc):
    """Obtiene referencias robustas a IP, TCP, IPv6 (distintas versiones de Scapy)."""
    IP = getattr(sc, "IP", None)
    TCP = getattr(sc, "TCP", None)
    IPv6 = getattr(sc, "IPv6", None)

    # Alternativos por módulos
    if IP is None or TCP is None:
        try:
            from scapy.layers.inet import IP as _IP, TCP as _TCP  # type: ignore
            IP = IP or _IP
            TCP = TCP or _TCP
        except Exception:
            pass
    if IPv6 is None:
        try:
            from scapy.layers.inet6 import IPv6 as _IPv6  # type: ignore
            IPv6 = _IPv6
        except Exception:
            pass

    if IP is None or TCP is None:
        raise RuntimeError("Scapy no expone capas IP/TCP. Actualiza Scapy: pip install -U scapy")
    return IP, TCP, IPv6

def _get_readers():
    """Devuelve posibles lectores (PcapReader/PcapNgReader) si existen en esta versión."""
    sc = _get_scapy()
    PR = getattr(sc, "PcapReader", None)
    PNR = getattr(sc, "PcapNgReader", None)

    # Intentos por módulos conocidos
    if PR is None:
        try:
            from scapy.utils import PcapReader as _PR  # type: ignore
            PR = _PR
        except Exception:
            pass
    if PNR is None:
        # Algunas versiones lo tienen en scapy.utils; otras en scapy.layers.pcapng
        ok = False
        try:
            from scapy.utils import PcapNgReader as _PNR  # type: ignore
            PNR = _PNR
            ok = True
        except Exception:
            pass
        if not ok:
            try:
                from scapy.layers.pcapng import PcapNgReader as _PNR  # type: ignore
                PNR = _PNR
            except Exception:
                pass

    # Fallbacks de solo-lectura cruda (no siempre presentes)
    if PR is None:
        try:
            from scapy.utils import RawPcapReader as _RPR  # type: ignore
            PR = _RPR
        except Exception:
            pass
    if PNR is None:
        try:
            from scapy.layers.pcapng import RawPcapNgReader as _RPNR  # type: ignore
            PNR = _RPNR
        except Exception:
            pass

    return PR, PNR

def _open_iter(path: str):
    """
    Iterador de paquetes:
      - Prefiere lectores en streaming (PcapReader/PcapNgReader/Raw*).
      - Si no hay, cae a rdpcap() (carga a memoria).
    """
    sc = _get_scapy()
    PR, PNR = _get_readers()
    p = Path(path)
    suf = p.suffix.lower()

    # pcapng primero
    if suf == ".pcapng" and PNR is not None:
        reader = PNR(str(p))
        # Todos los readers de Scapy se pueden iterar; cerramos al final
        try:
            for pkt in reader:
                yield pkt
        finally:
            try:
                reader.close()
            except Exception:
                pass
        return

    # pcap
    if suf == ".pcap" and PR is not None:
        reader = PR(str(p))
        try:
            for pkt in reader:
                yield pkt
        finally:
            try:
                reader.close()
            except Exception:
                pass
        return

    # Fallback: rdpcap (sirve para .pcap y .pcapng si la versión lo soporta)
    try:
        from scapy.utils import rdpcap  # type: ignore
    except Exception:
        rdpcap = getattr(sc, "rdpcap", None)

    if rdpcap is None:
        raise RuntimeError("Tu versión de Scapy no expone readers ni rdpcap(). Actualiza Scapy.")

    pkts = rdpcap(str(p))
    for pkt in pkts:
        yield pkt

# -------------------------------------------------
#  Flags & helpers
# -------------------------------------------------
SYN = 0x02
ACK = 0x10
FIN = 0x01
PSH = 0x08
URG = 0x20
RST = 0x04

def _ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")

def _is_public(ip: str) -> bool:
    try:
        obj = ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast)
    except Exception:
        return False

def _scan_kind(flags: int) -> Optional[str]:
    if flags == 0:
        return "null_scan"
    if (flags & FIN) and not (flags & (SYN | ACK | PSH | URG)):
        return "fin_scan"
    if (flags & FIN) and (flags & PSH) and (flags & URG) and not (flags & ACK):
        return "xmas_scan"
    if (flags & SYN) and not (flags & ACK):
        return "syn_scan"
    return None

def _dominant_pattern(flag_stats: Counter) -> str:
    syn = flag_stats.get("SYN", 0)
    fin = flag_stats.get("FIN", 0)
    psh = flag_stats.get("PSH", 0)
    urg = flag_stats.get("URG", 0)
    if syn >= max(fin, psh, urg):
        return "syn_scan"
    if fin > syn and fin >= max(psh, urg):
        return "fin_scan"
    if psh > 0 and urg > 0 and fin > 0:
        return "xmas_scan"
    return "null_or_mixed"

def _targets_top(src_stats, top_k: int):
    targets_counter = Counter()
    for st in src_stats.values():
        targets_counter.update(st["targets"])
    return [{"ip": ip, "hits": hits} for ip, hits in targets_counter.most_common(top_k)]

# -------------------------------------------------
#  Núcleo de análisis
# -------------------------------------------------
def analyze_pcap(path: str, time_window_s: int = 60, top_k: int = 20) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Recorre el PCAP/PCAPNG y devuelve:
      - overview: métricas agregadas y ranking de posibles 'scanners'
      - first_event: primer evento de escaneo detectado (o None)
    """
    sc = _get_scapy()
    IP, TCP, IPv6 = _resolve_layers(sc)

    total_pkts = 0
    t_first: Optional[float] = None
    t_last: Optional[float] = None

    src_stats = defaultdict(lambda: {
        "pkts": 0, "ports": set(), "targets": set(), "flag_stats": Counter(), "first_t": None
    })
    port_dist = Counter()
    patterns_seen = set()
    first_event: Optional[Dict[str, Any]] = None

    for pkt in _open_iter(path):
        total_pkts += 1
        ts = float(getattr(pkt, "time", 0.0))
        if t_first is None:
            t_first = ts
        t_last = ts

        ip_src = None
        ip_dst = None
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
        elif IPv6 is not None and pkt.haslayer(IPv6):
            ip_src = pkt[IPv6].src
            ip_dst = pkt[IPv6].dst
        else:
            continue

        if not pkt.haslayer(TCP):
            continue
        tcp = pkt[TCP]
        dport = int(tcp.dport)
        flags = int(tcp.flags)

        kind = _scan_kind(flags)
        if not kind:
            continue

        if first_event is None:
            first_event = {
                "t_first": _ts_iso(ts),
                "scanner": ip_src,
                "pattern": kind,
                "target": ip_dst,
                "port": dport,
                "detail": f"TCP flags={flags}",
            }
        patterns_seen.add(kind)

        st = src_stats[ip_src]
        st["pkts"] += 1
        st["ports"].add(dport)
        st["targets"].add(ip_dst)
        st["flag_stats"].update({
            "SYN": 1 if (flags & SYN) else 0,
            "FIN": 1 if (flags & FIN) else 0,
            "PSH": 1 if (flags & PSH) else 0,
            "URG": 1 if (flags & URG) else 0,
            "RST": 1 if (flags & RST) else 0,
            "ACK": 1 if (flags & ACK) else 0,
        })
        if st["first_t"] is None:
            st["first_t"] = ts

        port_dist.update([dport])

    interval_s = 0 if (t_first is None or t_last is None) else int(t_last - t_first)

    ranking = sorted(
        [
            {
                "ip": ip,
                "pkts": st["pkts"],
                "distinct_ports": len(st["ports"]),
                "distinct_hosts": len(st["targets"]),
                "flag_stats": dict(st["flag_stats"]),
                "first_t": _ts_iso(st["first_t"]) if st["first_t"] else None,
                "pattern": _dominant_pattern(st["flag_stats"]),
            }
            for ip, st in src_stats.items()
        ],
        key=lambda x: (x["distinct_ports"] + x["distinct_hosts"], x["pkts"]),
        reverse=True,
    )

    overview = {
        "total_pkts": total_pkts,
        "interval_s": interval_s,
        "scanners": ranking[:top_k],
        "targets": _targets_top(src_stats, top_k),
        "port_distribution": [{"port": p, "hits": c} for p, c in port_dist.most_common(top_k)],
        "suspected_patterns": sorted(patterns_seen),
        "generated_at": _ts_iso(datetime.now().timestamp()),
    }
    return overview, first_event

# -------------------------------------------------
#  Wrappers "listos para tool"
# -------------------------------------------------
def summarize_overview(path: str, time_window_s: int = 60, top_k: int = 20) -> Dict[str, Any]:
    overview, _ = analyze_pcap(path, time_window_s=time_window_s, top_k=top_k)
    return overview

def first_scan_event(path: str) -> Optional[Dict[str, Any]]:
    _, first = analyze_pcap(path, time_window_s=60, top_k=20)
    return first

def list_suspects(path: str, only_public: bool = True, top_k: int = 50) -> Dict[str, Any]:
    overview, _ = analyze_pcap(path, time_window_s=60, top_k=max(top_k, 50))
    scanners = overview.get("scanners", [])
    filtered: List[Dict[str, Any]] = []
    for s in scanners:
        ip = s.get("ip")
        if not ip:
            continue
        if only_public and not _is_public(ip):
            continue
        filtered.append(s)
    suspects = filtered[:top_k]
    return {"count": len(suspects), "suspects": suspects, "generated_at": overview.get("generated_at")}
