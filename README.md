# PortHunter MCP — Local MCP server for port-scan analysis (PCAP/PCAPNG)

**PortHunter** es un servidor **MCP** local (transport **STDIO**) que:

* analiza capturas **PCAP/PCAPNG**,
* detecta técnicas comunes de escaneo (**SYN**, **FIN/NULL/Xmas**),
* clasifica patrones (**horizontal** / **vertical**),
* lista sospechosos y obtiene el **primer evento** relevante,
* puede **enriquecer IPs públicas** (OTX/GreyNoise/ASN/Geo) y **correlacionarlas**.

Está pensado para ser consumido por cualquier **host/chatbot MCP**.

---

## Requisitos

* **Python 3.11+**
* Windows, Linux o macOS
* (Opcional) Docker

---

## Instalación

```bash
python -m venv .venv
# Windows PowerShell:  .\.venv\Scripts\Activate.ps1
# Linux/macOS:         source .venv/bin/activate
pip install -U pip
pip install -e .
```

> El `-e .` instala el paquete `porthunter` en editable desde este repo.

---

## Ejecución (STDIO)

### Windows PowerShell (recomendado)

```powershell
$env:PORT_HUNTER_TOKEN = "TEST_TOKEN"
$env:PORT_HUNTER_ALLOWED_DIR = (Get-Location).Path
python -m porthunter.server
```

### Windows CMD

```cmd
set PORT_HUNTER_TOKEN=TEST_TOKEN
set PORT_HUNTER_ALLOWED_DIR=%CD%
python -m porthunter.server
```

### Linux/macOS

```bash
export PORT_HUNTER_TOKEN=TEST_TOKEN
export PORT_HUNTER_ALLOWED_DIR="$PWD"
python -m porthunter.server
```

> El servidor queda **escuchando por STDIO** a la espera de llamadas MCP `call_tool`.

---

## Variables de entorno (seguridad y límites)

| Variable                    |      Default | Descripción                                                            |
| --------------------------- | -----------: | ---------------------------------------------------------------------- |
| `PORT_HUNTER_TOKEN`         | `TEST_TOKEN` | Token requerido si `PORT_HUNTER_REQUIRE_TOKEN=true`.                   |
| `PORT_HUNTER_REQUIRE_TOKEN` |       `true` | Exige `auth_token` en cada llamada de tool.                            |
| `PORT_HUNTER_ALLOWED_DIR`   |          `.` | **Directorio raíz permitido** para leer PCAP/PCAPNG.                   |
| `PORT_HUNTER_MAX_PCAP_MB`   |         `50` | Tamaño máximo del archivo a procesar.                                  |
| `PORT_HUNTER_ALLOW_PRIVATE` |      `false` | Si `true`, permite enriquecer IPs privadas (por defecto se **omite**). |

---

## `mcp.json` (ejemplo listo para usar)

```json
{
  "name": "porthunter",
  "version": "0.1.0",
  "transport": {
    "stdio": { "command": "python", "args": ["-m", "porthunter.server"] }
  },
  "env": {
    "PORT_HUNTER_TOKEN": "TEST_TOKEN",
    "PORT_HUNTER_ALLOWED_DIR": ".",
    "PORT_HUNTER_REQUIRE_TOKEN": "true",
    "PORT_HUNTER_MAX_PCAP_MB": "50"
  },
  "tools": [
    "scan_overview",
    "list_suspects",
    "first_scan_event",
    "enrich_ip",
    "correlate"
  ]
}
```

---

## Tools (API)

> Todas las herramientas devuelven **UTC ISO-8601** en `generated_at`.

### 1) `scan_overview(path, time_window_s=60, top_k=20)`

**Input**

```json
{ "path": "captures/scan-demo.pcapng", "time_window_s": 60, "top_k": 20, "auth_token": "TEST_TOKEN" }
```

**Return**

```json
{ "ok": true, "overview": { /* ver ejemplo */ }, "generated_at": "..." }
```

### 2) `list_suspects(path, min_ports=10, min_rate_pps=5.0)`

**Input**

```json
{ "path": "captures/scan-demo.pcapng", "min_ports": 10, "min_rate_pps": 5.0, "auth_token": "TEST_TOKEN" }
```

**Return**

```json
{ "ok": true, "suspects": [ /* items */ ], "generated_at": "..." }
```

### 3) `first_scan_event(path)`

**Input**

```json
{ "path": "captures/scan-demo.pcapng", "auth_token": "TEST_TOKEN" }
```

**Return**

```json
{ "ok": true, "first_event": { /* o null */ }, "generated_at": "..." }
```

### 4) `enrich_ip(ip)`

**Input**

```json
{ "ip": "8.8.8.8", "auth_token": "TEST_TOKEN" }
```

**Return (ok)**

```json
{ "ok": true, "enrichment": { "asn": "...", "org": "...", "geo": { "country": "US" }, "threat": { "otx": {...}, "greynoise": {...} } }, "generated_at": "..." }
```

**Return (error)**

```json
{ "ok": false, "error": "invalid_ip", "generated_at": "..." }
```

### 5) `correlate(ips[])`

**Input**

```json
{ "ips": ["abc", "192.168.0.10", "8.8.8.8"], "auth_token": "TEST_TOKEN" }
```

**Return**

```json
{
  "ok": true,
  "results": [
    { "ip": "abc", "ok": false, "error": "invalid_ip" },
    { "ip": "192.168.0.10", "skipped": true, "reason": "private_ip" },
    { "ip": "8.8.8.8", "ok": true, "kind": "public", "enrichment": {/*...*/} }
  ],
  "generated_at": "..."
}
```

---

## Ejemplos de JSON (respuestas reales)

### `scan_overview` (ejemplo)

```json
{
  "ok": true,
  "overview": {
    "file": "captures/scan.pcapng",
    "total_pkts": 12345,
    "interval_s": 600,
    "scanners": [
      {
        "ip": "1.2.3.4",
        "pkts": 500,
        "distinct_ports": 120,
        "distinct_hosts": 30,
        "flag_stats": { "SYN": 480, "FIN": 15, "XMAS": 5 }
      }
    ],
    "targets": [
      { "ip": "10.0.0.5", "pkts": 320, "ports_hit": [22, 80, 443] }
    ],
    "port_distribution": [
      { "port": 80, "hits": 450 }, { "port": 22, "hits": 120 }
    ],
    "suspected_patterns": ["syn_scan", "xmas_scan"]
  },
  "generated_at": "2025-09-20T23:00:02Z"
}
```

### `list_suspects` (ejemplo)

```json
{
  "ok": true,
  "suspects": [
    {
      "ip": "5.6.7.8",
      "kind": "horizontal",
      "distinct_ports": 50,
      "rate_pps": 7.2,
      "flags_seen": ["SYN"]
    },
    {
      "ip": "9.9.9.9",
      "kind": "vertical",
      "distinct_ports": 1,
      "rate_pps": 12.0,
      "flags_seen": ["SYN","FIN"]
    }
  ],
  "generated_at": "2025-09-20T23:01:12Z"
}
```

### `first_scan_event` (ejemplo)

```json
{
  "ok": true,
  "first_event": {
    "ts": "2025-09-20T22:59:58Z",
    "src": "1.2.3.4",
    "dst": "10.0.0.5",
    "port": 80,
    "flags": "S"
  },
  "generated_at": "2025-09-20T23:01:45Z"
}
```

### `enrich_ip` (error por IP inválida)

```json
{ "ok": false, "error": "invalid_ip", "generated_at": "2025-09-20T23:02:10Z" }
```

### `correlate` (mixto)

```json
{
  "ok": true,
  "results": [
    { "ip": "abc", "ok": false, "error": "invalid_ip" },
    { "ip": "192.168.0.10", "skipped": true, "reason": "private_ip" },
    { "ip": "8.8.8.8", "ok": true, "kind": "public" }
  ],
  "generated_at": "2025-09-20T23:02:30Z"
}
```

---

## Errores comunes (contract)

* Archivo fuera del directorio permitido:

```json
{ "ok": false, "error": "path_outside_allowed_dir", "generated_at": "..." }
```

* Extensión no soportada:

```json
{ "ok": false, "error": "unsupported_file_type", "generated_at": "..." }
```

* Excede tamaño máximo:

```json
{ "ok": false, "error": "file_too_large", "generated_at": "..." }
```

* Token faltante o incorrecto (si se requiere):

```json
{ "ok": false, "error": "unauthorized", "generated_at": "..." }
```

---

## Uso desde un host MCP (pseudo-cliente)

```python
import asyncio, json
from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

async def main():
    params = StdioServerParameters(
        command="python",
        args=["-m", "porthunter.server"],
        env={
            "PORT_HUNTER_TOKEN": "TEST_TOKEN",
            "PORT_HUNTER_ALLOWED_DIR": ".",
        }
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            resp = await session.call_tool(
                name="scan_overview",
                arguments={"path": "captures/scan-demo-20250906-1.pcapng", "auth_token": "TEST_TOKEN"}
            )

            # structuredContent preferente
            sc = getattr(resp, "structuredContent", None)
            if isinstance(sc, dict):
                print(json.dumps(sc.get("result", sc), indent=2))
            else:
                text = "".join(b.text for b in resp.content if isinstance(b, types.TextContent))
                print(text)

asyncio.run(main())
```

---

## Docker

```bash
docker build -t porthunter-mcp .
docker run --rm -it \
  -e PORT_HUNTER_TOKEN=TEST_TOKEN \
  -e PORT_HUNTER_ALLOWED_DIR=/data \
  -v "$PWD:/data" \
  porthunter-mcp
```

---

## Benchmark (opcional)

```bash
python scripts/benchmark_porthunter.py captures/scan-demo-20250906-1.pcapng
```

Salida sugerida:

* tamaño archivo,
* paquetes totales,
* duración total (s),
* pps promedio.

Incluye una tablita de resultados en el README si vas a reportar métricas.

---

## Desarrollo

* Código fuente del servidor en `porthunter/`
* Utilidades de PCAP e inteligencia en `porthunter/utils/**`
* Ejecuta linters/tests en tu proyecto principal si los tienes allí.
* Si subes pruebas mínimas aquí: `pytest -q`

---

## Licencia

MIT (sugerida). Añade un archivo `LICENSE` si lo deseas.

---

## Créditos y referencias

* [Model Context Protocol](https://modelcontextprotocol.io/)
* Técnicas de escaneo: documentación pública (e.g., Nmap)

---

### TL;DR

Arranca con:

```powershell
$env:PORT_HUNTER_TOKEN = "TEST_TOKEN"
$env:PORT_HUNTER_ALLOWED_DIR = (Get-Location).Path
python -m porthunter.server
```

Llama `scan_overview / list_suspects / first_scan_event / enrich_ip / correlate` y consume el **JSON** como en los ejemplos de arriba.
