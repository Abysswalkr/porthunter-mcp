# Compliance Matrix – PortHunter MCP

| Requisito guía | ¿Dónde se cumple? | Estado |
|---|---|---|
| Servidor MCP propio publicado | README + Releases | ✅ |
| Ejecución STDIO | `python -m porthunter.server` | ✅ |
| Auth/Control acceso | `PORT_HUNTER_TOKEN` + `PORT_HUNTER_ALLOWED_DIR` | ✅ (local) |
| Validación de entrada | Extensión/tamaño/paths + IP privadas/ inválidas | ✅ |
| Esquemas y ejemplos JSON | README (Tools + JSON Examples) | ✅ |
| Benchmarks reproducibles | `scripts/benchmark_porthunter.py` + `docs/benchmarks.md` | 🟡 |
| Pruebas en CI | `smoke` + `pytest` | ✅ |
| Seguridad producción remota | `docs/security.md` (TLS/mTLS) | 🟡 |
| Integración en chatbot | Proyecto principal | 🟡 |
