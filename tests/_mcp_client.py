# tests/_mcp_client.py
import os
import sys
import json
from typing import Any, Dict

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

# Intentamos importar tipos nuevos; si no existen, seguimos con duck typing.
try:
    from mcp.client.stdio import StdioServerParameters  # API nueva
except Exception:
    StdioServerParameters = None  # type: ignore

try:
    from mcp.types import CallToolResult  # objeto de retorno nuevo
except Exception:
    CallToolResult = None  # type: ignore


def _server_params():
    """Construye parámetros para stdio_client (compatible con API nueva y vieja)."""
    env = {
        "PORT_HUNTER_TOKEN": os.environ.get("PORT_HUNTER_TOKEN", "TEST_TOKEN"),
        "PORT_HUNTER_ALLOWED_DIR": os.environ.get("PORT_HUNTER_ALLOWED_DIR", os.getcwd()),
    }
    python_exe = sys.executable

    if StdioServerParameters is not None:
        return StdioServerParameters(
            command=python_exe,
            args=["-m", "porthunter.server"],
            env=env,
        )
    else:
        # Compat API antigua (dict)
        return {
            "command": python_exe,
            "args": ["-m", "porthunter.server"],
            "env": env,
        }


def _normalize_call_result(res: Any) -> Dict[str, Any]:
    """
    Normaliza el resultado de session.call_tool(*) a un dict con claves reales (ok, error, ...).
    Soporta:
      - Formato viejo: dict con "result" (dict o str JSON)
      - Formato nuevo: objeto CallToolResult con .content = [TextContent(text='{"ok":...}')]
      - Listas de contenidos (dicts) con {"type":"text","text":"{...}"}
    """
    # 1) Si es un dict que envuelve {"result": ...}
    if isinstance(res, dict) and "result" in res:
        inner = res["result"]
        if isinstance(inner, dict):
            return inner
        if isinstance(inner, str):
            try:
                return json.loads(inner)
            except Exception:
                return {"raw": inner}

    # 2) API nueva: objeto con .content (CallToolResult)
    #    Duck typing: si tiene atributo 'content', lo recorremos.
    content = getattr(res, "content", None)
    if isinstance(content, list) and content:
        for item in content:
            # item puede ser objeto (TextContent) o dict
            text = None
            if isinstance(item, dict):
                # p.ej. {"type": "text", "text": "..."}
                if item.get("type") == "text":
                    text = item.get("text")
            else:
                # objeto con atributo .text
                text = getattr(item, "text", None)

            if isinstance(text, str):
                try:
                    return json.loads(text)
                except Exception:
                    # Si no es JSON, seguimos buscando el siguiente item
                    pass

    # 3) Algunas versiones tienen también atributo .result (además de .content)
    inner = getattr(res, "result", None)
    if isinstance(inner, dict):
        return inner
    if isinstance(inner, str):
        try:
            return json.loads(inner)
        except Exception:
            return {"raw": inner}

    # 4) Si ya es una lista de contenidos brutos
    if isinstance(res, list) and res:
        first = res[0]
        if isinstance(first, dict) and first.get("type") == "text" and "text" in first:
            try:
                return json.loads(first["text"])
            except Exception:
                return {"raw": first["text"]}

    # 5) Si ya es un dict plano
    if isinstance(res, dict):
        return res

    # Fallback: no supimos parsearlo
    return {"raw": repr(res)}


async def call_tool(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Llama a un tool del servidor PortHunter por STDIO y devuelve un dict normalizado."""
    params = _server_params()

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool(tool_name, args)
            return _normalize_call_result(res)
