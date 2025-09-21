from __future__ import annotations
import json, time
from pathlib import Path
from typing import Any, Optional

class SimpleCache:
    """
    Caché JSON por llave (string) con TTL en segundos.
    """
    def __init__(self, cache_file: Path, ttl_seconds: int = 7*24*3600) -> None:
        self.cache_file = cache_file
        self.ttl = ttl_seconds
        self._data = {"_ts": int(time.time()), "items": {}}  # key -> {"ts":int,"value":Any}
        if cache_file.exists():
            try:
                self._data = json.loads(cache_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    def get(self, key: str) -> Optional[Any]:
        it = self._data["items"].get(key)
        if not it:
            return None
        if int(time.time()) - it.get("ts", 0) > self.ttl:
            # expirado
            self._data["items"].pop(key, None)
            self._flush()
            return None
        return it.get("value")

    def set(self, key: str, value: Any) -> None:
        self._data["items"][key] = {"ts": int(time.time()), "value": value}
        self._flush()

    def _flush(self) -> None:
        try:
            self.cache_file.write_text(json.dumps(self._data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
