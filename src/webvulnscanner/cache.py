"""Caché en disco con TTL para respuestas de servicios externos (crt.sh, NVD).

Evita repetir consultas lentas y respeta los rate limits del NVD. Simple a
propósito: un archivo JSON por clave bajo una carpeta de caché del usuario.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger("webvulnscanner.cache")

_DIR = Path.home() / ".cache" / "webvulnscanner"


def _ruta(clave: str) -> Path:
    h = hashlib.sha256(clave.encode()).hexdigest()[:16]
    return _DIR / f"{h}.json"


def cached_json(
    clave: str,
    ttl: int,
    productor: Callable[[], Any],
    *,
    cache_if: Callable[[Any], bool] = bool,
) -> Any:
    """Devuelve el valor cacheado si es fresco; si no, llama a `productor`,
    guarda y devuelve. `ttl` en segundos; ttl<=0 desactiva la caché.

    Solo se persiste si `cache_if(valor)` es verdadero — así un fallo de red
    (respuesta vacía) no envenena la caché durante todo el TTL.
    """
    if ttl <= 0:
        return productor()

    ruta = _ruta(clave)
    if ruta.exists() and (time.time() - ruta.stat().st_mtime) < ttl:
        try:
            log.debug("cache hit: %s", clave)
            return json.loads(ruta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass  # caché corrupta → regenerar

    valor = productor()
    if cache_if(valor):
        try:
            _DIR.mkdir(parents=True, exist_ok=True)
            ruta.write_text(json.dumps(valor), encoding="utf-8")
        except (OSError, TypeError):
            log.debug("no se pudo escribir caché para %s", clave)
    return valor
