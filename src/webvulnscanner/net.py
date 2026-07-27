"""Utilidades de red compartidas por los módulos de análisis.

Todo aquí es pasivo: una petición HTTP normal o una lectura de banner. Sin
inyección de payloads ni fuzzing.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

USER_AGENT = "WebVulnScanner/2.0 (auditoria-academica; +no-intrusivo)"
TIMEOUT = 6


@dataclass
class HttpResponse:
    url: str
    esquema: str
    status: int
    headers: dict[str, str]  # claves en minúscula
    body: str

    def header(self, nombre: str, default: str | None = None) -> str | None:
        return self.headers.get(nombre.lower(), default)


def _contexto_inseguro() -> ssl.SSLContext:
    """Contexto TLS que NO verifica el certificado.

    Deliberado: queremos poder inspeccionar sitios con certificados rotos o
    autofirmados (la validez del cert la evalúa el módulo TLS por separado).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(
    dominio: str,
    ruta: str = "/",
    *,
    max_body: int = 200_000,
    cabeceras_extra: dict[str, str] | None = None,
) -> HttpResponse | None:
    """Descarga una URL probando HTTPS y luego HTTP. Devuelve None si ambos fallan.

    No sigue el body más allá de `max_body` para no cargar páginas enormes.
    `cabeceras_extra` permite añadir headers (p.ej. Origin para probar CORS).
    """
    headers_req = {"User-Agent": USER_AGENT, **(cabeceras_extra or {})}
    for esquema in ("https", "http"):
        url = f"{esquema}://{dominio}{ruta}"
        try:
            req = urllib.request.Request(url, headers=headers_req)
            ctx = _contexto_inseguro() if esquema == "https" else None
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                body = resp.read(max_body).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResponse(url, esquema, resp.status, headers, body)
        except urllib.error.HTTPError as e:
            # Un 4xx/5xx sigue siendo una respuesta válida para analizar headers.
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = ""
            with contextlib.suppress(Exception):
                body = e.read(max_body).decode("utf-8", errors="replace")
            return HttpResponse(url, esquema, e.code, headers, body)
        except Exception:  # noqa: BLE001 — pasar al siguiente esquema
            continue
    return None


def leer_banner(ip: str, puerto: int, *, timeout: float = 2.0, enviar: bytes | None = None) -> str | None:
    """Lee el banner de bienvenida de un servicio TCP (grabbing pasivo).

    Algunos servicios (HTTP) no hablan primero; para esos se puede pasar un
    `enviar` mínimo. Devuelve texto imprimible o None.
    """
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            if enviar:
                s.sendall(enviar)
            datos = s.recv(1024)
    except OSError:
        return None
    if not datos:
        return None
    texto = datos.decode("latin-1", errors="replace").strip()
    # Filtrar caracteres de control salvo tab/newline
    texto = "".join(c for c in texto if c.isprintable() or c in "\t\n")
    return texto[:300] or None
