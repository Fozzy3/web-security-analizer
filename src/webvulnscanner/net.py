"""Utilidades de red compartidas por los módulos de análisis.

Todo aquí es pasivo: una petición HTTP normal o una lectura de banner. Sin
inyección de payloads ni fuzzing.
"""

from __future__ import annotations

import contextlib
import json as _jsonlib
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse

USER_AGENT = "WebVulnScanner/2.0 (auditoria-academica; +no-intrusivo)"
TIMEOUT = 6

# Hostname RFC 1123: etiquetas alfanuméricas con guiones internos, ≤253 chars.
_RE_HOST = re.compile(r"(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


def es_host_valido(valor: str) -> bool:
    """True si `valor` es un hostname/IP con forma válida."""
    return bool(_RE_HOST.fullmatch(valor.strip().lower()))


def normalizar_dominio(entrada: str) -> str:
    """Extrae y valida el host de lo que haya escrito el usuario.

    Único punto de confianza del objetivo: lo que salga de aquí se interpola en
    URLs y se pasa como argv a herramientas externas (nuclei, nmap, wpscan). Por
    eso debe ser un hostname y nada más — sin rutas, credenciales, ni algo que
    empiece por '-' (que las herramientas leerían como una opción).
    """
    bruto = entrada.strip()
    if "//" not in bruto:
        bruto = "//" + bruto
    try:
        host = urlparse(bruto).hostname or ""
    except ValueError as e:
        raise ValueError(f"Dominio inválido: {entrada!r}") from e
    if not es_host_valido(host):
        raise ValueError(f"Dominio inválido: {entrada!r} (se esperaba un host tipo example.com)")
    return host


@dataclass
class HttpResponse:
    url: str
    esquema: str
    status: int
    headers: dict[str, str]  # claves en minúscula
    body: str

    def header(self, nombre: str, default: str | None = None) -> str | None:
        return self.headers.get(nombre.lower(), default)


@dataclass
class Sesion:
    """Estado de sesión compartido por todas las peticiones de un escaneo.

    `headers` se adjuntan a cada petición (cookie/bearer/header de auth para
    escanear zonas autenticadas). `delay` espacia las peticiones (cortesía).
    Los valores de `headers` NUNCA se registran en logs (pueden ser secretos).
    """

    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    _ultima: float | None = field(default=None, repr=False, compare=False)


# Sesión activa, compartida por todos los módulos sin ensuciar sus firmas.
# ponytail: global de módulo, no ContextVar — los workers del ThreadPoolExecutor
# NO heredan contextvars, así que un global compartido es lo que realmente
# propaga la sesión a todos los hilos. El throttle (_ultima) queda best-effort
# bajo concurrencia; per-host locking si algún día importa.
_sesion_activa: Sesion = Sesion()


def configurar_sesion(sesion: Sesion) -> None:
    """Fija la sesión activa (headers de auth y throttle) para las peticiones."""
    global _sesion_activa
    _sesion_activa = sesion


def sesion_actual() -> Sesion:
    return _sesion_activa


def _throttle(sesion: Sesion) -> None:
    """Espera lo necesario para respetar `sesion.delay` entre peticiones."""
    if sesion.delay > 0 and sesion._ultima is not None:
        pendiente = sesion.delay - (time.monotonic() - sesion._ultima)
        if pendiente > 0:
            time.sleep(pendiente)
    sesion._ultima = time.monotonic()


def _cuerpo(data: dict[str, str] | bytes | None, json: object | None) -> tuple[bytes | None, str | None]:
    """Serializa el cuerpo. Devuelve (bytes, content-type) o (None, None)."""
    if json is not None:
        return _jsonlib.dumps(json).encode(), "application/json"
    if data is None:
        return None, None
    if isinstance(data, bytes):
        return data, None
    return urlencode(data).encode(), "application/x-www-form-urlencoded"


def _contexto_inseguro() -> ssl.SSLContext:
    """Contexto TLS que NO verifica el certificado.

    Deliberado: queremos poder inspeccionar sitios con certificados rotos o
    autofirmados (la validez del cert la evalúa el módulo TLS por separado).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(
    dominio: str,
    ruta: str = "/",
    *,
    method: str = "GET",
    data: dict[str, str] | bytes | None = None,
    json: object | None = None,
    headers: dict[str, str] | None = None,
    max_body: int = 200_000,
    sin_sesion: bool = False,
) -> HttpResponse | None:
    """Petición HTTP con método y cuerpo, probando HTTPS y luego HTTP.

    Motor único de red: `fetch()` delega aquí. Adjunta los headers de la sesión
    activa (auth) y respeta su throttle. Devuelve None si ambos esquemas fallan.
    `data` dict → form-urlencoded; `json` → JSON. No se registran headers (secretos).
    `sin_sesion=True` omite las credenciales de sesión (forced browsing / no-auth).
    """
    sesion = sesion_actual()
    cuerpo, content_type = _cuerpo(data, json)
    auth = {} if sin_sesion else sesion.headers
    headers_req = {"User-Agent": USER_AGENT, **auth, **(headers or {})}
    if content_type and "Content-Type" not in headers_req:
        headers_req["Content-Type"] = content_type

    _throttle(sesion)

    for esquema in ("https", "http"):
        url = f"{esquema}://{dominio}{ruta}"
        try:
            req = urllib.request.Request(url, data=cuerpo, headers=headers_req, method=method)
            ctx = _contexto_inseguro() if esquema == "https" else None
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                body = resp.read(max_body).decode("utf-8", errors="replace")
                headers_resp = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResponse(url, esquema, resp.status, headers_resp, body)
        except urllib.error.HTTPError as e:
            # Un 4xx/5xx sigue siendo una respuesta válida para analizar headers.
            headers_resp = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = ""
            with contextlib.suppress(Exception):
                body = e.read(max_body).decode("utf-8", errors="replace")
            return HttpResponse(url, esquema, e.code, headers_resp, body)
        except Exception:  # noqa: BLE001 — pasar al siguiente esquema
            continue
    return None


def fetch(
    dominio: str,
    ruta: str = "/",
    *,
    max_body: int = 200_000,
    cabeceras_extra: dict[str, str] | None = None,
) -> HttpResponse | None:
    """Descarga una URL por GET (HTTPS y luego HTTP). Devuelve None si ambos fallan.

    Fina capa sobre `request()` para conservar la firma histórica que usan los
    módulos pasivos. `cabeceras_extra` añade headers (p.ej. Origin para CORS).
    """
    return request(dominio, ruta, method="GET", headers=cabeceras_extra, max_body=max_body)


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
