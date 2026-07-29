"""Fase Q: control de acceso — IDOR/BOLA y forced browsing (A01:2025, API1/3/5).

Activo, gateado tras `autorizado=True`. Requiere sesión (Fase L) para IDOR.
**Solo lectura (GET)**: prueba el acceso a objetos ajenos sin comprometer datos;
la verificación de escritura queda para revisión manual (evita alterar el objetivo).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import request

log = logging.getLogger("webvulnscanner.access_control")

_RE_ID = re.compile(r"\d+")

# Rutas administrativas/privadas a probar por forced browsing.
_RUTAS_ADMIN = (
    "/admin",
    "/admin/users",
    "/administrator",
    "/api/admin",
    "/dashboard",
    "/manage",
    "/settings/users",
    "/wp-admin/",
)
# Señales de que una respuesta es realmente un panel/función administrativa.
_SENALES_ADMIN = ("administra", "dashboard", "panel", "usuarios", "users", "manage")


def _segmento_numerico(ruta: str) -> tuple[str, str, str] | None:
    """Parte la ruta en (prefijo, id_numérico, sufijo), o None si no hay número."""
    m = _RE_ID.search(ruta)
    if not m:
        return None
    return ruta[: m.start()], m.group(), ruta[m.end() :]


def _vecino(idv: str) -> str:
    return str(int(idv) + 1)


def _probar_idor(dominio: str, ruta: str) -> Finding | None:
    seg = _segmento_numerico(ruta)
    if not seg:
        return None
    prefijo, idv, sufijo = seg
    r1 = request(dominio, ruta)
    if not r1 or r1.status != 200 or not r1.body:
        return None
    ruta2 = f"{prefijo}{_vecino(idv)}{sufijo}"
    r2 = request(dominio, ruta2)
    # Objeto ajeno accesible con contenido distinto y no vacío → IDOR.
    if r2 and r2.status == 200 and r2.body and r2.body != r1.body:
        log.info("  [!!] Posible IDOR: %s accesible desde la sesión", ruta2)
        return Finding(
            "Control de Acceso",
            f"Posible IDOR/BOLA en {ruta} (objeto ajeno {ruta2} accesible)",
            Risk.ALTO,
            "Cambiar el identificador da acceso a datos de otro objeto/usuario. Aplique "
            "autorización a nivel de objeto. Verifique además el acceso de escritura manualmente.",
            referencia=ruta2,
            owasp="A01:2025",
        )
    return None


def _forced_browsing(dominio: str) -> list[Finding]:
    findings: list[Finding] = []
    for ruta in _RUTAS_ADMIN:
        r = request(dominio, ruta, sin_sesion=True)  # sin credenciales
        if r and r.status == 200 and any(s in r.body.lower() for s in _SENALES_ADMIN):
            log.info("  [!!] Ruta administrativa accesible sin sesión: %s", ruta)
            findings.append(
                Finding(
                    "Control de Acceso",
                    f"Función administrativa accesible sin autenticación: {ruta}",
                    Risk.ALTO,
                    "Una ruta administrativa responde sin sesión: control de acceso roto. "
                    "Exija autenticación y autorización en estas rutas.",
                    referencia=ruta,
                    owasp="A01:2025",
                )
            )
    return findings


def analizar(dominio: str, crawl: Crawl | None = None) -> list[Finding]:
    findings: list[Finding] = []
    vistas: set[str] = set()

    for url in sorted(crawl.urls) if crawl else []:
        ruta = urlparse(url).path or "/"
        if ruta in vistas:
            continue
        vistas.add(ruta)
        f = _probar_idor(dominio, ruta)
        if f:
            findings.append(f)

    findings.extend(_forced_browsing(dominio))
    return findings
