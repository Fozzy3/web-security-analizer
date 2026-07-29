"""Fase U: manejo de condiciones excepcionales (A10:2025). Activo suave, gateado.

Provoca errores con entradas malformadas benignas y detecta fugas: stack traces
y modo debug en producción (revelan rutas, tecnología, consultas). No es
destructivo — solo entradas inesperadas.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse, request

log = logging.getLogger("webvulnscanner.error_audit")

# Firmas de un stack trace / traza de framework en la respuesta.
_FIRMAS_TRACE = (
    "traceback (most recent call last)",
    "at java.",
    "exception in",
    "stack trace",
    '.py", line',
    "at System.",
    "goroutine ",
    "n+0x",
)
# Firmas de un panel/consola de debug de framework en producción.
_FIRMAS_DEBUG = ("werkzeug", "whoops\\", "whoops ", "symfony profiler", "rails.application", "django debug")
# Headers de respuesta que delatan el modo debug del framework (Symfony y afines).
_HEADERS_DEBUG = (
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-debug-mode",
    "symfony-debug-toolbar-replace",
)
# Entradas que suelen inducir un error mal manejado.
_SONDAS = ("/?id[]=1", "/?id='", "/%ff", "/'\"><", "/?page=-1e999")


def _es_stack_trace(body: str) -> bool:
    b = (body or "").lower()
    return any(s in b for s in _FIRMAS_TRACE)


def _es_debug(body: str) -> bool:
    b = (body or "").lower()
    return any(s in b for s in _FIRMAS_DEBUG)


def _debug_por_headers(r: HttpResponse) -> str | None:
    """Nombre del header de respuesta que delata modo debug, o None."""
    for nombre in _HEADERS_DEBUG:
        if r.header(nombre) is not None:
            return nombre
    return None


def analizar(dominio: str) -> list[Finding]:
    findings: list[Finding] = []
    visto_trace = visto_debug = False
    for ruta in _SONDAS:
        if visto_trace and visto_debug:
            break
        r = request(dominio, ruta)
        if r is None:
            continue
        if not visto_debug:
            header_debug = _debug_por_headers(r)
            if header_debug is not None:
                log.info("  [!!] Modo debug expuesto por header de respuesta (%s)", header_debug)
                findings.append(
                    Finding(
                        "Errores",
                        "Modo debug expuesto en producción (header de respuesta)",
                        Risk.ALTO,
                        f"Un header de respuesta ({header_debug}) delata el modo debug del "
                        "framework (p. ej. el profiler/toolbar de Symfony): expone entorno, "
                        "rutas y la traza de peticiones. Desactive el debug en producción.",
                        referencia=ruta,
                        owasp="A10:2025",
                    )
                )
                visto_debug = True
            elif _es_debug(r.body):
                log.info("  [!!] Modo debug expuesto en producción")
                findings.append(
                    Finding(
                        "Errores",
                        "Modo debug expuesto en producción",
                        Risk.ALTO,
                        "Una condición de error revela una consola/panel de debug del framework: "
                        "expone código, entorno y a veces ejecución. Desactive el debug en producción.",
                        referencia=ruta,
                        owasp="A10:2025",
                    )
                )
                visto_debug = True
        if not visto_trace and _es_stack_trace(r.body):
            log.info("  [!] Stack trace expuesto en un error")
            findings.append(
                Finding(
                    "Errores",
                    "Stack trace expuesto en respuesta de error",
                    Risk.MEDIO,
                    "Una entrada inesperada devuelve un stack trace: filtra rutas internas, "
                    "tecnología y a veces consultas. Maneje los errores sin exponer la traza.",
                    referencia=ruta,
                    owasp="A10:2025",
                )
            )
            visto_trace = True
    return findings
