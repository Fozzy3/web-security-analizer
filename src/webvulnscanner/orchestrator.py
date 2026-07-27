"""Orquestador: coordina los módulos de análisis y arma el ScanResult.

Cada módulo se ejecuta aislado: si uno falla, se registra y el escaneo sigue.
La comunicación de progreso es vía logging (el CLI y la GUI enganchan sus
propios handlers), no secuestrando sys.stdout.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk, ScanResult
from webvulnscanner.net import fetch
from webvulnscanner.modules import (
    cve, dns_records, disclosure, fingerprint, headers, ports, recon, subdomains, tls, waf,
)

log = logging.getLogger("webvulnscanner")

# Orden y etiquetas de los módulos.
MODULOS = [
    ("recon", "Reconocimiento (Footprinting)"),
    ("ports", "Escaneo de Puertos + Banners"),
    ("tls", "Análisis TLS / HTTPS"),
    ("headers", "Encabezados HTTP de Seguridad"),
    ("dns", "Registros DNS y Seguridad de Correo"),
    ("subdomains", "Subdominios (Certificate Transparency)"),
    ("disclosure", "Archivos y Rutas Sensibles"),
    ("waf", "Detección de WAF / CDN"),
    ("fingerprint", "Fingerprint de Tecnologías"),
    ("cve", "Correlación de CVEs (NVD)"),
]


def _ejecutar(nombre: str, fn) -> list[Finding]:
    """Corre un módulo capturando cualquier error para no abortar el escaneo."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Módulo '%s' falló: %s", nombre, e)
        return [Finding(nombre, f"El módulo '{nombre}' falló durante la ejecución", Risk.INFO,
                        f"Error interno: {e}")]


def run_scan(dominio: str, *, activos: set[str] | None = None) -> ScanResult:
    """Ejecuta el escaneo completo (o el subconjunto en `activos`)."""
    activos = activos or {n for n, _ in MODULOS}
    dominio = dominio.strip().replace("https://", "").replace("http://", "").rstrip("/")

    respuesta = fetch(dominio)  # una sola petición compartida por varios módulos
    result = ScanResult(dominio=dominio)

    # recon primero: define ip/producto/version que necesitan otros módulos
    log.info("\n[MÓDULO] Reconocimiento (Footprinting)\n" + "─" * 48)
    f_recon, info = _run_recon(dominio, respuesta)
    result.findings.extend(f_recon)
    result.ip = info.get("ip")
    result.servidor = info.get("servidor")

    if not info.get("ip"):
        log.info("  Análisis detenido: el dominio no resuelve.")
        return result

    plan = [
        ("ports", lambda: ports.analizar(info["ip"]), info["ip"] and "ports" in activos),
        ("tls", lambda: tls.analizar(dominio), "tls" in activos),
        ("headers", lambda: headers.analizar(respuesta), "headers" in activos),
        ("dns", lambda: dns_records.analizar(dominio), "dns" in activos),
        ("subdomains", lambda: subdomains.analizar(dominio), "subdomains" in activos),
        ("disclosure", lambda: disclosure.analizar(dominio), "disclosure" in activos),
        ("waf", lambda: waf.analizar(respuesta), "waf" in activos),
        ("fingerprint", lambda: fingerprint.analizar(respuesta), "fingerprint" in activos),
        ("cve", lambda: cve.analizar(info.get("producto"), info.get("version")), "cve" in activos),
    ]
    etiquetas = dict(MODULOS)
    for nombre, fn, habilitado in plan:
        if not habilitado:
            continue
        log.info("\n[MÓDULO] %s\n%s", etiquetas.get(nombre, nombre), "─" * 48)
        result.findings.extend(_ejecutar(nombre, fn))

    return result


def _run_recon(dominio, respuesta):
    try:
        return recon.analizar(dominio, respuesta)
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Reconocimiento falló: %s", e)
        return [Finding("Reconocimiento", "Falló el reconocimiento", Risk.ALTO, str(e))], {}
