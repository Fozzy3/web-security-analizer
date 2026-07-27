"""Orquestador: coordina los módulos de análisis y arma el ScanResult.

Cada módulo se ejecuta aislado: si uno falla, se registra y el escaneo sigue.
La comunicación de progreso es vía logging (el CLI y la GUI enganchan sus
propios handlers), no secuestrando sys.stdout.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from webvulnscanner.models import Finding, Risk, ScanResult
from webvulnscanner.modules import (
    active,
    cve,
    disclosure,
    dns_records,
    fingerprint,
    headers,
    ports,
    recon,
    shodan_intel,
    subdomains,
    tls,
    waf,
)
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner")

# Orden y etiquetas de los módulos PASIVOS (siempre disponibles).
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
    ("shodan", "Inteligencia Shodan (opcional)"),
]

# Módulos ACTIVOS (Fase D): solo con autorización explícita (autorizado=True).
MODULOS_ACTIVOS = [
    ("cookies", "Flags de Cookies"),
    ("cors", "Configuración CORS"),
    ("inyeccion", "Inyección Reflejada (XSS/SQLi)"),
    ("fuzzing", "Fuzzing de Rutas"),
]


def _ejecutar(nombre: str, fn) -> list[Finding]:
    """Corre un módulo capturando cualquier error para no abortar el escaneo."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Módulo '%s' falló: %s", nombre, e)
        return [
            Finding(
                nombre, f"El módulo '{nombre}' falló durante la ejecución", Risk.INFO, f"Error interno: {e}"
            )
        ]


def run_scan(
    dominio: str,
    *,
    activos: set[str] | None = None,
    paralelo: bool = True,
    max_workers: int = 8,
    autorizado: bool = False,
) -> ScanResult:
    """Ejecuta el escaneo completo (o el subconjunto en `activos`).

    recon corre primero (define ip/producto que otros módulos necesitan); el
    resto corre en paralelo salvo que `paralelo=False`. Los findings se
    ensamblan en el orden de MODULOS para que el reporte sea determinista.

    Los módulos ACTIVOS (Fase D) solo se ejecutan con `autorizado=True`, ya que
    envían peticiones elaboradas al objetivo (requiere autorización expresa).
    """
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

    # (nombre -> función del módulo). Solo los que estén activos.
    trabajos: dict[str, Callable[[], list[Finding]]] = {
        "ports": lambda: ports.analizar(info["ip"]),
        "tls": lambda: tls.analizar(dominio),
        "headers": lambda: headers.analizar(respuesta),
        "dns": lambda: dns_records.analizar(dominio),
        "subdomains": lambda: subdomains.analizar(dominio),
        "disclosure": lambda: disclosure.analizar(dominio),
        "waf": lambda: waf.analizar(respuesta),
        "fingerprint": lambda: fingerprint.analizar(respuesta),
        "cve": lambda: cve.analizar(info.get("producto"), info.get("version")),
        "shodan": lambda: shodan_intel.analizar(info.get("ip")),
    }

    orden = list(MODULOS)
    if autorizado:
        log.warning("  ⚠ Modo ACTIVO habilitado (autorizado): se enviarán peticiones al objetivo.")
        trabajos.update(
            {
                "cookies": lambda: active.analizar_cookies(respuesta),
                "cors": lambda: active.analizar_cors(dominio),
                "inyeccion": lambda: active.analizar_inyeccion(dominio),
                "fuzzing": lambda: active.analizar_fuzzing(dominio),
            }
        )
        orden = orden + MODULOS_ACTIVOS

    pendientes = {n: fn for n, fn in trabajos.items() if n in activos}

    if paralelo:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            salidas = ex.map(lambda nf: _ejecutar(*nf), pendientes.items())
            resultados = dict(zip(pendientes, salidas, strict=True))
    else:
        resultados = {n: _ejecutar(n, fn) for n, fn in pendientes.items()}

    # Ensamblar en el orden canónico (pasivos y, si aplica, activos).
    etiquetas = dict(orden)
    for nombre, _label in orden:
        if nombre in resultados:
            log.info("\n[MÓDULO] %s\n%s", etiquetas.get(nombre, nombre), "─" * 48)
            result.findings.extend(resultados[nombre])

    return result


def _run_recon(dominio, respuesta):
    try:
        return recon.analizar(dominio, respuesta)
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Reconocimiento falló: %s", e)
        return [Finding("Reconocimiento", "Falló el reconocimiento", Risk.ALTO, str(e))], {}
