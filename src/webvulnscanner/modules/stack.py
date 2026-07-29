"""Fingerprint de tecnologías con Wappalyzer (opcional) + correlación CVE por componente.

Wappalyzer detecta cientos de tecnologías CON versión (CMS, framework, servidor,
librerías). Con eso se cierra el hueco: además del `Server`, se correlacionan CVEs
para CADA componente versionado (WordPress core, plugins, jQuery, PHP…).

Degradación elegante: si Wappalyzer no está instalado, el módulo se omite.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.modules import cve
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.stack")

_SEVERIDAD = {"CRITICAL": Risk.ALTO, "HIGH": Risk.ALTO, "MEDIUM": Risk.MEDIO, "LOW": Risk.BAJO}

# Carga perezosa de Wappalyzer (su DB puede descargarse la primera vez).
_wapp = None
_intentado = False


def _cargar_wapp():
    global _wapp, _intentado
    if not _intentado:
        _intentado = True
        try:
            from Wappalyzer import Wappalyzer

            _wapp = Wappalyzer.latest()
        except Exception as e:  # noqa: BLE001
            log.info("  [i] Wappalyzer no disponible (%s) — fingerprint extendido omitido", type(e).__name__)
            _wapp = None
    return _wapp


def disponible() -> bool:
    return _cargar_wapp() is not None


def detectar(respuesta: HttpResponse) -> dict[str, dict]:
    """Devuelve {tecnología: {versions:[...], categories:[...]}}. {} si no hay Wappalyzer."""
    w = _cargar_wapp()
    if w is None or respuesta is None:
        return {}
    try:
        from Wappalyzer import WebPage

        page = WebPage(respuesta.url, html=respuesta.body, headers=respuesta.headers)
        return w.analyze_with_versions_and_categories(page)
    except Exception as e:  # noqa: BLE001
        log.info("  [i] Wappalyzer falló al analizar: %s", e)
        return {}


def analizar(dominio: str, respuesta: HttpResponse | None, *, max_componentes: int = 6) -> list[Finding]:
    if respuesta is None:
        return []
    techs = detectar(respuesta)
    if not techs:
        return []

    findings: list[Finding] = []

    # 1. Resumen del stack (con versiones cuando las hay).
    resumen = ", ".join(
        f"{t} {info['versions'][0]}" if info.get("versions") else t for t, info in sorted(techs.items())
    )
    findings.append(
        Finding(
            "Stack",
            f"Tecnologías detectadas (Wappalyzer): {len(techs)}",
            Risk.INFO,
            f"Superficie tecnológica identificada: {resumen}.",
            evidencia=resumen,
            owasp="A03:2025",
        )
    )

    # 2. Correlación CVE por componente versionado (además del servidor).
    versionados = [(t, info["versions"][0]) for t, info in techs.items() if info.get("versions")]
    for producto, version in versionados[:max_componentes]:
        cves = cve.consultar_nvd(producto.lower(), version)
        for c in cves:
            findings.append(
                Finding(
                    "CVE",
                    f"{c['id']} — {producto} {version} (CVSS {c['score']} {c['severidad']})",
                    _SEVERIDAD.get(c["severidad"], Risk.MEDIO),
                    c["resumen"],
                    referencia=f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                    evidencia=f"componente: {producto} {version}",
                    owasp="A03:2025",
                )
            )
    return findings
