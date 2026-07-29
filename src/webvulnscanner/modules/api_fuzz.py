"""Fuzzing de API contra su propio esquema OpenAPI (schemathesis). Activo, gateado.

Cuando `api_discovery` encuentra un OpenAPI/Swagger, schemathesis genera casos a
partir del esquema y detecta: errores 5xx no manejados, respuestas que no cumplen
el contrato y códigos de estado no documentados.

Sigue el patrón de los wrappers externos: se invoca el CLI de schemathesis (del
mismo venv) con un tope de ejemplos; si no está instalado, el módulo se omite. El
parseo del reporte JUnit (`_parse_junit`) es puro y testeable.
"""

from __future__ import annotations

import logging
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from webvulnscanner import tools
from webvulnscanner.models import Finding, Risk
from webvulnscanner.modules import api_discovery
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.api_fuzz")

# CLI de schemathesis del mismo entorno (evita depender del PATH).
_ST_BIN = Path(sys.executable).parent / "schemathesis"


def disponible() -> bool:
    return _ST_BIN.exists()


def _schema_url(dominio: str) -> str | None:
    """Devuelve la URL de un OpenAPI válido servido por el objetivo, o None."""
    for ruta in api_discovery._OPENAPI_PATHS:
        r = fetch(dominio, ruta)
        if r and r.status == 200 and api_discovery._doc_openapi(r.body) is not None:
            return f"{r.esquema}://{dominio}{ruta}"
    return None


def _nivel(mensaje: str) -> tuple[Risk, str]:
    """Severidad y categoría OWASP según el tipo de fallo reportado."""
    m = mensaje.lower()
    if "server error" in m or "500" in m or "internal server error" in m:
        return Risk.ALTO, "A08:2025"  # error no manejado / robustez
    if "schema" in m or "conformance" in m:
        return Risk.MEDIO, "A08:2025"
    return Risk.MEDIO, "A08:2025"


def _parse_junit(xml: str) -> list[Finding]:
    """Extrae los casos con fallo del reporte JUnit de schemathesis."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    findings: list[Finding] = []
    for caso in root.iter("testcase"):
        fallo = caso.find("failure")
        if fallo is None:
            continue
        operacion = caso.get("name", "operación")
        mensaje = (fallo.get("message") or fallo.text or "").strip()
        nivel, owasp = _nivel(mensaje)
        log.info("  [!] schemathesis: fallo en %s", operacion)
        findings.append(
            Finding(
                "API Fuzzing",
                f"La API no cumple su contrato en {operacion}",
                nivel,
                "schemathesis generó casos desde el esquema OpenAPI y encontró un fallo "
                f"(error del servidor o respuesta fuera de contrato): {mensaje[:200]}",
                referencia=operacion,
                evidencia=mensaje[:120] or None,
                owasp=owasp,
            )
        )
    return findings


def analizar(dominio: str, *, max_ejemplos: int = 6, timeout: int = 180) -> list[Finding]:
    if not disponible():
        log.info("  [i] schemathesis no instalado — fuzzing de API omitido (extra 'apifuzz')")
        return []
    url = _schema_url(dominio)
    if not url:
        return []
    with tempfile.TemporaryDirectory() as d:
        junit = Path(d) / "report.xml"
        tools.ejecutar(
            [
                str(_ST_BIN),
                "run",
                url,
                "--max-examples",
                str(max_ejemplos),
                "--checks",
                "all",
                "--report",
                "junit",
                "--report-junit-path",
                str(junit),
                "--output-sanitize",
                "true",
                "--suppress-health-check",
                "all",
            ],
            timeout=timeout,
        )
        if not junit.exists():
            return []
        return _parse_junit(junit.read_text(encoding="utf-8", errors="replace"))
