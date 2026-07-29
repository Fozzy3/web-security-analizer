"""Análisis TLS profundo con sslyze (opcional).

Complementa el módulo TLS nativo con un motor probado: detecta Heartbleed, ROBOT,
CCS-injection y protocolos obsoletos (SSLv2/v3, TLS 1.0/1.1). Degradación elegante:
si sslyze no está instalado, el módulo se omite.

El mapeo a hallazgos (`_mapear`) es puro y testeable; la ejecución de sslyze es una
capa fina encima (como los wrappers de herramientas externas).
"""

from __future__ import annotations

import logging
from typing import Any

from webvulnscanner.models import Finding, Risk

log = logging.getLogger("webvulnscanner.tls_deep")

try:
    import sslyze  # noqa: F401

    _SSLYZE = True
except Exception:  # noqa: BLE001
    _SSLYZE = False


def disponible() -> bool:
    return _SSLYZE


# (clave, nivel, hallazgo, descripción, referencia)
_VULNS = {
    "heartbleed": (
        Risk.ALTO,
        "Vulnerable a Heartbleed",
        "Fuga de memoria del servidor (CVE-2014-0160). Actualice OpenSSL.",
        "CVE-2014-0160",
    ),
    "robot": (
        Risk.ALTO,
        "Vulnerable a ROBOT",
        "Oráculo de relleno RSA: permite descifrar tráfico o firmar. Deshabilite cifrados RSA.",
        "CVE-2017-13099",
    ),
    "ccs": (
        Risk.ALTO,
        "Vulnerable a CCS Injection",
        "Inyección de ChangeCipherSpec (CVE-2014-0224). Actualice OpenSSL.",
        "CVE-2014-0224",
    ),
    "sslv2": (Risk.ALTO, "Acepta SSLv2", "Protocolo roto (DROWN). Deshabilítelo.", "CVE-2016-0800"),
    "sslv3": (Risk.ALTO, "Acepta SSLv3", "Protocolo obsoleto (POODLE). Deshabilítelo.", "CVE-2014-3566"),
    "tls10": (Risk.MEDIO, "Acepta TLS 1.0", "Obsoleto (BEAST); PCI-DSS lo prohíbe. Migre a TLS 1.2+.", None),
    "tls11": (Risk.MEDIO, "Acepta TLS 1.1", "Obsoleto. Migre a TLS 1.2+.", None),
    "renegociacion": (
        Risk.MEDIO,
        "Renegociación insegura del cliente",
        "Permite renegociación iniciada por el cliente (DoS). Deshabilítela.",
        None,
    ),
}


def _mapear(datos: dict[str, bool]) -> list[Finding]:
    """Traduce el dict de resultados de sslyze a hallazgos. Puro, sin red."""
    findings: list[Finding] = []
    for clave, presente in datos.items():
        if presente and clave in _VULNS:
            nivel, hallazgo, desc, ref = _VULNS[clave]
            findings.append(Finding("TLS (sslyze)", hallazgo, nivel, desc, referencia=ref, owasp="A02:2025"))
    return findings


def _escanear(dominio: str) -> dict[str, bool]:  # pragma: no cover - depende de red y sslyze
    """Ejecuta sslyze y extrae los indicadores. {} si falla."""
    from sslyze import (
        ScanCommand,
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
    )

    req = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=dominio, port=443),
        scan_commands={
            ScanCommand.HEARTBLEED,
            ScanCommand.ROBOT,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
        },
    )
    scanner = Scanner()
    scanner.queue_scans([req])
    datos: dict[str, bool] = {}
    for result in scanner.get_results():
        r: Any = result.scan_result
        with_ok = lambda attempt: attempt.result if attempt and attempt.status.name == "COMPLETED" else None  # noqa: E731

        hb = with_ok(r.heartbleed)
        datos["heartbleed"] = bool(hb and hb.is_vulnerable_to_heartbleed)
        ccs = with_ok(r.openssl_ccs_injection)
        datos["ccs"] = bool(ccs and ccs.is_vulnerable_to_ccs_injection)
        robot = with_ok(r.robot)
        datos["robot"] = bool(robot and "VULNERABLE" in robot.robot_result.name)
        reneg = with_ok(r.session_renegotiation)
        datos["renegociacion"] = bool(reneg and reneg.is_vulnerable_to_client_renegotiation_dos)
        for clave, attr in (
            ("sslv2", r.ssl_2_0_cipher_suites),
            ("sslv3", r.ssl_3_0_cipher_suites),
            ("tls10", r.tls_1_0_cipher_suites),
            ("tls11", r.tls_1_1_cipher_suites),
        ):
            res = with_ok(attr)
            datos[clave] = bool(res and res.accepted_cipher_suites)
    return datos


def analizar(dominio: str) -> list[Finding]:
    if not _SSLYZE:
        return []
    try:
        datos = _escanear(dominio)
    except Exception as e:  # noqa: BLE001
        log.info("  [i] sslyze no pudo escanear %s: %s", dominio, e)
        return []
    return _mapear(datos)
