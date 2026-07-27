"""Módulo 1: Reconocimiento (footprinting).

Resolución DNS (IPv4 + IPv6) y lectura de cabeceras de servidor. Extrae
producto/versión del servidor para que el módulo CVE pueda correlacionar.
"""

from __future__ import annotations

import logging
import re
import socket

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.recon")

# "Apache/2.4.29 (Ubuntu)" -> ("Apache", "2.4.29")
_RE_SERVIDOR = re.compile(r"([A-Za-z][A-Za-z0-9_\-]*)\s*/\s*([0-9][0-9A-Za-z.\-]*)")


def resolver_ips(dominio: str) -> dict[str, list[str]]:
    """Resuelve A (IPv4) y AAAA (IPv6) usando getaddrinfo (sin dependencias)."""
    ips: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    try:
        for fam, *_rest, sockaddr in socket.getaddrinfo(dominio, None):
            addr = str(sockaddr[0])
            if fam == socket.AF_INET and addr not in ips["ipv4"]:
                ips["ipv4"].append(addr)
            elif fam == socket.AF_INET6 and addr not in ips["ipv6"]:
                ips["ipv6"].append(addr)
    except socket.gaierror:
        pass
    return ips


def extraer_producto_version(server_header: str) -> tuple[str, str] | None:
    """De 'Apache/2.4.29 (Ubuntu)' extrae ('apache', '2.4.29'). None si no hay versión."""
    m = _RE_SERVIDOR.search(server_header or "")
    if not m:
        return None
    return m.group(1).lower(), m.group(2)


def analizar(dominio: str, respuesta: HttpResponse | None) -> tuple[list[Finding], dict]:
    """Devuelve (findings, info) donde info alimenta a otros módulos."""
    findings: list[Finding] = []
    info: dict = {"dominio": dominio}

    ips = resolver_ips(dominio)
    info["ips"] = ips
    todas = ips["ipv4"] + ips["ipv6"]

    if not todas:
        log.info("  [-] No se pudo resolver el dominio: %s", dominio)
        findings.append(
            Finding(
                "Reconocimiento",
                f"No se pudo resolver el dominio '{dominio}'",
                Risk.ALTO,
                "El dominio no resuelve a ninguna IP. Verifique que sea correcto.",
            )
        )
        return findings, info

    info["ip"] = ips["ipv4"][0] if ips["ipv4"] else ips["ipv6"][0]
    log.info("  [+] IPv4: %s | IPv6: %s", ips["ipv4"] or "—", ips["ipv6"] or "—")
    findings.append(
        Finding(
            "Reconocimiento",
            f"Dominio resuelve a {len(todas)} IP(s): {', '.join(todas)}",
            Risk.INFO,
            "Resolución DNS exitosa. Las IPs públicas sirven para reconocimiento adicional.",
            evidencia=", ".join(todas),
        )
    )

    if not respuesta:
        return findings, info

    servidor = respuesta.header("server")
    if servidor:
        info["servidor"] = servidor
        log.info("  [+] Servidor: %s", servidor)
        prod = extraer_producto_version(servidor)
        if prod:
            info["producto"], info["version"] = prod
            riesgo, extra = Risk.MEDIO, " Expone producto y versión exactos, útil para buscar CVEs."
        else:
            riesgo, extra = Risk.BAJO, ""
        findings.append(
            Finding(
                "Reconocimiento",
                f"Servidor web: {servidor}",
                riesgo,
                "La cabecera 'Server' revela el software del servidor."
                + extra
                + " Se recomienda ocultarla o generalizarla.",
                evidencia=servidor,
            )
        )

    powered = respuesta.header("x-powered-by")
    if powered:
        info["x_powered_by"] = powered
        log.info("  [!] X-Powered-By: %s", powered)
        findings.append(
            Finding(
                "Reconocimiento",
                f"Tecnología expuesta (X-Powered-By): {powered}",
                Risk.MEDIO,
                "Expone lenguaje/framework del backend (ej. PHP/7.4), facilitando ataques dirigidos.",
                evidencia=powered,
            )
        )

    return findings, info
