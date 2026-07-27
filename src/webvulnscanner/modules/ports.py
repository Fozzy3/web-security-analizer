"""Módulo 2: Escaneo de puertos (TCP connect) + banner grabbing.

Connect scan concurrente sobre puertos comunes. En puertos abiertos intenta
leer el banner del servicio para fingerprint de versión (pasivo: solo lee lo
que el servicio anuncia).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import socket

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import leer_banner

log = logging.getLogger("webvulnscanner.ports")

PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

PUERTOS_RIESGO = {
    21: Risk.ALTO, 23: Risk.ALTO, 3306: Risk.ALTO, 3389: Risk.ALTO,
    5432: Risk.ALTO, 6379: Risk.ALTO, 27017: Risk.ALTO, 445: Risk.ALTO,
    25: Risk.MEDIO, 110: Risk.MEDIO, 143: Risk.MEDIO,
    22: Risk.BAJO, 53: Risk.BAJO, 8080: Risk.BAJO, 8443: Risk.BAJO,
    80: Risk.INFO, 443: Risk.INFO,
}

# Sondas mínimas para provocar respuesta en servicios que no hablan primero.
_SONDAS = {80: b"HEAD / HTTP/1.0\r\n\r\n", 8080: b"HEAD / HTTP/1.0\r\n\r\n"}

_DESCRIPCIONES = {
    21: "FTP sin cifrado: transmite credenciales en texto plano.",
    22: "SSH abierto. Use autenticación por clave y deshabilite login root.",
    23: "Telnet obsoleto y sin cifrado. Reemplace por SSH.",
    25: "SMTP expuesto. Verifique que no sea open relay.",
    53: "DNS expuesto. Verifique que no permita recursión externa ni AXFR.",
    80: "HTTP estándar. Debe redirigir a HTTPS (ver módulo TLS).",
    110: "POP3 sin cifrado. Use POP3S (995).",
    143: "IMAP sin cifrado. Use IMAPS (993).",
    443: "HTTPS estándar. Correcto en un servidor web seguro.",
    445: "SMB expuesto: vector crítico (EternalBlue/WannaCry). No exponer a Internet.",
    3306: "MySQL expuesto a Internet. Alto riesgo de acceso no autorizado.",
    3389: "RDP expuesto: objetivo de fuerza bruta y ransomware.",
    5432: "PostgreSQL expuesto. Restrinja por firewall.",
    6379: "Redis sin auth por defecto. Riesgo crítico.",
    8080: "HTTP alternativo. Verifique si el tráfico debería cifrarse.",
    8443: "HTTPS alternativo. Verifique la config TLS.",
    27017: "MongoDB expuesto. Versiones antiguas sin auth. Alto riesgo.",
}


def _escanear(ip: str, puerto: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, puerto), timeout=timeout):
            return True
    except OSError:
        return False


def analizar(ip: str, *, timeout: float = 1.5, grab_banners: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    abiertos: list[int] = []

    log.info("  Escaneando %d puertos en %s...", len(PUERTOS_COMUNES), ip)
    with ThreadPoolExecutor(max_workers=20) as ex:
        futuros = {ex.submit(_escanear, ip, p, timeout): p for p in PUERTOS_COMUNES}
        for fut in as_completed(futuros):
            if fut.result():
                abiertos.append(futuros[fut])

    if not abiertos:
        log.info("  [-] Sin puertos abiertos en la lista analizada")
        return [Finding(
            "Escaneo de Puertos", "No se encontraron puertos abiertos", Risk.INFO,
            "El servidor no responde a los puertos comunes. Puede tener firewall.",
        )]

    for puerto in sorted(abiertos):
        servicio = PUERTOS_COMUNES[puerto]
        nivel = PUERTOS_RIESGO.get(puerto, Risk.MEDIO)
        banner = leer_banner(ip, puerto, enviar=_SONDAS.get(puerto)) if grab_banners else None
        log.info("  [+] %d/TCP abierto → %s [%s]%s",
                 puerto, servicio, nivel.value.upper(),
                 f"  banner: {banner[:60]}" if banner else "")
        desc = _DESCRIPCIONES.get(puerto, f"Puerto {puerto} ({servicio}) abierto.")
        if banner:
            desc += f" Banner detectado: «{banner.splitlines()[0][:120]}»."
        findings.append(Finding(
            "Escaneo de Puertos", f"Puerto {puerto}/TCP abierto ({servicio})", nivel,
            desc, evidencia=banner,
        ))
    return findings
