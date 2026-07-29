"""Pruebas dirigidas a frameworks/CMS comunes (pivotea sobre la tecnología).

Además de WordPress (ver `wordpress.py`), sondea endpoints característicos de
Drupal, Joomla, Laravel y paneles de administración habituales. Pasivo: solo GET
a rutas conocidas, y cada prueba se auto-confirma con una firma en la respuesta,
así que en sitios que no usan esa tecnología no reporta nada.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.frameworks")

# (ruta, firma_en_body[minúsculas], riesgo, hallazgo, descripción, owasp)
_CHECKS: tuple[tuple[str, str, Risk, str, str, str], ...] = (
    # ── Drupal ──
    (
        "/CHANGELOG.txt",
        "drupal",
        Risk.BAJO,
        "Drupal: CHANGELOG.txt expone la versión",
        "El archivo CHANGELOG.txt es público y revela la versión de Drupal, facilitando buscar "
        "exploits de esa versión. Restrinja o elimine el archivo.",
        "A02:2025",
    ),
    (
        "/user/login",
        "user-login-form",
        Risk.INFO,
        "Drupal: formulario de acceso accesible (/user/login)",
        "El panel de acceso de Drupal está expuesto. Combine con rate-limit y 2FA.",
        "A07:2025",
    ),
    # ── Joomla ──
    (
        "/administrator/manifests/files/joomla.xml",
        "<version>",
        Risk.BAJO,
        "Joomla: versión expuesta en el manifiesto",
        "El manifiesto joomla.xml es accesible y revela la versión exacta de Joomla.",
        "A02:2025",
    ),
    (
        "/administrator/",
        "joomla",
        Risk.INFO,
        "Joomla: panel /administrator accesible",
        "El panel de administración de Joomla está expuesto públicamente. Restrinja el acceso.",
        "A07:2025",
    ),
    # ── Laravel ──
    (
        "/_ignition/health-check",
        "can_execute",
        Risk.ALTO,
        "Laravel Ignition en modo debug expuesto",
        "El endpoint de Ignition (debug de Laravel) responde: expone información sensible y en "
        "versiones vulnerables permite RCE (CVE-2021-3129). Desactive el debug en producción.",
        "A05:2025",
    ),
    (
        "/telescope/requests",
        "telescope",
        Risk.MEDIO,
        "Laravel Telescope expuesto",
        "El panel Telescope está accesible: expone peticiones, consultas y datos internos. "
        "Restrinja Telescope a entornos de desarrollo.",
        "A02:2025",
    ),
    # ── Paneles genéricos ──
    (
        "/phpmyadmin/",
        "phpmyadmin",
        Risk.MEDIO,
        "Panel phpMyAdmin accesible",
        "phpMyAdmin (gestor de base de datos) está expuesto: objetivo directo de fuerza bruta. "
        "Restrínjalo por IP o VPN.",
        "A02:2025",
    ),
    (
        "/adminer.php",
        "adminer",
        Risk.MEDIO,
        "Panel Adminer accesible",
        "Adminer (gestor de base de datos) está expuesto. Restrinja o elimine el archivo.",
        "A02:2025",
    ),
    (
        "/server-status",
        "apache server status",
        Risk.BAJO,
        "mod_status (server-status) expuesto",
        "La página server-status de Apache revela peticiones activas, IPs y rutas internas. "
        "Restrinja el acceso a localhost.",
        "A02:2025",
    ),
)

_RE_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def analizar(dominio: str) -> list[Finding]:
    findings: list[Finding] = []
    for ruta, firma, riesgo, hallazgo, descripcion, owasp in _CHECKS:
        r = fetch(dominio, ruta, max_body=8000)
        if not r or r.status != 200 or firma not in r.body.lower():
            continue
        m = _RE_VERSION.search(r.body)
        log.info("  [!] %s (%s)", hallazgo, ruta)
        findings.append(
            Finding(
                "Frameworks",
                hallazgo,
                riesgo,
                descripcion,
                referencia=ruta,
                evidencia=m.group(1) if m and "versión" in hallazgo.lower() else None,
                owasp=owasp,
            )
        )
    return findings
