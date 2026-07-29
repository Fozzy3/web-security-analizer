"""Pruebas dirigidas a WordPress (pivotea sobre el CMS detectado).

Cuando el objetivo es WordPress, sondea sus endpoints estándar: enumeración de
usuarios (REST y ?author=), xmlrpc, versión en readme.html, wp-login y listado de
uploads. Pasivo: solo GET a rutas conocidas (como el módulo de exposición). Cada
prueba se auto-confirma, así que en sitios que no son WordPress no reporta nada.
"""

from __future__ import annotations

import json
import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.wordpress")

_RE_VERSION = re.compile(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)")
# IPs privadas (RFC 1918) + loopback/link-local — no deberían aparecer en respuestas públicas.
_RE_IP_PRIV = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b"
)


def _enum_usuarios_rest(dominio: str) -> list[Finding]:
    """Analiza /wp-json/wp/v2/users: cuentas expuestas e IPs internas filtradas."""
    r = fetch(dominio, "/wp-json/wp/v2/users")
    if not r or r.status != 200:
        return []
    try:
        datos = json.loads(r.body)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(datos, list) or not datos:
        return []

    cuentas: list[str] = []  # "id N: slug"
    ips_internas: set[str] = set()
    for u in datos:
        if not isinstance(u, dict):
            continue
        slug = u.get("slug") or u.get("name")
        if slug:
            cuentas.append(f"id {u.get('id', '?')}: {slug}")
        # El campo 'url' del autor suele filtrar la URL/IP interna configurada.
        ips_internas.update(_RE_IP_PRIV.findall(str(u.get("url") or "")))

    findings: list[Finding] = []
    if cuentas:
        n = len(cuentas)
        admin = (
            " (el id 1 es la cuenta de administrador)" if any(c.startswith("id 1:") for c in cuentas) else ""
        )
        log.info("  [!] wp-json expone %d cuenta(s): %s", n, "; ".join(cuentas))
        findings.append(
            Finding(
                "WordPress",
                f"La REST API expone {n} cuenta de usuario" + ("s" if n != 1 else ""),
                Risk.ALTO,
                f"El endpoint /wp-json/wp/v2/users lista las cuentas con permiso de publicar: {'; '.join(cuentas)}"
                f"{admin}. Conocer el nombre de usuario es la mitad de un ataque de fuerza bruta; "
                "combinado con la ausencia de rate-limit, el login queda expuesto. Restrinja el endpoint.",
                referencia="/wp-json/wp/v2/users",
                evidencia="; ".join(cuentas),
                owasp="A07:2025",
            )
        )
    if ips_internas:
        log.info("  [!] wp-json filtra IP(s) interna(s): %s", ", ".join(sorted(ips_internas)))
        findings.append(
            Finding(
                "WordPress",
                "Divulgación de IP interna vía wp-json",
                Risk.MEDIO,
                "El campo 'url' de un usuario expone una IP privada de la red interna "
                f"({', '.join(sorted(ips_internas))}), revelando la dirección real del backend detrás "
                "del proxy/balanceador. Facilita ataques dirigidos y SSRF. Sanee ese campo.",
                referencia="/wp-json/wp/v2/users",
                evidencia=", ".join(sorted(ips_internas)),
                owasp="A05:2025",
            )
        )
    return findings


def _xmlrpc(dominio: str) -> Finding | None:
    r = fetch(dominio, "/xmlrpc.php")
    if r and "xml-rpc server accepts post" in r.body.lower():
        log.info("  [!] xmlrpc.php habilitado")
        return Finding(
            "WordPress",
            "xmlrpc.php habilitado",
            Risk.MEDIO,
            "xmlrpc.php está activo: permite amplificar fuerza bruta (system.multicall) y ataques "
            "de pingback/DDoS. Deshabilítelo si no lo usa.",
            referencia="/xmlrpc.php",
            owasp="A05:2025",
        )
    return None


def _enum_autor(dominio: str) -> Finding | None:
    r = fetch(dominio, "/?author=1")
    if r and "/author/" in r.url:
        usuario = r.url.rstrip("/").split("/")[-1]
        log.info("  [!] Enumeración de autor vía ?author=1 → %s", usuario)
        return Finding(
            "WordPress",
            "Enumeración de usuarios por autor (?author=1)",
            Risk.MEDIO,
            "La consulta ?author=1 redirige al slug del usuario, revelando nombres de cuenta. "
            "Bloquee la redirección de autor.",
            referencia="/?author=1",
            evidencia=usuario,
            owasp="A07:2025",
        )
    return None


def _readme(dominio: str) -> Finding | None:
    r = fetch(dominio, "/readme.html")
    if not r or r.status != 200 or "wordpress" not in r.body.lower():
        return None
    m = _RE_VERSION.search(r.body)
    version = m.group(1) if m else "?"
    log.info("  [i] readme.html expone versión de WordPress: %s", version)
    return Finding(
        "WordPress",
        "readme.html revela la versión de WordPress",
        Risk.BAJO,
        "El archivo readme.html es público y expone la versión exacta de WordPress, facilitando "
        "buscar exploits de esa versión. Bórrelo o restrinja su acceso.",
        referencia="/readme.html",
        evidencia=version,
        owasp="A02:2025",
    )


def _wp_login(dominio: str) -> Finding | None:
    r = fetch(dominio, "/wp-login.php")
    if r and r.status == 200 and "user_login" in r.body.lower():
        return Finding(
            "WordPress",
            "Panel de acceso wp-login.php accesible",
            Risk.INFO,
            "El panel de administración está expuesto públicamente. Combínelo con rate-limit y "
            "2FA; considere restringir el acceso por IP.",
            referencia="/wp-login.php",
            owasp="A07:2025",
        )
    return None


def _uploads_listables(dominio: str) -> Finding | None:
    r = fetch(dominio, "/wp-content/uploads/")
    if r and r.status == 200 and "index of" in r.body.lower():
        return Finding(
            "WordPress",
            "Listado de directorio en /wp-content/uploads/",
            Risk.BAJO,
            "El directorio de subidas permite listar su contenido: puede exponer archivos no "
            "enlazados. Desactive el directory listing.",
            referencia="/wp-content/uploads/",
            owasp="A02:2025",
        )
    return None


def analizar(dominio: str) -> list[Finding]:
    findings = _enum_usuarios_rest(dominio)  # devuelve 0..2 hallazgos
    for prueba in (_xmlrpc, _enum_autor, _readme, _wp_login, _uploads_listables):
        f = prueba(dominio)
        if f is not None:
            findings.append(f)
    return findings
