"""Módulo 9: Fingerprint de tecnologías web.

Identifica CMS, frameworks y lenguajes por firmas en cabeceras, cookies y HTML
(meta generator, rutas típicas). Alimenta la búsqueda de CVEs cuando detecta
una versión.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.fingerprint")

_RE_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

# tecnología -> lista de firmas: (fuente, patrón). fuente ∈ {header:<n>, cookie, body}
_FIRMAS = {
    "WordPress": [("body", "/wp-content/"), ("body", "/wp-includes/"), ("header:x-generator", "wordpress")],
    "Drupal": [("body", "sites/all/"), ("header:x-generator", "drupal"), ("header:x-drupal-cache", "")],
    "Joomla": [("body", "/media/jui/"), ("body", "com_content")],
    "PHP": [("header:x-powered-by", "php"), ("cookie", "phpsessid")],
    "ASP.NET": [("header:x-powered-by", "asp.net"), ("header:x-aspnet-version", ""), ("cookie", "asp.net_sessionid")],
    "Laravel": [("cookie", "laravel_session")],
    "Django": [("cookie", "csrftoken"), ("cookie", "django")],
    "Express/Node": [("header:x-powered-by", "express")],
    "Nginx": [("header:server", "nginx")],
    "Apache": [("header:server", "apache")],
}


def detectar(respuesta: HttpResponse) -> dict[str, str]:
    """Devuelve {tecnología: evidencia}. Incluye versión si aparece en meta generator."""
    encontrados: dict[str, str] = {}
    body = respuesta.body.lower()
    cookies = respuesta.header("set-cookie", "").lower()

    for tech, firmas in _FIRMAS.items():
        for fuente, patron in firmas:
            if fuente == "body" and patron in body:
                encontrados[tech] = patron
                break
            if fuente == "cookie" and patron in cookies:
                encontrados[tech] = f"cookie {patron}"
                break
            if fuente.startswith("header:"):
                valor = respuesta.header(fuente.split(":", 1)[1], "") or ""
                if patron == "" and valor or (patron and patron in valor.lower()):
                    encontrados[tech] = valor or fuente
                    break

    m = _RE_GENERATOR.search(respuesta.body)
    if m:
        gen = m.group(1).strip()
        encontrados[f"generator: {gen}"] = gen

    return encontrados


def analizar(respuesta: HttpResponse | None) -> list[Finding]:
    if respuesta is None:
        return []
    techs = detectar(respuesta)
    if not techs:
        return [Finding("Fingerprint", "No se identificaron tecnologías por firmas", Risk.INFO,
                        "No se detectaron CMS/frameworks conocidos en headers, cookies ni HTML.")]
    log.info("  [+] Tecnologías: %s", ", ".join(techs))
    # Un generator con número de versión es más sensible.
    tiene_version = any(re.search(r"\d+\.\d+", t) for t in techs)
    nivel = Risk.MEDIO if tiene_version else Risk.BAJO
    return [Finding("Fingerprint", f"Tecnologías detectadas: {', '.join(techs)}", nivel,
                    "Conocer el stack facilita buscar exploits específicos. "
                    + ("Se detectó número de versión: revise CVEs para esa versión."
                       if tiene_version else "Evite exponer versiones concretas."),
                    evidencia=", ".join(f"{k}={v}" for k, v in techs.items()))]
