"""Checks web pasivos sobre el HTML servido: mixed content, SRI y formularios.

No envía nada al objetivo: analiza la respuesta que ya se descargó.
"""

from __future__ import annotations

import logging
import re

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.webchecks")

_RE_HTTP_RES = re.compile(r"""(?:src|href)\s*=\s*["'](http://[^"']+)["']""", re.I)
_RE_INTEGRITY = re.compile(r"\bintegrity\s*=", re.I)
_RE_PASSWORD = re.compile(r"""<input\b[^>]*type\s*=\s*["']password["']""", re.I)


def analizar(respuesta: HttpResponse | None) -> list[Finding]:
    if respuesta is None or not respuesta.body:
        return []
    findings: list[Finding] = []
    body = respuesta.body
    es_https = respuesta.esquema == "https"

    # 1. Mixed content: página HTTPS que carga recursos por HTTP
    if es_https:
        recursos_http = [u for u in _RE_HTTP_RES.findall(body) if not u.startswith("http://www.w3.org")]
        if recursos_http:
            log.info("  [!] Mixed content: %d recursos por HTTP", len(recursos_http))
            findings.append(
                Finding(
                    "Integridad",
                    f"Mixed content: {len(recursos_http)} recurso(s) HTTP en página HTTPS",
                    Risk.MEDIO,
                    "Cargar recursos por HTTP en una página HTTPS permite interceptarlos/modificarlos "
                    "(MITM). Sirva todo por HTTPS. Ejemplos: " + ", ".join(recursos_http[:3]),
                    evidencia="\n".join(recursos_http[:10]),
                    owasp="A02:2021",
                )
            )

    # 2. SRI ausente en scripts externos
    sin_sri = []
    for m in re.finditer(r"<script\b[^>]*>", body, re.I):
        tag = m.group(0)
        if re.search(r"""src\s*=\s*["']https?://""", tag, re.I) and not _RE_INTEGRITY.search(tag):
            src = re.search(r"""src\s*=\s*["']([^"']+)""", tag, re.I)
            if src:
                sin_sri.append(src.group(1))
    if sin_sri:
        log.info("  [!] %d scripts externos sin SRI", len(sin_sri))
        findings.append(
            Finding(
                "Integridad",
                f"{len(sin_sri)} script(s) externo(s) sin Subresource Integrity",
                Risk.BAJO,
                "Sin el atributo 'integrity', si el CDN/origen externo es comprometido se ejecuta "
                "código arbitrario. Añada hashes SRI. Ejemplos: " + ", ".join(sin_sri[:3]),
                evidencia="\n".join(sin_sri[:10]),
                owasp="A08:2021",
            )
        )

    # 3. Campo de contraseña en página no-HTTPS
    if not es_https and _RE_PASSWORD.search(body):
        findings.append(
            Finding(
                "Integridad",
                "Formulario con contraseña servido por HTTP",
                Risk.ALTO,
                "Hay un campo de contraseña en una página HTTP: las credenciales viajan en claro.",
                owasp="A02:2021",
            )
        )

    return findings
