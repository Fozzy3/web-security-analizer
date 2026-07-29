"""Detección pasiva de CSRF: formularios POST sin token anti-CSRF.

Solo lee lo que el crawler ya descubrió (no envía payloads), así que es PASIVO y
está disponible sin `--authorized`. Un formulario que ejecuta una acción con
efecto (POST) sin token anti-CSRF ni cookies `SameSite` es explotable desde otro
sitio (CSRF, OWASP A01:2021).
"""

from __future__ import annotations

import logging

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse

log = logging.getLogger("webvulnscanner.csrf")

# Nombres de campo que suelen contener un token anti-CSRF.
_TOKENS = (
    "csrf",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
    "csrfmiddlewaretoken",
)


def _tiene_token(inputs: list[str]) -> bool:
    return any(any(t in nombre.lower() for t in _TOKENS) for nombre in inputs)


def analizar(respuesta: HttpResponse | None, crawl: Crawl | None) -> list[Finding]:
    if crawl is None:
        return []

    # SameSite en las cookies mitiga parcialmente el CSRF.
    samesite = False
    if respuesta is not None:
        samesite = "samesite" in (respuesta.header("set-cookie") or "").lower()

    findings: list[Finding] = []
    for form in crawl.forms:
        if form.method.lower() != "post" or _tiene_token(form.inputs):
            continue
        riesgo = Risk.BAJO if samesite else Risk.MEDIO
        mitig = " (mitigado parcialmente por SameSite)" if samesite else ""
        log.info("  [!] Formulario POST sin token anti-CSRF: %s", form.action)
        findings.append(
            Finding(
                "CSRF",
                f"Formulario POST sin token anti-CSRF: {form.action}",
                riesgo,
                "El formulario ejecuta una acción por POST sin token anti-CSRF; es invocable "
                f"desde otro origen (phishing/forzado de acciones){mitig}. Añada un token por sesión.",
                referencia=form.action,
                owasp="A01:2021",
            )
        )
    return findings
