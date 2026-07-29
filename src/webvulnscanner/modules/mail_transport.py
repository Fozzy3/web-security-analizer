"""Seguridad de transporte de correo: MTA-STS y TLS-RPT.

Complementa el módulo DNS (SPF/DMARC/DKIM/BIMI). MTA-STS fuerza TLS en la
entrega de correo (evita downgrade); TLS-RPT habilita reportes de fallos TLS.
Pasivo: consultas DNS + un GET a la política MTA-STS.
"""

from __future__ import annotations

import logging

from webvulnscanner.models import Finding, Risk
from webvulnscanner.modules.dns_records import _consultar
from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.mail_transport")


def _modo_mta_sts(policy: str) -> str | None:
    """Extrae el `mode:` de una política mta-sts.txt (enforce/testing/none)."""
    for linea in (policy or "").splitlines():
        if linea.lower().strip().startswith("mode:"):
            return linea.split(":", 1)[1].strip().lower()
    return None


def _analizar_mta_sts(dominio: str) -> Finding:
    if not _consultar(f"_mta-sts.{dominio}", "TXT"):
        return Finding(
            "MTA-STS",
            "Sin MTA-STS",
            Risk.BAJO,
            "El dominio no publica MTA-STS: un atacante puede forzar el downgrade de TLS en la "
            "entrega de correo (interceptación). Publique una política MTA-STS.",
            owasp="A05:2021",
        )
    policy = fetch(f"mta-sts.{dominio}", "/.well-known/mta-sts.txt")
    modo = _modo_mta_sts(policy.body) if policy and policy.status == 200 else None
    if modo == "enforce":
        return Finding("MTA-STS", "MTA-STS en modo enforce", Risk.OK, "Fuerza TLS en la entrega de correo.")
    if modo == "testing":
        return Finding(
            "MTA-STS",
            "MTA-STS en modo testing (no fuerza TLS aún)",
            Risk.INFO,
            "La política está en 'testing': monitoriza pero no fuerza TLS. Pase a 'enforce'.",
            owasp="A05:2021",
        )
    return Finding(
        "MTA-STS",
        "MTA-STS declarado en DNS pero sin política válida",
        Risk.BAJO,
        "Existe el registro _mta-sts pero la política no es accesible o no define 'mode'.",
        owasp="A05:2021",
    )


def analizar(dominio: str) -> list[Finding]:
    findings = [_analizar_mta_sts(dominio)]

    if not _consultar(f"_smtp._tls.{dominio}", "TXT"):
        findings.append(
            Finding(
                "TLS-RPT",
                "Sin TLS-RPT",
                Risk.INFO,
                "El dominio no publica TLS-RPT: no recibe reportes de fallos de TLS en el correo, "
                "sin visibilidad de intentos de downgrade. Publique un registro _smtp._tls.",
                owasp="A05:2021",
            )
        )
    return findings
