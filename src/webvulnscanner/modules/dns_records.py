"""Módulo 5: Registros DNS y seguridad de correo.

Consulta MX, TXT, NS, CAA y evalúa SPF/DMARC (postura antispoofing del
dominio) y CAA (control de qué CAs pueden emitir certificados). Intenta una
transferencia de zona (AXFR) contra los NS: si tiene éxito es una fuga grave.
"""

from __future__ import annotations

import logging

import dns.resolver
import dns.query
import dns.zone
import dns.exception

from webvulnscanner.models import Finding, Risk

log = logging.getLogger("webvulnscanner.dns")


def _consultar(dominio: str, tipo: str) -> list[str]:
    try:
        resp = dns.resolver.resolve(dominio, tipo, lifetime=6)
        return [r.to_text() for r in resp]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return []


def _txt_plano(registros: list[str]) -> list[str]:
    # dnspython devuelve los TXT entre comillas; las quitamos.
    return [r.strip('"') for r in registros]


def analizar(dominio: str) -> list[Finding]:
    findings: list[Finding] = []

    # MX
    mx = _consultar(dominio, "MX")
    if mx:
        log.info("  [+] MX: %s", ", ".join(mx))
        findings.append(Finding("DNS", f"{len(mx)} registro(s) MX", Risk.INFO,
                                "El dominio recibe correo. Se evalúa SPF/DMARC abajo.",
                                evidencia="; ".join(mx)))

    # SPF (en TXT)
    txt = _txt_plano(_consultar(dominio, "TXT"))
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if spf:
        val = spf[0]
        if "-all" in val:
            findings.append(Finding("DNS", "SPF con política estricta (-all)", Risk.OK,
                                    "SPF rechaza remitentes no autorizados.", evidencia=val))
        elif "~all" in val:
            findings.append(Finding("DNS", "SPF en modo softfail (~all)", Risk.BAJO,
                                    "SPF marca pero no rechaza. Considere endurecer a '-all'.", evidencia=val))
        else:
            findings.append(Finding("DNS", "SPF sin política de rechazo (?all/+all)", Risk.MEDIO,
                                    "SPF no protege contra spoofing de forma efectiva.", evidencia=val))
    elif mx:
        findings.append(Finding("DNS", "Sin registro SPF", Risk.MEDIO,
                                "El dominio recibe correo pero no publica SPF: facilita el spoofing."))

    # DMARC
    dmarc = _txt_plano(_consultar(f"_dmarc.{dominio}", "TXT"))
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if dmarc:
        val = dmarc[0].lower()
        if "p=reject" in val:
            nivel, desc = Risk.OK, "DMARC en 'reject': máxima protección antispoofing."
        elif "p=quarantine" in val:
            nivel, desc = Risk.BAJO, "DMARC en 'quarantine'. Considere 'reject' cuando esté maduro."
        else:
            nivel, desc = Risk.MEDIO, "DMARC en 'none': solo monitorea, no protege."
        findings.append(Finding("DNS", f"DMARC presente ({val.split('p=')[-1].split(';')[0]})",
                                nivel, desc, evidencia=dmarc[0]))
    elif mx:
        findings.append(Finding("DNS", "Sin registro DMARC", Risk.MEDIO,
                                "Sin DMARC no hay política contra suplantación del dominio en correo."))

    # CAA
    caa = _consultar(dominio, "CAA")
    if caa:
        findings.append(Finding("DNS", f"CAA presente ({len(caa)} registro/s)", Risk.OK,
                                "Restringe qué CAs pueden emitir certificados para el dominio.",
                                evidencia="; ".join(caa)))
    else:
        findings.append(Finding("DNS", "Sin registro CAA", Risk.BAJO,
                                "Sin CAA, cualquier CA puede emitir certificados para el dominio."))

    # AXFR contra cada NS
    ns = [n.rstrip(".") for n in _consultar(dominio, "NS")]
    for servidor in ns:
        try:
            zona = dns.zone.from_xfr(dns.query.xfr(servidor, dominio, lifetime=6))
            nombres = len(list(zona.nodes.keys()))
            log.info("  [!!] AXFR permitido en %s (%d registros)", servidor, nombres)
            findings.append(Finding("DNS", f"Transferencia de zona (AXFR) permitida en {servidor}",
                                    Risk.ALTO,
                                    f"El NS expone la zona completa ({nombres} registros): fuga grave de "
                                    "infraestructura interna. Restrinja AXFR a secundarios autorizados.",
                                    evidencia=servidor))
        except Exception:  # noqa: BLE001 — lo normal es que falle (bien configurado)
            continue

    return findings
