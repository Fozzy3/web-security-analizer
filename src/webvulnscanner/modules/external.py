"""Wrappers de herramientas externas de seguridad.

Cada función corre la herramienta si está instalada y normaliza su salida a
`Finding`; si no está, devuelve [] (el orquestador ni se entera). Así el mismo
código cubre entornos con y sin las herramientas.
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET

from webvulnscanner import tools
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import es_host_valido

log = logging.getLogger("webvulnscanner.external")

# Severidad textual (nuclei/testssl/wpscan) -> Risk
_SEV = {
    "critical": Risk.ALTO,
    "high": Risk.ALTO,
    "medium": Risk.MEDIO,
    "low": Risk.BAJO,
    "info": Risk.INFO,
    "informational": Risk.INFO,
}


# ── nuclei: 9000+ plantillas comunitarias ─────────────────────
def nuclei(dominio: str, *, timeout: int = 300) -> list[Finding]:
    salida = tools.ejecutar(
        ["nuclei", "-u", f"https://{dominio}", "-jsonl", "-silent", "-nc"], timeout=timeout
    )
    if not salida:
        return []
    findings: list[Finding] = []
    for linea in salida.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            d = json.loads(linea)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        sev = info.get("severity", "info").lower()
        findings.append(
            Finding(
                "nuclei",
                f"{info.get('name', d.get('template-id', 'hallazgo'))}",
                _SEV.get(sev, Risk.INFO),
                (info.get("description") or "Detección por plantilla nuclei.")[:300],
                referencia=d.get("matched-at") or d.get("template-url"),
                evidencia=d.get("template-id"),
            )
        )
    log.info("  [+] nuclei: %d hallazgos", len(findings))
    return findings


# ── nmap -sV --script vuln ────────────────────────────────────
def nmap(objetivo: str, *, timeout: int = 300) -> list[Finding]:
    salida = tools.ejecutar(["nmap", "-sV", "--script", "vuln", "-oX", "-", objetivo], timeout=timeout)
    if not salida:
        return []
    try:
        root = ET.fromstring(salida)
    except ET.ParseError:
        return []
    findings: list[Finding] = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        pid = port.get("portid")
        svc = port.find("service")
        nombre = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        for script in port.iter("script"):
            out = (script.get("output") or "").strip()
            if "VULNERABLE" in out.upper() or script.get("id", "").startswith("vulners"):
                findings.append(
                    Finding(
                        "nmap",
                        f"Puerto {pid} ({nombre} {version}): {script.get('id')}",
                        Risk.ALTO,
                        out[:400],
                        evidencia=script.get("id"),
                    )
                )
    log.info("  [+] nmap: %d hallazgos de vulnerabilidad", len(findings))
    return findings


# ── testssl.sh ────────────────────────────────────────────────
def testssl(dominio: str, *, timeout: int = 240) -> list[Finding]:
    salida = tools.ejecutar(
        ["testssl.sh", "--quiet", "--jsonfield", "--json", "/dev/stdout", dominio], timeout=timeout
    )
    if not salida:
        return []
    try:
        datos = json.loads(salida)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for item in datos if isinstance(datos, list) else datos.get("scanResult", []):
        sev = str(item.get("severity", "info")).lower()
        if sev in ("ok", "info", "informational"):
            continue
        findings.append(
            Finding(
                "testssl",
                f"{item.get('id', 'TLS')}: {item.get('finding', '')}"[:120],
                _SEV.get(sev, Risk.INFO),
                str(item.get("finding", ""))[:300],
                evidencia=item.get("id"),
            )
        )
    log.info("  [+] testssl: %d hallazgos", len(findings))
    return findings


# ── WPScan (WordPress) ────────────────────────────────────────
def wpscan(dominio: str, *, timeout: int = 300) -> list[Finding]:
    salida = tools.ejecutar(
        ["wpscan", "--url", f"https://{dominio}", "--format", "json", "--no-banner"],
        timeout=timeout,
    )
    if not salida:
        return []
    try:
        d = json.loads(salida)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []

    def _vulns(origen: dict, contexto: str) -> None:
        for v in origen.get("vulnerabilities", []) or []:
            findings.append(
                Finding(
                    "wpscan",
                    f"{contexto}: {v.get('title', 'vulnerabilidad')}",
                    Risk.ALTO,
                    "Vulnerabilidad conocida en WordPress.",
                    referencia=(v.get("references", {}).get("url") or [None])[0],
                    evidencia=", ".join(v.get("references", {}).get("cve", [])) or None,
                )
            )

    if d.get("version"):
        _vulns(d["version"], f"WordPress core {d['version'].get('number', '')}")
    for slug, plugin in (d.get("plugins") or {}).items():
        _vulns(plugin, f"plugin {slug}")
    for slug, theme in (d.get("themes") or {}).items():
        _vulns(theme, f"tema {slug}")
    log.info("  [+] wpscan: %d vulnerabilidades", len(findings))
    return findings


# ── subfinder (enumeración de subdominios) ────────────────────
def subfinder(dominio: str, *, timeout: int = 120) -> list[Finding]:
    salida = tools.ejecutar(["subfinder", "-d", dominio, "-silent"], timeout=timeout)
    if not salida:
        return []
    # Filtrar a hostnames reales: subfinder mezcla avisos y errores en stdout, y
    # sin esto acababan en el reporte como "subdominios".
    subs = sorted({s.strip().lower() for s in salida.splitlines() if es_host_valido(s)})
    if not subs:
        return []
    log.info("  [+] subfinder: %d subdominios", len(subs))
    return [
        Finding(
            "subfinder",
            f"{len(subs)} subdominios (subfinder)",
            Risk.INFO,
            "Subdominios adicionales descubiertos: " + ", ".join(subs[:20]),
            evidencia="\n".join(subs),
        )
    ]
