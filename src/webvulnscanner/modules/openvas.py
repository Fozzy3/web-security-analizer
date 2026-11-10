"""Módulo OpenVAS / Greenbone Vulnerability Management (GVM).

A diferencia de nuclei/nmap/testssl (un binario que se ejecuta), OpenVAS es una
plataforma cliente-servidor: gvmd + ospd-openvas + PostgreSQL + Redis + feed de
NVTs. Aquí NO se levanta esa infra; se asume una instancia GVM ya corriendo y se
habla con ella por el protocolo GMP sobre un socket Unix (librería `python-gvm`).

Con "Full and fast" (config por defecto) se lanzan TODAS las NVTs del feed —
toda la funcionalidad de OpenVAS. Es un módulo LENTO (un escaneo serio tarda
10-40 min): corre en la 2ª fase del orquestador.

Requisitos del entorno (si faltan, el módulo se omite en silencio como el resto):
  - `pip install python-gvm`
  - una instancia GVM con el socket en /run/gvmd/gvmd.sock (o $GVM_SOCKET)
  - credenciales GMP en $GVM_USERNAME / $GVM_PASSWORD
"""

from __future__ import annotations

import logging
import os
import time
import xml.etree.ElementTree as ET

from webvulnscanner import tools
from webvulnscanner.models import Finding, Risk

log = logging.getLogger("webvulnscanner.openvas")

# threat de GMP -> Risk (no hay CRÍTICO en el modelo: critical/high → ALTO).
_THREAT = {
    "critical": Risk.ALTO,
    "high": Risk.ALTO,
    "medium": Risk.MEDIO,
    "low": Risk.BAJO,
    "log": Risk.INFO,
    "debug": Risk.INFO,
    "false positive": Risk.INFO,
}

# UUIDs bien conocidos de GVM (sobreescribibles por entorno). "Full and fast" =
# todas las NVTs; "All IANA assigned TCP" = todos los puertos TCP asignados.
_CONFIG_FULL_FAST = "daba56c8-73ec-11df-a475-002264764cea"
_SCANNER_OPENVAS = "08b69003-5fc2-4037-a479-93b440211c73"
_PORTLIST_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"


def _elem(resp: str | ET.Element) -> ET.Element:
    """python-gvm (Gmp por defecto) devuelve XML como str; lo normaliza a Element."""
    return resp if isinstance(resp, ET.Element) else ET.fromstring(resp)  # noqa: S314 — XML del propio GVM


def _parsear_reporte(xml: str) -> list[Finding]:
    """Convierte un reporte GMP (get_report) en Findings. Robusto ante XML roto."""
    try:
        root = _elem(xml)
    except ET.ParseError:
        log.warning("  [x] Reporte GMP ilegible")
        return []

    findings: list[Finding] = []
    for res in root.iter("result"):  # iter: ignora el anidamiento report>report
        nombre = (res.findtext("name") or "Hallazgo OpenVAS").strip()
        threat = (res.findtext("threat") or "log").strip().lower()
        riesgo = _THREAT.get(threat, Risk.INFO)
        host = (res.findtext("host") or "").strip()
        puerto = (res.findtext("port") or "").strip()
        desc = (res.findtext("description") or "Detección por NVT de OpenVAS.").strip()

        nvt = res.find("nvt")
        oid = nvt.get("oid", "") if nvt is not None else ""
        cves = _refs(nvt, "cve")
        urls = _refs(nvt, "url")

        # CVE en el título → participa en el dedupe global de CVEs del orquestador.
        hallazgo = nombre
        if cves and "CVE-" not in nombre:
            hallazgo = f"{nombre} ({cves[0]})"

        score = _score(res)
        cvss = {"vector": _vector(nvt), "score": score} if score > 0 else None

        findings.append(
            Finding(
                "OpenVAS",
                hallazgo,
                riesgo,
                desc[:500],
                referencia=_referencia(urls, cves, oid),
                evidencia=f"{host}:{puerto} · NVT {oid}".strip(" ·"),
                cvss=cvss,
            )
        )
    log.info("  [+] OpenVAS: %d hallazgos", len(findings))
    return findings


def _refs(nvt: ET.Element | None, tipo: str) -> list[str]:
    if nvt is None:
        return []
    return [r.get("id", "") for r in nvt.findall("refs/ref") if r.get("type") == tipo and r.get("id")]


def _score(res: ET.Element) -> float:
    try:
        return max(0.0, float(res.findtext("severity") or 0))
    except ValueError:
        return 0.0


def _vector(nvt: ET.Element | None) -> str | None:
    """Extrae cvss_base_vector de las tags del NVT (formato 'k=v|k=v')."""
    if nvt is None:
        return None
    for parte in (nvt.findtext("tags") or "").split("|"):
        if parte.startswith("cvss_base_vector="):
            return parte.split("=", 1)[1] or None
    return None


def _referencia(urls: list[str], cves: list[str], oid: str) -> str | None:
    if urls:
        return urls[0]
    if cves:
        return f"https://nvd.nist.gov/vuln/detail/{cves[0]}"
    return oid or None


def analizar(objetivo: str) -> list[Finding]:
    """Lanza un escaneo GVM 'Full and fast' contra `objetivo` y devuelve Findings.

    Se omite (→ []) si GVM no está disponible. Si está pero la conexión/escaneo
    falla, deja propagar el error para que el orquestador lo marque 'falló'.
    """
    if not tools.motor_disponible("openvas"):
        log.info("  [i] OpenVAS/GVM no disponible — módulo omitido")
        return []
    xml = _ejecutar_scan(objetivo)
    return _parsear_reporte(xml) if xml else []


def _ejecutar_scan(objetivo: str) -> str | None:
    """Orquesta el escaneo vía GMP: target → task → start → poll → get_report.

    ponytail: escaneo síncrono con polling; tope duro $GVM_MAX_WAIT (def. 3600s).
    Para muchos objetivos en paralelo, migrar a un gestor de tasks asíncrono.
    """
    from gvm.connections import UnixSocketConnection  # import perezoso: dep opcional
    from gvm.protocols.gmp import Gmp

    socket = tools.gvm_socket()
    usuario = os.environ.get("GVM_USERNAME", "admin")
    clave = os.environ.get("GVM_PASSWORD")
    if not socket or not clave:
        log.warning("  [x] OpenVAS: falta socket GVM o $GVM_PASSWORD — no se puede escanear")
        return None

    config = os.environ.get("GVM_SCAN_CONFIG", _CONFIG_FULL_FAST)
    scanner = os.environ.get("GVM_SCANNER", _SCANNER_OPENVAS)
    portlist = os.environ.get("GVM_PORT_LIST", _PORTLIST_TCP)
    max_wait = int(os.environ.get("GVM_MAX_WAIT", "3600"))
    poll = int(os.environ.get("GVM_POLL", "15"))

    conexion = UnixSocketConnection(path=socket)
    target_id = task_id = None
    with Gmp(connection=conexion) as gmp:
        gmp.authenticate(usuario, clave)
        try:
            nombre = f"wvs-{objetivo}"
            target_id = _elem(gmp.create_target(name=nombre, hosts=[objetivo], port_list_id=portlist)).get(
                "id"
            )
            task_id = _elem(
                gmp.create_task(name=nombre, config_id=config, target_id=target_id, scanner_id=scanner)
            ).get("id")
            report_id = _elem(gmp.start_task(task_id)).findtext("report_id")
            log.info("  [+] OpenVAS: escaneo lanzado (task %s) — esto tarda; polling…", task_id)

            esperado = 0
            while esperado < max_wait:
                time.sleep(poll)
                esperado += poll
                estado = _elem(gmp.get_task(task_id)).findtext(".//status") or ""
                if estado in ("Done", "Stopped", "Interrupted"):
                    log.info("  [+] OpenVAS: escaneo %s", estado)
                    break
            else:
                log.warning("  [x] OpenVAS: se agotó GVM_MAX_WAIT (%ds); reporte parcial", max_wait)

            return gmp.get_report(report_id, details=True)
        finally:
            # Limpieza best-effort: no dejar target/task colgando en GVM.
            for borrar, arg in ((gmp.delete_task, task_id), (gmp.delete_target, target_id)):
                if arg:
                    try:
                        borrar(arg, ultimate=True)
                    except Exception as e:  # noqa: BLE001
                        log.info("  [-] OpenVAS: no se pudo limpiar %s: %s", arg, e)
