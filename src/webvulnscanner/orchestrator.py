"""Orquestador: coordina los módulos de análisis y arma el ScanResult.

Cada módulo se ejecuta aislado: si uno falla, se registra y el escaneo sigue.
La comunicación de progreso es vía logging (el CLI y la GUI enganchan sus
propios handlers), no secuestrando sys.stdout.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from webvulnscanner import classify, crawler, enrich, owasp, sbom, tools
from webvulnscanner.models import Finding, Risk, ScanResult
from webvulnscanner.modules import (
    access_control,
    active,
    api_discovery,
    api_fuzz,
    auth_test,
    cloud,
    csrf,
    cve,
    disclosure,
    dns_records,
    error_audit,
    external,
    fingerprint,
    frameworks,
    headers,
    jwt_audit,
    mail_transport,
    ports,
    rate_limit,
    recon,
    retire_js,
    secrets,
    shodan_intel,
    ssrf,
    stack,
    subdomains,
    tls,
    tls_deep,
    waf,
    webchecks,
    wordpress,
)
from webvulnscanner.net import Sesion, configurar_sesion, fetch, normalizar_dominio

log = logging.getLogger("webvulnscanner")

# Orden y etiquetas de los módulos PASIVOS (siempre disponibles).
MODULOS = [
    ("recon", "Reconocimiento (Footprinting)"),
    ("ports", "Escaneo de Puertos + Banners"),
    ("tls", "Análisis TLS / HTTPS"),
    ("tls_deep", "TLS profundo (sslyze, opcional)"),
    ("headers", "Encabezados HTTP de Seguridad"),
    ("dns", "Registros DNS y Seguridad de Correo"),
    ("subdomains", "Subdominios (Certificate Transparency)"),
    ("disclosure", "Archivos y Rutas Sensibles"),
    ("waf", "Detección de WAF / CDN"),
    ("fingerprint", "Fingerprint de Tecnologías"),
    ("stack", "Stack extendido (Wappalyzer) + CVE por componente"),
    ("wordpress", "WordPress (endpoints y enumeración)"),
    ("frameworks", "Frameworks/CMS (Drupal, Joomla, Laravel, paneles)"),
    ("webchecks", "Mixed content / SRI / Formularios"),
    ("csrf", "CSRF (formularios sin token)"),
    ("retirejs", "Librerías JS Vulnerables"),
    ("secrets", "Secretos Expuestos"),
    ("jwt", "Debilidades en JWT"),
    ("api", "Superficie de API (OpenAPI/GraphQL)"),
    ("cloud", "Misconfiguración Cloud"),
    ("mail_transport", "MTA-STS / TLS-RPT"),
    ("sbom", "Supply Chain / Dependency Confusion"),
    ("cve", "Correlación de CVEs (NVD)"),
    ("shodan", "Inteligencia Shodan (opcional)"),
    ("subfinder", "Subdominios (subfinder, externo)"),
    ("testssl", "TLS profundo (testssl.sh, externo)"),
]

# Módulos ACTIVOS (Fase D+): solo con autorización explícita (autorizado=True).
MODULOS_ACTIVOS = [
    ("cookies", "Flags de Cookies"),
    ("cors", "Configuración CORS"),
    ("inyeccion", "Inyección Reflejada (XSS/SQLi)"),
    ("open_redirect", "Open Redirect"),
    ("fuzzing", "Fuzzing de Rutas"),
    ("access_control", "Control de Acceso (IDOR / forced browsing)"),
    ("auth_test", "Fallos de Autenticación"),
    ("ssrf", "SSRF / Host Header Injection"),
    ("error_audit", "Manejo de Errores (stack traces / debug)"),
    ("rate_limit", "Rate Limiting (consumo de recursos)"),
    ("api_fuzz", "Fuzzing de API (schemathesis, opcional)"),
    ("nuclei", "nuclei (plantillas, externo)"),
    ("nmap", "nmap --script vuln (externo)"),
    ("wpscan", "WPScan (externo)"),
]

# Módulos LENTOS (motores externos + fuzzing de API): corren en una 2ª fase para
# que el informe salga ya con lo rápido y se actualice cuando estos terminen.
_MODULOS_LENTOS = frozenset({"tls_deep", "subfinder", "testssl", "nuclei", "nmap", "wpscan", "api_fuzz"})


def _ejecutar(nombre: str, fn) -> list[Finding]:
    """Corre un módulo capturando cualquier error para no abortar el escaneo."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Módulo '%s' falló: %s", nombre, e)
        return [
            Finding(
                nombre, f"El módulo '{nombre}' falló durante la ejecución", Risk.INFO, f"Error interno: {e}"
            )
        ]


def run_scan(
    dominio: str,
    *,
    activos: set[str] | None = None,
    paralelo: bool = True,
    max_workers: int = 8,
    sesion: Sesion | None = None,
    rl_burst: int = 12,
    on_parcial: Callable[[ScanResult], None] | None = None,
) -> ScanResult:
    """Ejecuta el escaneo completo (todos los módulos) o el subconjunto en `activos`.

    recon corre primero (define ip/producto que otros módulos necesitan); el
    resto corre en paralelo salvo que `paralelo=False`. Los findings se
    ensamblan en el orden de MODULOS para que el reporte sea determinista.

    **Corre TODOS los módulos** (pasivos + activos): los activos envían peticiones
    elaboradas al objetivo. Úsese solo sobre objetivos propios o autorizados.
    Para limitar el alcance, pasar `activos` con el subconjunto deseado.

    `sesion` fija credenciales de auth y throttle para TODAS las peticiones
    (escaneo autenticado). Lanza ValueError si `dominio` no es un hostname válido.
    `rl_burst` fija el tamaño de ráfaga del módulo rate_limit (API4:2023).
    """
    activos = activos or ({n for n, _ in MODULOS} | {n for n, _ in MODULOS_ACTIVOS})
    if sesion is not None:
        configurar_sesion(sesion)  # auth + throttle para todos los módulos
    dominio = normalizar_dominio(dominio)  # lanza ValueError si no es un host

    respuesta = fetch(dominio)  # una sola petición compartida por varios módulos
    result = ScanResult(dominio=dominio)

    # recon primero: define ip/producto/version que necesitan otros módulos
    log.info("\n[MÓDULO] Reconocimiento (Footprinting)\n" + "─" * 48)
    f_recon, info = _run_recon(dominio, respuesta)
    result.findings.extend(f_recon)
    result.ip = info.get("ip")
    result.servidor = info.get("servidor")

    if not info.get("ip"):
        log.info("  Análisis detenido: el dominio no resuelve.")
        return result

    # Crawler compartido (browsing pasivo): habilita retire.js, secretos e inyección dirigida.
    crawl = crawler.Crawl()
    if respuesta is not None:
        log.info("\n[CRAWLER] Descubriendo URLs, parámetros y scripts\n" + "─" * 48)
        crawl = _ejecutar_crawler(dominio)

    # (nombre -> función del módulo). Solo los que estén activos.
    trabajos: dict[str, Callable[[], list[Finding]]] = {
        "ports": lambda: ports.analizar(info["ip"]),
        "tls": lambda: tls.analizar(dominio),
        "tls_deep": lambda: tls_deep.analizar(dominio),
        "headers": lambda: headers.analizar(respuesta),
        "dns": lambda: dns_records.analizar(dominio),
        "subdomains": lambda: subdomains.analizar(dominio),
        "disclosure": lambda: disclosure.analizar(dominio),
        "waf": lambda: waf.analizar(respuesta),
        "fingerprint": lambda: fingerprint.analizar(respuesta),
        "stack": lambda: stack.analizar(dominio, respuesta),
        "wordpress": lambda: wordpress.analizar(dominio),
        "frameworks": lambda: frameworks.analizar(dominio),
        "webchecks": lambda: webchecks.analizar(respuesta),
        "csrf": lambda: csrf.analizar(respuesta, crawl),
        "retirejs": lambda: retire_js.analizar_scripts(crawl.scripts),
        "secrets": lambda: secrets.analizar(dominio, crawl.scripts),
        "jwt": lambda: jwt_audit.analizar(dominio, crawl.scripts),
        "api": lambda: api_discovery.analizar(dominio),
        "cloud": lambda: cloud.analizar(dominio, crawl.scripts),
        "mail_transport": lambda: mail_transport.analizar(dominio),
        "sbom": lambda: sbom.analizar(dominio, crawl.scripts),
        "cve": lambda: cve.analizar(info.get("producto"), info.get("version")),
        "shodan": lambda: shodan_intel.analizar(info.get("ip")),
        "subfinder": lambda: external.subfinder(dominio),
        "testssl": lambda: external.testssl(dominio),
    }

    # Activos SIEMPRE (sin gate): la herramienta corre con todo. Envían peticiones
    # elaboradas al objetivo — úsese solo sobre objetivos propios o autorizados.
    log.warning("  ⚠ Escaneo ACTIVO: se enviarán peticiones de prueba al objetivo.")
    trabajos.update(
        {
            "cookies": lambda: active.analizar_cookies(respuesta),
            "cors": lambda: active.analizar_cors(dominio),
            "inyeccion": lambda: active.analizar_inyeccion(dominio, crawl),
            "open_redirect": lambda: active.analizar_open_redirect(dominio, crawl),
            "fuzzing": lambda: active.analizar_fuzzing(dominio),
            "access_control": lambda: access_control.analizar(dominio, crawl),
            "auth_test": lambda: auth_test.analizar(dominio, crawl, info.get("producto")),
            "ssrf": lambda: ssrf.analizar(dominio, crawl),
            "error_audit": lambda: error_audit.analizar(dominio),
            "rate_limit": lambda: rate_limit.analizar(dominio, burst=rl_burst),
            "api_fuzz": lambda: api_fuzz.analizar(dominio),
            "nuclei": lambda: external.nuclei(dominio),
            "nmap": lambda: external.nmap(info["ip"]),
            "wpscan": lambda: external.wpscan(dominio),
        }
    )
    orden = list(MODULOS) + MODULOS_ACTIVOS

    pendientes = {n: fn for n, fn in trabajos.items() if n in activos}
    lentos_keys = frozenset(pendientes) & _MODULOS_LENTOS
    rapidos = {n: fn for n, fn in pendientes.items() if n not in lentos_keys}
    lentos = {n: fn for n, fn in pendientes.items() if n in lentos_keys}

    def _correr(sub: dict[str, Callable[[], list[Finding]]]) -> dict[str, list[Finding]]:
        if not sub:
            return {}
        if paralelo:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                return dict(zip(sub, ex.map(lambda nf: _ejecutar(*nf), sub.items()), strict=True))
        return {n: _ejecutar(n, fn) for n, fn in sub.items()}

    def _ensamblar(resultados: dict[str, list[Finding]], en_progreso: frozenset[str] = frozenset()) -> None:
        # Reconstruye findings desde recon en el orden canónico; post-proceso idempotente.
        findings = list(f_recon)
        for nombre, _label in orden:
            if nombre in resultados:
                findings.extend(resultados[nombre])
        findings = _dedupe_cves(findings)
        enrich.enriquecer(findings)
        owasp.etiquetar(findings)
        classify.clasificar(findings)
        result.findings = findings
        result.estado_modulos = _estado_modulos(orden, resultados, en_progreso)

    # Fase 1 — módulos rápidos: informe inmediato, con los lentos marcados "en progreso".
    resultados = _correr(rapidos)
    if lentos and on_parcial is not None:
        _ensamblar(resultados, en_progreso=lentos_keys)
        try:
            on_parcial(result)
        except Exception as e:  # noqa: BLE001 — un fallo emitiendo el parcial no aborta el escaneo
            log.warning("  [x] No se pudo emitir el informe parcial: %s", e)

    # Fase 2 — módulos lentos (nuclei/testssl/nmap/…): informe final actualizado.
    if lentos:
        log.info("\n[FASE 2] Análisis profundo: %s\n%s", ", ".join(sorted(lentos)), "─" * 48)
        resultados.update(_correr(lentos))
    _ensamblar(resultados)
    return result


# Módulo activo/pasivo → clave de motor externo en tools.MOTORES.
# shodan ya NO está aquí: usa la API gratuita InternetDB (sin key), así que siempre corre.
_MOTOR_DE_MODULO: dict[str, str] = {
    "tls_deep": "sslyze",
    "api_fuzz": "schemathesis",
    "subfinder": "subfinder",
    "testssl": "testssl",
    "nuclei": "nuclei",
    "nmap": "nmap",
    "wpscan": "wpscan",
}


def _estado_modulos(
    orden: list[tuple[str, str]],
    resultados: dict[str, list[Finding]],
    en_progreso: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Estado de ejecución por módulo: 'analizado', 'omitido — <motor> …', 'falló'
    o 'en progreso' (módulos lentos aún corriendo en la 2ª fase).

    recon corre siempre (fuera de `resultados`); un módulo cuyo motor externo
    no está instalado se marca 'omitido' con el comando de instalación; uno que
    lanzó, 'falló'.
    """
    estado: dict[str, str] = {}
    for key, etiqueta in orden:
        if key == "recon":
            estado[etiqueta] = "analizado"
            continue
        if key in en_progreso:
            estado[etiqueta] = "en progreso — análisis profundo en curso"
            continue
        if key not in resultados:
            continue  # no seleccionado (subconjunto en `activos`)
        motor = _MOTOR_DE_MODULO.get(key)
        if motor and not tools.motor_disponible(motor):
            etq, _chk, cmd = tools.MOTORES[motor]
            estado[etiqueta] = f"omitido — {etq} no instalado (instalar: {cmd})"
        elif any("falló durante la ejecución" in f.hallazgo for f in resultados[key]):
            estado[etiqueta] = "falló"
        else:
            estado[etiqueta] = "analizado"
    return estado


_RE_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def _dedupe_cves(findings: list[Finding]) -> list[Finding]:
    """Elimina hallazgos de un mismo CVE repetido (mantiene el primero)."""
    vistos: set[str] = set()
    salida: list[Finding] = []
    for f in findings:
        m = _RE_CVE_ID.search(f.hallazgo)
        if m:
            if m.group() in vistos:
                continue
            vistos.add(m.group())
        salida.append(f)
    return salida


def _ejecutar_crawler(dominio: str) -> crawler.Crawl:
    try:
        return crawler.rastrear(dominio)
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Crawler falló: %s", e)
        return crawler.Crawl()


def _run_recon(dominio, respuesta):
    try:
        return recon.analizar(dominio, respuesta)
    except Exception as e:  # noqa: BLE001
        log.warning("  [x] Reconocimiento falló: %s", e)
        return [Finding("Reconocimiento", "Falló el reconocimiento", Risk.ALTO, str(e))], {}
