"""Módulos ACTIVOS (Fase D). Envían peticiones elaboradas al objetivo.

⚠️  A diferencia del resto de la herramienta, esto NO es pasivo: prueba cookies,
CORS, reflexión de parámetros (XSS/SQLi) y rutas por diccionario. Solo debe
ejecutarse contra objetivos propios o con autorización EXPRESA. El orquestador
únicamente lo activa con `autorizado=True`.

Los payloads son deliberadamente no destructivos: un marcador único para
reflexión, una comilla para errores SQL, y GET a rutas comunes. Nada de escritura
ni de explotación real.
"""

from __future__ import annotations

import logging
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse, fetch

log = logging.getLogger("webvulnscanner.active")

_MARCADOR = "wvs9z7xq"  # improbable de aparecer por casualidad
_PARAMS_REDIRECT = ("url", "redirect", "next", "return", "returnUrl", "dest", "destination", "r", "u")
_ERRORES_SQL = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "pg_query():",
    "sqlite3.operationalerror",
    "ora-01756",
)
_RUTAS_FUZZ = (
    "/admin",
    "/login",
    "/.git/config",
    "/backup.zip",
    "/phpinfo.php",
    "/server-status",
    "/wp-admin/",
    "/.svn/entries",
    "/api",
    "/debug",
)


# ── Cookies (flags de seguridad) ──────────────────────────────
def analizar_cookies(respuesta: HttpResponse | None) -> list[Finding]:
    if respuesta is None:
        return []
    cookies = respuesta.headers.get("set-cookie")
    if not cookies:
        return []
    low = cookies.lower()
    findings: list[Finding] = []
    if "secure" not in low:
        findings.append(
            Finding(
                "Cookies",
                "Cookie sin flag Secure",
                Risk.MEDIO,
                "Una cookie sin 'Secure' puede viajar por HTTP y ser interceptada.",
                evidencia=cookies[:120],
            )
        )
    if "httponly" not in low:
        findings.append(
            Finding(
                "Cookies",
                "Cookie sin flag HttpOnly",
                Risk.MEDIO,
                "Sin 'HttpOnly', JavaScript puede leer la cookie (robo de sesión vía XSS).",
                evidencia=cookies[:120],
            )
        )
    if "samesite" not in low:
        findings.append(
            Finding(
                "Cookies",
                "Cookie sin atributo SameSite",
                Risk.BAJO,
                "Sin 'SameSite' la cookie se envía en peticiones cross-site (riesgo CSRF).",
                evidencia=cookies[:120],
            )
        )
    return findings


# ── CORS ──────────────────────────────────────────────────────
def analizar_cors(dominio: str) -> list[Finding]:
    origen = "https://evil.example"
    resp = fetch(dominio, "/", cabeceras_extra={"Origin": origen})
    if resp is None:
        return []
    acao = resp.header("access-control-allow-origin")
    acac = (resp.header("access-control-allow-credentials") or "").lower()
    if acao == "*":
        return [
            Finding(
                "CORS",
                "CORS permisivo (Access-Control-Allow-Origin: *)",
                Risk.MEDIO,
                "Cualquier origen puede leer respuestas. Peligroso si expone datos sensibles.",
                evidencia=acao,
            )
        ]
    if acao == origen:
        nivel = Risk.ALTO if acac == "true" else Risk.MEDIO
        return [
            Finding(
                "CORS",
                "CORS refleja el Origin del atacante",
                nivel,
                "El servidor refleja un Origin arbitrario"
                + (" con credenciales: robo de datos autenticados." if acac == "true" else "."),
                evidencia=f"ACAO={acao}; credentials={acac}",
            )
        ]
    return []


def _objetivos(crawl: Crawl | None) -> list[tuple[str, str]]:
    """Lista de (ruta, parámetro) a probar. Usa lo descubierto por el crawler;
    si no hay crawl, cae a los parámetros genéricos en la raíz."""
    objetivos: list[tuple[str, str]] = []
    if crawl and crawl.params:
        for ruta, params in crawl.params.items():
            for p in params:
                objetivos.append((ruta or "/", p))
    if not objetivos:
        objetivos = [("/", "q"), ("/", "id"), ("/", "search"), ("/", "page")]
    return objetivos[:40]  # cota de seguridad


# ── Inyección reflejada (XSS / SQLi error-based) ──────────────
def analizar_inyeccion(dominio: str, crawl: Crawl | None = None) -> list[Finding]:
    findings: list[Finding] = []
    xss_payload = f'{_MARCADOR}"<x>'
    reportado_xss = reportado_sqli = False

    for ruta, param in _objetivos(crawl):
        if not reportado_xss:
            r = fetch(dominio, f"{ruta}?{param}={urllib.parse.quote(xss_payload)}")
            if r and xss_payload in r.body:
                log.info("  [!!] XSS reflejado en %s (param %s)", ruta, param)
                findings.append(
                    Finding(
                        "Inyección",
                        f"Posible XSS reflejado en {ruta} (parámetro '{param}')",
                        Risk.ALTO,
                        'El parámetro se refleja sin codificar < > ". Verifique la explotabilidad.',
                        referencia=f"{ruta}?{param}=",
                        evidencia=xss_payload,
                    )
                )
                reportado_xss = True
        if not reportado_sqli:
            r2 = fetch(dominio, f"{ruta}?{param}=1%27")
            if r2 and any(err in r2.body.lower() for err in _ERRORES_SQL):
                log.info("  [!!] SQLi error-based en %s (param %s)", ruta, param)
                findings.append(
                    Finding(
                        "Inyección",
                        f"Posible SQL injection en {ruta} (parámetro '{param}')",
                        Risk.ALTO,
                        "Una comilla dispara un error SQL: parámetro no parametrizado. Verifique manualmente.",
                        referencia=f"{ruta}?{param}=",
                        evidencia="comilla",
                    )
                )
                reportado_sqli = True
        if reportado_xss and reportado_sqli:
            break
    return findings


# ── Open redirect ─────────────────────────────────────────────
def analizar_open_redirect(dominio: str, crawl: Crawl | None = None) -> list[Finding]:
    findings: list[Finding] = []
    destino = "https://evil.example/"
    # Parámetros candidatos: los típicos + los descubiertos que suenen a redirect
    candidatos = set(_PARAMS_REDIRECT)
    if crawl:
        for params in crawl.params.values():
            candidatos.update(p for p in params if p.lower() in {c.lower() for c in _PARAMS_REDIRECT})

    for param in list(candidatos)[:12]:
        r = fetch(dominio, f"/?{param}={urllib.parse.quote(destino)}")
        if r is None:
            continue
        location = r.header("location", "") or ""
        if location.startswith(destino) or location.startswith("//evil.example"):
            log.info("  [!!] Open redirect vía parámetro %s", param)
            findings.append(
                Finding(
                    "Open Redirect",
                    f"Posible open redirect (parámetro '{param}')",
                    Risk.MEDIO,
                    "El servidor redirige a un destino externo controlado por el atacante "
                    "(phishing, robo de tokens OAuth). Valide destinos contra una lista blanca.",
                    referencia=f"/?{param}=",
                    evidencia=location[:120],
                )
            )
            break
    return findings


# ── Fuzzing de rutas (diccionario corto) ──────────────────────
def analizar_fuzzing(dominio: str, *, max_workers: int = 10) -> list[Finding]:
    def probar(ruta: str) -> Finding | None:
        resp = fetch(dominio, ruta, max_body=2000)
        if resp and resp.status == 200:
            log.info("  [!] Ruta accesible: %s (200)", ruta)
            return Finding(
                "Fuzzing",
                f"Ruta accesible: {ruta}",
                Risk.BAJO,
                "La ruta responde 200. Verifique si debería estar expuesta o protegida.",
                referencia=f"{resp.esquema}://{dominio}{ruta}",
            )
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return [f for f in ex.map(probar, _RUTAS_FUZZ) if f is not None]
