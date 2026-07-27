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

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse, fetch

log = logging.getLogger("webvulnscanner.active")

_MARCADOR = "wvs9z7xq"  # improbable de aparecer por casualidad
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


# ── Inyección reflejada (XSS / SQLi error-based) ──────────────
def analizar_inyeccion(dominio: str) -> list[Finding]:
    findings: list[Finding] = []

    # XSS reflejado: marcador con caracteres crudos < > "
    payload = f'{_MARCADOR}"<x>'
    resp = fetch(dominio, f"/?q={urllib.parse.quote(payload)}")
    if resp and payload in resp.body:
        findings.append(
            Finding(
                "Inyección",
                "Posible XSS reflejado (parámetro sin sanear)",
                Risk.ALTO,
                'El parámetro se refleja en la respuesta sin codificar los caracteres < > ". '
                "Verifique manualmente la explotabilidad.",
                evidencia=payload,
            )
        )

    # SQLi error-based: una comilla y buscar errores de motor SQL
    resp2 = fetch(dominio, "/?id=1%27")
    if resp2 and any(err in resp2.body.lower() for err in _ERRORES_SQL):
        findings.append(
            Finding(
                "Inyección",
                "Posible SQL injection (error de motor expuesto)",
                Risk.ALTO,
                "Inyectar una comilla provoca un error SQL en la respuesta: el parámetro no está "
                "parametrizado. Verifique manualmente.",
                evidencia="comilla en ?id=",
            )
        )
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
