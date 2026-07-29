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
import re
import time
import urllib.parse
from collections import namedtuple
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from webvulnscanner.crawler import Crawl
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import HttpResponse, fetch, request

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


# ── Inyección profunda (Fase M): query + form/POST, por-parámetro ──
#
# Payloads no destructivos: marcadores únicos, aritmética con resultado
# improbable, y confirmación por firma. Nada escribe ni borra en el objetivo.

_Punto = namedtuple("_Punto", "ruta param metodo extra")

_XSS = f'{_MARCADOR}"<x>'
_LFI_PAYLOAD = "../../../../../../etc/passwd"
_RE_LFI = re.compile(r"root:[^:]*:0:0:")
_SSTI_PAYLOAD = "{{113*131}}"  # 113*131 = 14803, resultado improbable por azar
_SSTI_RESULT = "14803"
_CMDI_PAYLOAD = ";expr 127 \\* 131"  # 127*131 = 16637
_CMDI_RESULT = "16637"
_CRLF_HEADER = "wvs-inject"
_CRLF_PAYLOAD = f"\r\n{_CRLF_HEADER}: {_MARCADOR}"  # urlencode lo vuelve %0D%0A
# Payloads de retardo para SQLi ciega (MySQL / PostgreSQL).
_SLEEP_PAYLOADS = ("1' AND SLEEP(3)-- -", "1); SELECT pg_sleep(3)-- -")
_SLEEP_SEG = 3
_UMBRAL_BLIND = 2.0  # margen sobre la latencia base para no confundir con jitter


def _confirma_lfi(body: str) -> bool:
    return bool(_RE_LFI.search(body or ""))


def _confirma_ssti(body: str) -> bool:
    """SSTI confirmada solo si la plantilla se EVALUÓ (resultado presente y el
    literal sin procesar ausente)."""
    b = body or ""
    return _SSTI_RESULT in b and "113*131" not in b


def _confirma_crlf(headers: dict[str, str]) -> bool:
    return _CRLF_HEADER in {k.lower() for k in (headers or {})}


def _es_retardo(base: float, t1: float, t2: float, *, umbral: float) -> bool:
    """Retardo consistente: ambas mediciones superan la base + umbral (evita
    falsos por jitter con una segunda confirmación)."""
    return (t1 - base) >= umbral and (t2 - base) >= umbral


# (nombre, payload, riesgo, confirmar(body, headers))
_Confirmar = Callable[[str, dict[str, str]], bool]
_REFLEJADAS: tuple[tuple[str, str, Risk, _Confirmar], ...] = (
    ("XSS reflejado", _XSS, Risk.ALTO, lambda b, h: _XSS in b),
    ("Path traversal (LFI)", _LFI_PAYLOAD, Risk.ALTO, lambda b, h: _confirma_lfi(b)),
    ("SSTI", _SSTI_PAYLOAD, Risk.ALTO, lambda b, h: _confirma_ssti(b)),
    ("Command injection", _CMDI_PAYLOAD, Risk.ALTO, lambda b, h: _CMDI_RESULT in b),
    ("CRLF injection", _CRLF_PAYLOAD, Risk.MEDIO, lambda b, h: _confirma_crlf(h)),
)


def _puntos_inyeccion(crawl: Crawl | None) -> list[_Punto]:
    """Puntos (ruta, parámetro, método, campos-extra) a probar: parámetros de
    query y campos de formularios descubiertos. Fallback genérico si no hay crawl."""
    puntos: list[_Punto] = []
    if crawl and crawl.params:
        for ruta, params in crawl.params.items():
            puntos.extend(_Punto(ruta or "/", p, "GET", {}) for p in params)
    if crawl and crawl.forms:
        for form in crawl.forms:
            metodo = "POST" if form.method.lower() == "post" else "GET"
            for campo in form.inputs:
                extra = {c: "1" for c in form.inputs if c != campo}
                puntos.append(_Punto(form.action or "/", campo, metodo, extra))
    if not puntos:
        puntos = [_Punto("/", p, "GET", {}) for p in ("q", "id", "search", "page")]
    return puntos[:40]  # cota de seguridad


def _enviar(dominio: str, punto: _Punto, payload: str) -> HttpResponse | None:
    """Envía el payload en el parámetro del punto, por su método real."""
    campos = {**punto.extra, punto.param: payload}
    if punto.metodo == "GET":
        return fetch(dominio, f"{punto.ruta}?{urllib.parse.urlencode(campos)}")
    return request(dominio, punto.ruta, method=punto.metodo, data=campos)


def _medir(dominio: str, punto: _Punto, payload: str) -> float | None:
    """Devuelve la latencia (s) de enviar el payload, o None si no responde."""
    t0 = time.monotonic()
    r = _enviar(dominio, punto, payload)
    return None if r is None else time.monotonic() - t0


def _finding(clase: str, punto: _Punto, riesgo: Risk, payload: str) -> Finding:
    return Finding(
        "Inyección",
        f"Posible {clase} en {punto.ruta} (parámetro '{punto.param}', {punto.metodo})",
        riesgo,
        f"El parámetro '{punto.param}' parece vulnerable a {clase} vía {punto.metodo}. "
        "Verifique la explotabilidad manualmente.",
        referencia=f"{punto.ruta}?{punto.param}=",
        evidencia=payload[:80],
    )


def analizar_inyeccion(dominio: str, crawl: Crawl | None = None) -> list[Finding]:
    """Prueba cada punto contra todas las clases de inyección, por-parámetro.

    No corta al primer hallazgo: reporta cada (ruta, parámetro, clase) una vez.
    """
    findings: list[Finding] = []
    reportado: set[tuple[str, str, str]] = set()

    for punto in _puntos_inyeccion(crawl):
        # Reflejadas (XSS/LFI/SSTI/cmdi/CRLF): una petición por clase.
        for clase, payload, riesgo, confirmar in _REFLEJADAS:
            clave = (punto.ruta, punto.param, clase)
            if clave in reportado:
                continue
            r = _enviar(dominio, punto, payload)
            if r is not None and confirmar(r.body, r.headers):
                log.info("  [!!] %s en %s (param %s, %s)", clase, punto.ruta, punto.param, punto.metodo)
                findings.append(_finding(clase, punto, riesgo, payload))
                reportado.add(clave)

        # SQLi basada en error.
        clave_sql = (punto.ruta, punto.param, "SQL injection")
        r = _enviar(dominio, punto, "1'")
        if r is not None and any(err in r.body.lower() for err in _ERRORES_SQL):
            log.info("  [!!] SQLi error-based en %s (param %s)", punto.ruta, punto.param)
            findings.append(_finding("SQL injection", punto, Risk.ALTO, "comilla '"))
            reportado.add(clave_sql)

        # SQLi ciega basada en tiempo (solo si no hay ya SQLi por error).
        if clave_sql not in reportado:
            _probar_sqli_ciega(dominio, punto, findings, reportado)

    return findings


def _probar_sqli_ciega(
    dominio: str, punto: _Punto, findings: list[Finding], reportado: set[tuple[str, str, str]]
) -> None:
    base = _medir(dominio, punto, "1")
    if base is None:
        return
    for payload in _SLEEP_PAYLOADS:
        t1 = _medir(dominio, punto, payload)
        if t1 is None or (t1 - base) < _UMBRAL_BLIND:
            continue
        t2 = _medir(dominio, punto, payload)  # segunda medición: confirma
        if t2 is not None and _es_retardo(base, t1, t2, umbral=_UMBRAL_BLIND):
            log.info("  [!!] SQLi ciega (time-based) en %s (param %s)", punto.ruta, punto.param)
            findings.append(_finding("SQL injection ciega (time-based)", punto, Risk.ALTO, payload))
            reportado.add((punto.ruta, punto.param, "SQL injection ciega (time-based)"))
            return


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
