"""Fase R: fallos de autenticación (A07:2025, API2). Activo, gateado.

Enumeración de usuarios (respuesta diferencial), credenciales por defecto del
producto y ausencia de rate-limit en el login. No destructivo: solo intentos de
autenticación sobre un formulario de login descubierto.
"""

from __future__ import annotations

import logging

from webvulnscanner.crawler import Crawl, Form
from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import request

log = logging.getLogger("webvulnscanner.auth")

_USER_HINTS = ("user", "email", "login", "correo", "usuario")
# Señales de login fallido (para NO confundirlas con éxito).
_FALLO = (
    "incorrect",
    "invalid",
    "inválid",
    "incorrecta",
    "no encontrado",
    "failed",
    "denied",
    "demasiados",
    "wrong",
    "error",
)
# Credenciales por defecto comunes (se prueban todas: pentest autorizado).
_DEFAULTS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("user", "user"),
)
_USUARIO_INEXISTENTE = "zzq_nouser_9137"
_PASS_FALLIDO = "wrongpass_zzz_9137"


def _form_login(crawl: Crawl | None) -> tuple[Form, str, str] | None:
    """Devuelve (form, campo_usuario, campo_password) del primer login, o None."""
    for form in crawl.forms if crawl else []:
        cp = next((i for i in form.inputs if "pass" in i.lower() or "pwd" in i.lower()), None)
        cu = next((i for i in form.inputs if any(h in i.lower() for h in _USER_HINTS)), None)
        if cp and cu:
            return form, cu, cp
    return None


def _es_exito_login(r) -> bool:
    """Heurística de login exitoso: redirección, o 2xx sin señales de fallo."""
    if r.status in (301, 302, 303, 307, 308):
        return True
    if 200 <= r.status < 300:
        return not any(k in r.body.lower() for k in _FALLO)
    return False


def _login(dominio: str, action: str, cu: str, cp: str, usuario: str, clave: str):
    return request(dominio, action, method="POST", data={cu: usuario, cp: clave})


def _enumeracion(dominio: str, action: str, cu: str, cp: str) -> Finding | None:
    r_ok = _login(dominio, action, cu, cp, "admin", _PASS_FALLIDO)
    r_no = _login(dominio, action, cu, cp, _USUARIO_INEXISTENTE, _PASS_FALLIDO)
    if r_ok and r_no and (r_ok.status != r_no.status or r_ok.body != r_no.body):
        log.info("  [!] Enumeración de usuarios: respuesta diferencial en el login")
        return Finding(
            "Autenticación",
            "Enumeración de usuarios (respuesta diferencial en login/recuperación)",
            Risk.MEDIO,
            "El sistema responde distinto ante un usuario existente vs. inexistente, revelando "
            "qué cuentas existen. Unifique el mensaje y el tiempo de respuesta.",
            owasp="A07:2021",
        )
    return None


def _default_creds(dominio: str, action: str, cu: str, cp: str) -> Finding | None:
    for usuario, clave in _DEFAULTS:
        r = _login(dominio, action, cu, cp, usuario, clave)
        if r and _es_exito_login(r):
            log.info("  [!!] Credenciales por defecto válidas: %s:%s", usuario, clave)
            return Finding(
                "Autenticación",
                "Credenciales por defecto válidas",
                Risk.ALTO,
                "Un panel autentica con credenciales por defecto conocidas. Cámbielas de inmediato.",
                evidencia=f"{usuario}:{clave or '(vacío)'}",
                owasp="A07:2021",
            )
    return None


def _session_id(r) -> str | None:
    """Par `nombre=valor` de la cookie del `Set-Cookie` de `r` (o None si no hay)."""
    cookie = r.header("set-cookie") if r else None
    if not cookie:
        return None
    par = cookie.split(";", 1)[0].strip()
    return par or None


def _session_fixation(dominio: str, action: str, cu: str, cp: str) -> Finding | None:
    """Reporta si el id de sesión NO rota tras un login exitoso (session fixation)."""
    sid_pre = _session_id(request(dominio, action, method="GET"))
    if sid_pre is None:
        return None  # sin cookie de sesión pre-login no hay nada que comparar
    for usuario, clave in _DEFAULTS:
        r = _login(dominio, action, cu, cp, usuario, clave)
        if r and _es_exito_login(r):
            if _session_id(r) == sid_pre:
                log.info("  [!] Posible session fixation: el id de sesión no rota tras autenticar")
                return Finding(
                    "Autenticación",
                    "Posible session fixation (el id de sesión no rota tras autenticarse)",
                    Risk.MEDIO,
                    "El identificador de sesión no cambia tras un login exitoso: un atacante que fije "
                    "una sesión conocida en la víctima la secuestra cuando esta se autentica. Regenere "
                    "el id de sesión al iniciar sesión y al elevar privilegios.",
                    evidencia=sid_pre,
                    owasp="A07:2021",
                )
            return None  # autenticó y el id rotó → sin fixation
    return None  # no logramos autenticar → no evaluable


def _rate_limit(dominio: str, action: str, cu: str, cp: str, *, intentos: int = 6) -> Finding | None:
    for i in range(intentos):
        r = _login(dominio, action, cu, cp, "probe", f"{_PASS_FALLIDO}{i}")
        if r and r.status == 429:
            return None  # hay throttling
    log.info("  [!] Sin rate-limit en el login (%d intentos sin bloqueo)", intentos)
    return Finding(
        "Autenticación",
        "Ausencia de rate-limit en el login",
        Risk.MEDIO,
        f"El login aceptó {intentos} intentos fallidos sin throttling ni bloqueo: habilita "
        "fuerza bruta y credential stuffing. Aplique rate-limit y bloqueo temporal.",
        owasp="A07:2021",
    )


def analizar(dominio: str, crawl: Crawl | None = None, producto: str | None = None) -> list[Finding]:
    login = _form_login(crawl)
    if login is None:
        return []
    form, cu, cp = login
    findings = [
        _enumeracion(dominio, form.action, cu, cp),
        _default_creds(dominio, form.action, cu, cp),
        _rate_limit(dominio, form.action, cu, cp),
        _session_fixation(dominio, form.action, cu, cp),
    ]
    return [f for f in findings if f is not None]
