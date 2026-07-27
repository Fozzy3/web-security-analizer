"""Módulo 3: Análisis TLS/HTTPS en profundidad.

Enumera versiones de protocolo soportadas (detecta SSLv3/TLS1.0/1.1),
prueba ciphers débiles, valida el certificado (expiración, CN/SAN, emisor) y
verifica la redirección HTTP→HTTPS. Todo mediante handshakes normales.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
import urllib.error
import urllib.request

from webvulnscanner.models import Finding, Risk
from webvulnscanner.net import TIMEOUT, USER_AGENT

log = logging.getLogger("webvulnscanner.tls")

# Versiones a sondear y su clasificación de seguridad.
_VERSIONES = [
    (ssl.TLSVersion.SSLv3, "SSLv3", Risk.ALTO, "Obsoleto y roto (POODLE). Deshabilítelo."),
    (ssl.TLSVersion.TLSv1, "TLSv1.0", Risk.ALTO, "Obsoleto (BEAST). PCI-DSS lo prohíbe."),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1", Risk.MEDIO, "Obsoleto. Deshabilítelo en favor de 1.2/1.3."),
    (ssl.TLSVersion.TLSv1_2, "TLSv1.2", Risk.OK, "Versión segura y ampliamente soportada."),
    (ssl.TLSVersion.TLSv1_3, "TLSv1.3", Risk.OK, "Versión más moderna y segura."),
]


def _probar_version(dominio: str, version: ssl.TLSVersion) -> str | None:
    """Fuerza una única versión TLS. Devuelve la versión negociada, None si el
    servidor la rechaza, o "" si el cliente local no puede ni ofrecerla."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return ""  # OpenSSL local ya no ofrece esta versión
    try:
        with socket.create_connection((dominio, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ss:
                return ss.version() or "desconocida"
    except (ssl.SSLError, OSError):
        return None


def _cipher_debil(dominio: str) -> str | None:
    """Intenta negociar un cipher débil (RC4/3DES/DES/EXPORT/NULL)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("RC4:3DES:DES:MD5:aNULL:eNULL:EXPORT")
    except ssl.SSLError:
        return None  # el cliente no tiene ciphers débiles compilados
    try:
        with socket.create_connection((dominio, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ss:
                return ss.cipher()[0]
    except (ssl.SSLError, OSError):
        return None


def _analizar_certificado(dominio: str) -> list[Finding]:
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((dominio, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ss:
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        log.info("  [!] Verificación de certificado falló: %s", e.verify_message)
        return [Finding(
            "TLS/HTTPS", f"Certificado no confiable: {e.verify_message}", Risk.ALTO,
            "El certificado no valida (expirado, autofirmado, o dominio distinto). "
            "Los navegadores mostrarán advertencia.",
            evidencia=str(e.verify_message),
        )]
    except (OSError, ssl.SSLError) as e:
        log.info("  [-] HTTPS no disponible: %s", e)
        return [Finding(
            "TLS/HTTPS", "HTTPS no disponible (443 cerrado o sin TLS)", Risk.ALTO,
            "Sin HTTPS, todo el tráfico viaja en claro y es vulnerable a MITM.",
        )]

    # Expiración
    not_after = cert.get("notAfter", "")
    if not_after:
        exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc)
        dias = (exp - datetime.datetime.now(datetime.timezone.utc)).days
        if dias < 0:
            nivel, desc = Risk.ALTO, "El certificado EXPIRÓ."
        elif dias < 30:
            nivel, desc = Risk.ALTO, f"Expira en {dias} días. Renueve con urgencia."
        elif dias < 90:
            nivel, desc = Risk.MEDIO, f"Expira en {dias} días. Planifique la renovación."
        else:
            nivel, desc = Risk.OK, f"Válido por {dias} días más."
        log.info("  [+] Certificado válido hasta %s (%d días)", exp.date(), dias)
        findings.append(Finding(
            "TLS/HTTPS", f"Certificado expira {exp.date()} ({dias} días)", nivel, desc,
            evidencia=not_after))

    # Sujeto / emisor / SAN
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    cn = subject.get("commonName", "—")
    ca = issuer.get("organizationName", issuer.get("commonName", "—"))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    log.info("  [+] CN=%s | CA=%s | SAN=%d nombres", cn, ca, len(sans))
    findings.append(Finding(
        "TLS/HTTPS", f"Certificado: CN={cn}, emisor={ca}", Risk.INFO,
        f"Emitido para '{cn}' por '{ca}'. Cubre {len(sans)} nombre(s) SAN.",
        evidencia=", ".join(sans[:10]) or cn))
    return findings


def _redireccion_https(dominio: str) -> Finding | None:
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    req = urllib.request.Request(f"http://{dominio}", headers={"User-Agent": USER_AGENT})
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        opener.open(req, timeout=TIMEOUT)
        log.info("  [!] HTTP no redirige a HTTPS")
        return Finding(
            "TLS/HTTPS", "HTTP no redirige a HTTPS", Risk.MEDIO,
            "Responde por HTTP sin forzar HTTPS: usuarios expuestos a sniffing/MITM.")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 307, 308) and (e.headers.get("Location", "").startswith("https://")):
            log.info("  [+] HTTP redirige a HTTPS")
            return Finding(
                "TLS/HTTPS", f"HTTP redirige a HTTPS ({e.code})", Risk.OK,
                "Redirige correctamente el tráfico HTTP a HTTPS.")
    except Exception:  # noqa: BLE001
        pass
    return None


def analizar(dominio: str) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Enumeración de versiones
    soportadas: list[str] = []
    for version, nombre, nivel, desc in _VERSIONES:
        res = _probar_version(dominio, version)
        if res == "":
            continue  # cliente no puede ofrecerla; no concluir nada
        if res is not None:
            soportadas.append(nombre)
            if nivel != Risk.OK:
                log.info("  [!] Protocolo débil aceptado: %s", nombre)
                findings.append(Finding(
                    "TLS/HTTPS", f"Protocolo obsoleto aceptado: {nombre}", nivel, desc,
                    evidencia=nombre))
    if soportadas:
        log.info("  [+] Versiones TLS soportadas: %s", ", ".join(soportadas))
        moderno = any(v in soportadas for v in ("TLSv1.2", "TLSv1.3"))
        findings.append(Finding(
            "TLS/HTTPS", f"Versiones TLS soportadas: {', '.join(soportadas)}",
            Risk.OK if moderno else Risk.ALTO,
            "Soporta TLS moderno." if moderno else "No soporta TLS 1.2/1.3: inseguro.",
            evidencia=", ".join(soportadas)))
    else:
        findings.append(Finding(
            "TLS/HTTPS", "No se pudo negociar ninguna versión TLS en el puerto 443",
            Risk.ALTO, "El servidor no ofrece HTTPS o el puerto 443 está cerrado."))
        return findings  # sin TLS no tiene sentido seguir

    # 2. Ciphers débiles
    debil = _cipher_debil(dominio)
    if debil:
        log.info("  [!] Cipher débil aceptado: %s", debil)
        findings.append(Finding(
            "TLS/HTTPS", f"Cipher débil aceptado: {debil}", Risk.ALTO,
            "El servidor acepta cifrado débil (RC4/3DES/EXPORT/NULL), vulnerable a "
            "ataques de descifrado. Configure solo suites fuertes (AEAD).",
            evidencia=debil))

    # 3. Certificado
    findings.extend(_analizar_certificado(dominio))

    # 4. Redirección
    redir = _redireccion_https(dominio)
    if redir:
        findings.append(redir)

    return findings
