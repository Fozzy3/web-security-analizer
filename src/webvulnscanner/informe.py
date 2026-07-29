"""Genera el informe curado de 3 pestañas (HTML autocontenido) desde un ScanResult.

Reemplaza el informe hecho a mano: mismas pestañas (📋 Informe · 🗂️ Inteligencia ·
🔍 Qué revisa), pero data-driven, así cada escaneo produce el informe completo sin
edición manual. Tema claro/oscuro, responsive, pestañas en CSS puro (sin JS).
"""

from __future__ import annotations

import datetime
import html

from webvulnscanner import compliance, scoring
from webvulnscanner.models import Finding, Risk, ScanResult

# Módulo → categoría OWASP/CWE ya viene en el Finding; aquí solo presentación.
_SEV_VAR = {
    Risk.ALTO: "crit",
    Risk.MEDIO: "warn",
    Risk.BAJO: "low",
    Risk.INFO: "info",
    Risk.OK: "ok",
}
_SEV_NOMBRE = {
    Risk.ALTO: "Crítico",
    Risk.MEDIO: "Moderado",
    Risk.BAJO: "Menor",
    Risk.INFO: "Info",
    Risk.OK: "Correcto",
}
_GRUPO_TITULO = {
    Risk.ALTO: ("🔴 Problemas críticos", "críticos"),
    Risk.MEDIO: ("🟡 Problemas moderados", "moderados"),
    Risk.BAJO: ("🟢 Observaciones de bajo impacto", "menores"),
    Risk.INFO: ("🔵 Información", "informativos"),
    Risk.OK: ("✅ Buenas prácticas confirmadas", "correctos"),
}

# Fuente de verdad de la pestaña "Qué revisa": (nombre, revisa, según, activo?).
_MODULOS_INFO: tuple[tuple[str, str, str, bool], ...] = (
    (
        "Reconocimiento",
        "IP, servidor, producto y versión expuestos.",
        "Cabecera Server, DNS · A02:2025.",
        False,
    ),
    ("Puertos + banners", "Puertos TCP comunes abiertos y su banner.", "Lista de puertos de riesgo.", False),
    (
        "TLS / HTTPS",
        "Versiones, cifrados, certificado y redirección a HTTPS.",
        "SSL Labs / PCI-DSS / RFC 8446 · A04.",
        False,
    ),
    (
        "TLS profundo (sslyze)",
        "Heartbleed, ROBOT, CCS-injection, protocolos obsoletos.",
        "sslyze · A02. Opcional.",
        False,
    ),
    ("Cabeceras HTTP", "CSP, HSTS, X-Frame-Options, etc.", "OWASP Secure Headers · A02:2025.", False),
    ("DNS y correo", "SPF, DMARC, DKIM, CAA, DNSSEC, AXFR.", "RFC 7208/7489/6376/8659.", False),
    ("Subdominios (CT)", "Subdominios en Certificate Transparency + takeover.", "crt.sh · A01:2025.", False),
    ("Exposición", ".git, .env, backups, robots.txt, security.txt.", "RFC 9116 · A02:2025.", False),
    ("WAF / CDN", "Cortafuegos o CDN que protege el origen.", "Firmas conocidas.", False),
    (
        "Fingerprint",
        "Tecnologías y versiones (CMS, framework, servidor).",
        "HTML/headers/meta generator · A03.",
        False,
    ),
    (
        "Stack (Wappalyzer)",
        "Cientos de tecnologías con versión + CVE por componente.",
        "Wappalyzer → NVD · A03. Opcional.",
        False,
    ),
    (
        "WordPress (dirigido)",
        "wp-json (usuarios/IP interna), xmlrpc, readme, wp-login.",
        "Endpoints WordPress · A07/A05.",
        False,
    ),
    (
        "Frameworks/CMS (dirigido)",
        "Drupal, Joomla, Laravel (Ignition), paneles (phpMyAdmin…).",
        "Endpoints por stack · A02/A05.",
        False,
    ),
    (
        "Contenido mixto / SRI",
        "Recursos HTTP en HTTPS, scripts sin integrity.",
        "W3C SRI · A02/A08:2025.",
        False,
    ),
    ("CSRF (pasivo)", "Formularios POST sin token anti-CSRF.", "OWASP A01:2025 · CWE-352.", False),
    ("Librerías JS (retire.js)", "Bibliotecas JavaScript vulnerables.", "Base retire.js · A03:2025.", False),
    (
        "Secretos",
        "Claves/tokens en HTML/JS (patrones + entropía).",
        "Regex + detect-secrets · A04:2025.",
        False,
    ),
    ("JWT", "alg:none, secreto HS256 débil, sin exp.", "RFC 7519 · A07:2025.", False),
    (
        "Superficie de API",
        "OpenAPI/Swagger expuesto + GraphQL introspection.",
        "OWASP API Top 10 (API9).",
        False,
    ),
    ("Cloud", "Buckets públicos y referencias a metadata.", "A05 / A01 (SSRF).", False),
    ("Correo (MTA-STS/TLS-RPT)", "Fuerza TLS en el correo y reporta fallos.", "RFC 8461 / 8460.", False),
    (
        "Supply chain / SBOM",
        "Inventario (CycloneDX) + dependency confusion.",
        "CycloneDX 1.5 · A03:2025.",
        False,
    ),
    (
        "CVE (NVD) + por componente",
        "CVEs de cada componente, no solo el servidor.",
        "NVD + EPSS + CISA KEV · A03.",
        False,
    ),
    ("Cookies", "Flags Secure, HttpOnly, SameSite.", "RFC 6265 · A02:2025.", True),
    ("CORS", "Configuración permisiva o reflejo de Origin.", "A05:2025 · CWE-942.", True),
    ("Inyección", "XSS, SQLi (error/ciega), LFI, SSTI, CRLF, cmdi.", "A05 · CWE-79/89/22/78/93.", True),
    ("Open redirect", "Redirecciones a destinos externos.", "A01:2025 · CWE-601.", True),
    ("Control de acceso", "IDOR/BOLA y forced browsing (paneles sin sesión).", "A01:2025 · API1/3/5.", True),
    ("Autenticación", "Enumeración, default creds, sin rate-limit en login.", "A07:2025 · API2.", True),
    ("SSRF / Host header", "SSRF a metadata + Host Header Injection.", "A01 · API7 · CWE-918.", True),
    ("Manejo de errores", "Stack traces y modo debug en producción.", "A10:2025 (nueva).", True),
    ("Rate limiting", "Ausencia de límite de peticiones.", "OWASP API4.", True),
    (
        "Fuzzing de API (schemathesis)",
        "Errores 5xx y respuestas fuera de contrato.",
        "schemathesis · A08. Opcional.",
        True,
    ),
    (
        "Herramientas externas",
        "Delega a nuclei, nmap, WPScan, subfinder, testssl.",
        "Sus propias bases.",
        True,
    ),
)

_CSS = """
:root{--bg:#f4f7f9;--surface:#fff;--surface-2:#eef2f6;--ink:#14202b;--muted:#566573;--line:#dce3ea;
--accent:#0f6d7a;--accent-ink:#0a4e58;--crit:#c1354a;--warn:#cf7616;--low:#3a7ca5;--info:#6b7a8a;--ok:#2f9269;
--crit-bg:#fbeef0;--warn-bg:#fbf2e6;--low-bg:#ecf3f8;--info-bg:#eef1f4;--ok-bg:#eaf5ef;
--shadow:0 1px 2px rgba(20,32,43,.04),0 6px 20px rgba(20,32,43,.06);
--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
@media (prefers-color-scheme: dark){:root{--bg:#0d141b;--surface:#141d26;--surface-2:#1c2832;--ink:#e7eef4;
--muted:#94a4b3;--line:#263642;--accent:#37a6b6;--accent-ink:#7fd0dc;--crit:#e8677c;--warn:#e2953f;--low:#63a7d0;
--info:#8a99a8;--ok:#4bbd8a;--crit-bg:#2a1519;--warn-bg:#271c10;--low-bg:#12212c;--info-bg:#1a232c;--ok-bg:#10241b;
--shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.35);}}
:root[data-theme=light]{--bg:#f4f7f9;--surface:#fff;--ink:#14202b;--muted:#566573;--line:#dce3ea;--accent:#0f6d7a;--accent-ink:#0a4e58;}
:root[data-theme=dark]{--bg:#0d141b;--surface:#141d26;--surface-2:#1c2832;--ink:#e7eef4;--muted:#94a4b3;--line:#263642;--accent:#37a6b6;--accent-ink:#7fd0dc;--crit:#e8677c;--warn:#e2953f;--low:#63a7d0;--info:#8a99a8;--ok:#4bbd8a;--crit-bg:#2a1519;--warn-bg:#271c10;--low-bg:#12212c;--info-bg:#1a232c;--ok-bg:#10241b;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:940px;margin:0 auto;padding:32px 20px 80px}a{color:var(--accent);overflow-wrap:break-word}
.tabnav{display:flex;gap:4px;margin-bottom:22px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tabnav label{padding:11px 18px;cursor:pointer;font-weight:600;font-size:14.5px;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px;user-select:none}
.tabnav label:hover{color:var(--ink)}input.tabsel{position:absolute;width:1px;height:1px;opacity:0}.panel-view{display:none}
#t-inf:checked~.tabnav label[for=t-inf],#t-int:checked~.tabnav label[for=t-int],#t-mod:checked~.tabnav label[for=t-mod]{color:var(--accent-ink);border-bottom-color:var(--accent)}
#t-inf:checked~#v-inf,#t-int:checked~#v-int,#t-mod:checked~#v-mod{display:block}
.masthead{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:26px 26px 22px;box-shadow:var(--shadow);margin-bottom:20px}
.eyebrow{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent-ink);font-weight:650;margin:0 0 8px}
h1{font-size:clamp(22px,4vw,30px);margin:0 0 4px;letter-spacing:-.01em;overflow-wrap:break-word}.sub{color:var(--muted);font-size:14.5px;margin:0 0 16px}
.head-grid{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center}@media (max-width:620px){.head-grid{grid-template-columns:1fr}}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;font-size:13.5px}.meta div{display:flex;flex-direction:column}
.meta .k{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}.meta .v{font-family:var(--mono);font-size:13px}
.grade{display:flex;flex-direction:column;align-items:center;justify-content:center;width:112px;height:112px;border-radius:50%;flex-shrink:0}
.grade .letter{font-size:44px;font-weight:800;line-height:1}.grade .score{font-size:12px;font-family:var(--mono)}
.sevbar{display:flex;height:12px;border-radius:8px;overflow:hidden;margin:18px 0 12px;border:1px solid var(--line)}
.counts{display:flex;flex-wrap:wrap;gap:8px 16px;font-size:13px}.count{display:inline-flex;align-items:center;gap:7px}
.dot{width:10px;height:10px;border-radius:3px}.num{font-family:var(--mono);font-weight:650}
section{margin-top:26px}h2.sec{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line);font-weight:650}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px 20px;box-shadow:var(--shadow)}
.group{display:flex;align-items:center;gap:12px;margin:30px 0 4px}.group h3{font-size:18px;margin:0}.group .badge{font-family:var(--mono);font-size:12px;padding:2px 9px;border-radius:20px;font-weight:650}.group .rule{flex:1;height:1px;background:var(--line)}
.find{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px 16px 20px;margin-top:12px;box-shadow:var(--shadow);overflow:hidden}
.find::before{content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--sev,var(--info))}
.find .row{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:6px}
.pill{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:6px;color:#fff}
.tag{font-size:11.5px;padding:2px 8px;border-radius:6px;background:var(--surface-2);border:1px solid var(--line);color:var(--muted);font-family:var(--mono)}
.find h4{font-size:16px;margin:2px 0 8px;letter-spacing:-.005em}.simple{font-size:14.5px}
.tech{margin-top:12px;border-top:1px dashed var(--line);padding-top:11px}
.tech summary{cursor:pointer;font-size:12.5px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:650;list-style:none}
.tech summary::-webkit-details-marker{display:none}.tech summary::before{content:"▸ ";color:var(--accent)}.tech[open] summary::before{content:"▾ "}
.tech .data{margin-top:10px;display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-family:var(--mono);font-size:12.5px}
.tech .data dt{color:var(--muted)}.tech .data dd{margin:0;overflow-wrap:break-word}
.kv{display:grid;grid-template-columns:auto 1fr;gap:7px 18px;font-size:14px;align-items:baseline}@media (max-width:520px){.kv{grid-template-columns:1fr;gap:2px 0}.kv dt{margin-top:8px}}
.kv dt{color:var(--muted);font-weight:600}.kv dd{margin:0;font-family:var(--mono);font-size:13px;overflow-wrap:break-word}
.modgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media (max-width:640px){.modgrid{grid-template-columns:1fr}}
.modcard{border:1px solid var(--line);border-radius:12px;padding:14px 16px;background:var(--surface);box-shadow:var(--shadow)}
.modcard h4{margin:0 0 7px;font-size:15px}.modcard .revisa{font-size:14px}.modcard .segun{margin-top:8px;font-size:12px;color:var(--muted);font-family:var(--mono);line-height:1.7}.modcard .segun b{color:var(--accent-ink);font-family:var(--sans)}
.compliance{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}@media (max-width:620px){.compliance{grid-template-columns:1fr}}
.fw{border:1px solid var(--line);border-radius:10px;padding:14px 16px;background:var(--surface)}.fw h5{margin:0 0 8px;font-size:14px}.fw .ctrl{font-family:var(--mono);font-size:12px;color:var(--muted);line-height:1.9}
.mnote{font-size:13.5px;color:var(--muted);margin:8px 0 0}
footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted)}
"""


def _e(s: object) -> str:
    return html.escape(str(s)) if s is not None else ""


def _card(f: Finding) -> str:
    var = _SEV_VAR[f.riesgo]
    tags = [f'<span class="tag">{_e(f.modulo)}</span>']
    if f.owasp:
        tags.append(f'<span class="tag">OWASP {_e(f.owasp)}</span>')
    if f.api:
        tags.append(f'<span class="tag">{_e(f.api)}</span>')
    datos = []
    if f.owasp:
        datos.append(f"<dt>OWASP</dt><dd>{_e(f.owasp)}</dd>")
    if f.api:
        datos.append(f"<dt>API Top 10</dt><dd>{_e(f.api)}</dd>")
    if f.cwe:
        datos.append(f"<dt>CWE</dt><dd>{_e(f.cwe)}</dd>")
    if f.cvss:
        datos.append(f"<dt>CVSS</dt><dd>{_e(f.cvss.get('score'))}</dd>")
    if f.evidencia:
        datos.append(f"<dt>Evidencia</dt><dd>{_e(f.evidencia)}</dd>")
    if f.referencia:
        ref = _e(f.referencia)
        dd = f'<a href="{ref}">{ref}</a>' if f.referencia.startswith("http") else ref
        datos.append(f"<dt>Referencia</dt><dd>{dd}</dd>")
    tech = ""
    if datos:
        tech = (
            '<details class="tech"><summary>Detalle técnico</summary>'
            f'<dl class="data">{"".join(datos)}</dl></details>'
        )
    return (
        f'<article class="find" style="--sev:var(--{var})">'
        f'<div class="row"><span class="pill" style="background:var(--{var})">{_SEV_NOMBRE[f.riesgo]}</span>'
        f"{''.join(tags)}</div>"
        f"<h4>{_e(f.hallazgo)}</h4>"
        f'<div class="simple">{_e(f.descripcion)}</div>{tech}</article>'
    )


def _tab_informe(result: ScanResult, ts: str) -> str:
    conteo = result.conteo()
    por = result.por_riesgo()
    total = sum(conteo.values())
    ltr, pts = scoring.calcular(result)
    gvar = "crit" if ltr in ("F", "E", "D") else ("warn" if ltr == "C" else "ok")

    segs, cuentas = [], []
    for r in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO, Risk.OK):
        n = conteo[r]
        pct = round(100 * n / total) if total else 0
        segs.append(f'<span style="width:{pct}%;background:var(--{_SEV_VAR[r]})"></span>')
        cuentas.append(
            f'<span class="count"><span class="dot" style="background:var(--{_SEV_VAR[r]})"></span> '
            f'<span class="num">{n}</span> {_SEV_NOMBRE[r]}s</span>'
        )

    grupos = []
    for r in (Risk.ALTO, Risk.MEDIO, Risk.BAJO, Risk.INFO, Risk.OK):
        items = por[r]
        if not items:
            continue
        titulo, sing = _GRUPO_TITULO[r]
        grupos.append(
            f'<div class="group"><span class="badge" style="background:var(--{_SEV_VAR[r]}-bg);'
            f'color:var(--{_SEV_VAR[r]})">{len(items)} {sing}</span><h3>{titulo}</h3><span class="rule"></span></div>'
            + "".join(_card(f) for f in items)
        )

    return f"""<div id="v-inf" class="panel-view">
  <header class="masthead">
    <div class="head-grid"><div>
      <p class="eyebrow">Informe de auditoría de seguridad web · WebVulnScanner 2.0</p>
      <h1>{_e(result.dominio)}</h1>
      <p class="sub">Análisis completo (pasivo + activo) · {ts}</p>
      <div class="meta">
        <div><span class="k">IP</span><span class="v">{_e(result.ip) or "N/A"}</span></div>
        <div><span class="k">Servidor</span><span class="v">{_e(result.servidor) or "N/A"}</span></div>
        <div><span class="k">Hallazgos</span><span class="v">{total}</span></div>
      </div></div>
      <div class="grade" style="background:var(--{gvar}-bg);border:3px solid var(--{gvar});color:var(--{gvar})">
        <span class="letter">{ltr}</span><span class="score">{pts}/100</span></div>
    </div>
    <div class="sevbar">{"".join(segs)}</div>
    <div class="counts">{"".join(cuentas)}</div>
  </header>
  {"".join(grupos)}
  {_seccion_compliance(result.findings)}
  <footer>
    <p><strong>Metodología.</strong> Análisis completo con WebVulnScanner 2.0 (módulos pasivos y activos,
    con autorización). Categorización OWASP Top 10 2025 · CWE · CVSS v3.1. Las correlaciones de CVE por
    versión y los forced-browsing deben validarse manualmente.</p>
    <p>⚖️ Uso académico y ético. Solo analice sitios propios o con autorización expresa.</p>
  </footer>
</div>"""


def _seccion_compliance(findings: list[Finding]) -> str:
    resumen = compliance.resumen(findings)
    if not resumen:
        return ""
    cols = []
    for marco in sorted(resumen):
        ctrl = ", ".join(f"{c} ({n})" for c, n in sorted(resumen[marco].items()))
        cols.append(f'<div class="fw"><h5>{_e(marco)}</h5><div class="ctrl">{_e(ctrl)}</div></div>')
    return (
        '<section><h2 class="sec">Controles de cumplimiento afectados</h2>'
        f'<div class="panel"><div class="compliance">{"".join(cols)}</div></div></section>'
    )


def _tab_inteligencia(result: ScanResult) -> str:
    def _ev(modulos: tuple[str, ...]) -> list[str]:
        return [
            f"{f.hallazgo}: {f.evidencia}" for f in result.findings if f.modulo in modulos and f.evidencia
        ]

    techs = [f.evidencia for f in result.findings if f.modulo in ("Fingerprint", "Stack") and f.evidencia]
    kv = [
        f"<dt>Dominio</dt><dd>{_e(result.dominio)}</dd>",
        f"<dt>IP</dt><dd>{_e(result.ip) or 'N/A'}</dd>",
        f"<dt>Servidor</dt><dd>{_e(result.servidor) or 'N/A'}</dd>",
    ]
    if techs:
        kv.append(f"<dt>Tecnologías</dt><dd>{_e(' · '.join(techs))}</dd>")
    cert = _ev(("TLS/HTTPS",))
    cert_line = next((c for c in cert if "Certificado" in c), "")
    if cert_line:
        kv.append(f"<dt>Certificado</dt><dd>{_e(cert_line[:300])}</dd>")
    for etq, mods in (("WordPress", ("WordPress",)), ("DNS/correo", ("DNS", "MTA-STS", "TLS-RPT"))):
        vals = _ev(mods)
        if vals:
            kv.append(f"<dt>{etq}</dt><dd>{_e(' · '.join(v[:120] for v in vals[:4]))}</dd>")
    return (
        '<div id="v-int" class="panel-view"><section><h2 class="sec">Inteligencia recopilada</h2>'
        '<div class="panel"><p class="mnote" style="margin:0 0 12px">Información de valor extraída del '
        f'escaneo (no vulnerabilidades):</p><dl class="kv">{"".join(kv)}</dl></div></section></div>'
    )


def _tab_modulos() -> str:
    def _cards(activo: bool) -> str:
        return "".join(
            f'<div class="modcard"><h4>{_e(n)}</h4><div class="revisa">{_e(rev)}</div>'
            f'<div class="segun"><b>Según:</b> {_e(seg)}</div></div>'
            for n, rev, seg, act in _MODULOS_INFO
            if act == activo
        )

    return f"""<div id="v-mod" class="panel-view">
  <section><h2 class="sec">Qué revisa la herramienta</h2>
  <div class="panel"><p class="mnote" style="margin:0">Auditor de seguridad web que clasifica cada hallazgo
  según OWASP Top 10 2025, CWE y CVSS v3.1, y prioriza CVEs con EPSS y CISA KEV.</p></div></section>
  <div class="group"><span class="badge" style="background:var(--low-bg);color:var(--low)">Pasivos</span>
  <h3>🔎 Módulos pasivos</h3><span class="rule"></span></div>
  <div class="modgrid">{_cards(False)}</div>
  <div class="group"><span class="badge" style="background:var(--crit-bg);color:var(--crit)">Requiere autorización</span>
  <h3>🎯 Módulos activos</h3><span class="rule"></span></div>
  <div class="modgrid">{_cards(True)}</div>
</div>"""


def generar(result: ScanResult, *, timestamp: str | None = None) -> str:
    """Devuelve el informe completo de 3 pestañas (HTML autocontenido)."""
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad — {_e(result.dominio)}</title><style>{_CSS}</style></head><body>
<div class="wrap">
  <input class="tabsel" type="radio" name="tab" id="t-inf" checked>
  <input class="tabsel" type="radio" name="tab" id="t-int">
  <input class="tabsel" type="radio" name="tab" id="t-mod">
  <nav class="tabnav">
    <label for="t-inf" tabindex="0">📋 Informe</label>
    <label for="t-int" tabindex="0">🗂️ Inteligencia</label>
    <label for="t-mod" tabindex="0">🔍 Qué revisa la herramienta</label>
  </nav>
  {_tab_informe(result, ts)}
  {_tab_inteligencia(result)}
  {_tab_modulos()}
</div></body></html>"""
