"""Genera el informe curado de 3 pestañas (HTML autocontenido) desde un ScanResult.

Reemplaza el informe hecho a mano: mismas pestañas (📋 Informe · 🗂️ Inteligencia ·
🔍 Qué revisa), pero data-driven, así cada escaneo produce el informe completo sin
edición manual. Tema claro/oscuro, responsive, pestañas en CSS puro (sin JS).
"""

from __future__ import annotations

import datetime
import html
import re

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

# Fuente de verdad de "Qué revisa": (nombre, resumen, detalle simple, referencia, activo?, categoria).
# Cubre los 40 módulos reales del orquestador (MODULOS + MODULOS_ACTIVOS), motores externos incluidos.
_MODULOS_INFO: tuple[tuple[str, str, str, str, bool, str], ...] = (
    # ── Pasivos · Reconocimiento y red ──────────────────────────────────────
    (
        "Reconocimiento",
        "Qué servidor y tecnología usa el sitio.",
        "Identifica la IP, el software del servidor web (Apache, nginx…) y su versión, tal como el "
        "propio sitio los anuncia. Conocer la versión exacta permite buscar fallos publicados de ese "
        "software; exponerla de más le ahorra trabajo a un atacante.",
        "Cabecera Server, DNS · A02:2025.",
        False,
        "Reconocimiento y red",
    ),
    (
        "Puertos + banners",
        "Qué puertas de red están abiertas.",
        "Prueba los puertos de red más comunes para ver cuáles están abiertos y qué servicio responde en "
        "cada uno (correo, base de datos, administración remota…). Cada puerto abierto de más es una "
        "puerta extra; los de administración expuestos a internet son especialmente peligrosos.",
        "Puertos TCP de riesgo.",
        False,
        "Reconocimiento y red",
    ),
    (
        "WAF / CDN",
        "Si hay un escudo delante del sitio.",
        "Detecta si un cortafuegos de aplicaciones (WAF) o una red de distribución (CDN) protege al "
        "servidor de origen. Si no hay ninguno, el servidor real queda directamente expuesto a ataques y "
        "a caídas por saturación.",
        "Firmas conocidas.",
        False,
        "Reconocimiento y red",
    ),
    (
        "Subdominios (CT)",
        "Subdominios públicos y olvidados.",
        "Busca en los registros públicos de certificados (Certificate Transparency) todos los subdominios "
        "del dominio y comprueba si alguno apunta a un servicio abandonado que un atacante podría reclamar "
        "(subdomain takeover). Un subdominio huérfano puede ser secuestrado para alojar contenido "
        "malicioso bajo tu marca.",
        "crt.sh · A01:2025.",
        False,
        "Reconocimiento y red",
    ),
    (
        "Subdominios (subfinder)",
        "Más subdominios, con un motor dedicado.",
        "Si <strong>subfinder</strong> está instalado, descubre subdominios usando decenas de fuentes "
        "públicas (mucho más que Certificate Transparency por sí solo). Cada subdominio encontrado es una "
        "superficie de ataque adicional que conviene revisar.",
        "subfinder (motor externo). Opcional.",
        False,
        "Reconocimiento y red",
    ),
    (
        "Shodan",
        "Lo que Shodan ya sabe del host.",
        "Consulta la base pública de <strong>Shodan</strong> (un buscador de dispositivos conectados a "
        "internet) para traer lo que ya se conoce del host desde afuera: puertos abiertos, servicios, "
        "banners y vulnerabilidades observadas. Da una vista externa sin tocar el objetivo. Requiere una "
        "clave de API de Shodan.",
        "Shodan API · A02:2025. Opcional.",
        False,
        "Reconocimiento y red",
    ),
    # ── Pasivos · Cifrado y correo ──────────────────────────────────────────
    (
        "TLS / HTTPS",
        "Si el candado (HTTPS) está bien configurado.",
        "Revisa la versión del cifrado, la fuerza y validez del certificado, cuándo vence y si el sitio "
        "obliga a usar HTTPS. Un cifrado viejo o un certificado por vencer permiten espiar o suplantar la "
        "conexión entre el usuario y el sitio.",
        "SSL Labs / PCI-DSS / RFC 8446 · A04:2025.",
        False,
        "Cifrado y correo",
    ),
    (
        "TLS profundo (sslyze)",
        "Fallos graves y conocidos del cifrado.",
        "Prueba a fondo vulnerabilidades históricas del cifrado como Heartbleed (fuga de memoria), ROBOT o "
        "CCS-injection, y detecta protocolos obsoletos que ya no son seguros. Estas fallas pueden permitir "
        "descifrar el tráfico o robar datos de la conexión.",
        "sslyze · A02:2025. Corre solo si sslyze está instalado.",
        False,
        "Cifrado y correo",
    ),
    (
        "TLS profundo (testssl)",
        "Auditoría TLS exhaustiva con testssl.sh.",
        "Si <strong>testssl.sh</strong> está instalado, hace una auditoría completa del cifrado: "
        "protocolos y suites soportadas, vulnerabilidades conocidas (Heartbleed, ROBOT, BEAST…), calidad "
        "del certificado y más. Complementa el análisis TLS propio con un motor especializado.",
        "testssl.sh (motor externo) · A04:2025. Opcional.",
        False,
        "Cifrado y correo",
    ),
    (
        "DNS y correo",
        "Registros del dominio y protección del correo.",
        "Revisa la configuración del dominio (SPF, DMARC, DKIM, DNSSEC, CAA) e intenta una transferencia "
        "de zona (AXFR). Sin SPF/DMARC/DKIM cualquiera puede enviar correos falsos en nombre del dominio "
        "(phishing); una transferencia de zona abierta filtra el mapa completo de la infraestructura.",
        "RFC 7208/7489/6376/8659.",
        False,
        "Cifrado y correo",
    ),
    (
        "Correo (MTA-STS / TLS-RPT)",
        "Cifrado obligatorio en el correo.",
        "Comprueba si el dominio obliga a que el correo entrante viaje cifrado (MTA-STS) y si recibe "
        "reportes de fallos (TLS-RPT). Sin esto, los correos pueden ser interceptados o forzados a viajar "
        "sin cifrar.",
        "RFC 8461 / 8460.",
        False,
        "Cifrado y correo",
    ),
    # ── Pasivos · Configuración y exposición ────────────────────────────────
    (
        "Cabeceras HTTP",
        "Las protecciones que el navegador debería recibir.",
        "Verifica las cabeceras de seguridad que el sitio envía al navegador (CSP, HSTS, X-Frame-Options…). "
        "Su ausencia deja el sitio expuesto a inyección de scripts (XSS), robo de sesión o a que lo "
        "incrusten en una web falsa (clickjacking).",
        "OWASP Secure Headers · A02:2025.",
        False,
        "Configuración y exposición",
    ),
    (
        "Exposición",
        "Archivos sensibles publicados sin querer.",
        "Busca archivos que no deberían ser públicos: repositorios .git, archivos .env con contraseñas, "
        "copias de seguridad, robots.txt y security.txt. Un .env o un .git expuesto puede regalar "
        "credenciales y el código fuente completo del sitio.",
        "RFC 9116 · A02:2025.",
        False,
        "Configuración y exposición",
    ),
    (
        "Contenido mixto / SRI / formularios",
        "Recursos inseguros dentro de una página segura.",
        "Detecta recursos cargados por HTTP dentro de una página HTTPS (contenido mixto), scripts externos "
        "sin verificación de integridad (SRI) y formularios que envían datos de forma insegura. Cualquiera "
        "de estos permite que un tercero altere o intercepte lo que ve o envía el usuario.",
        "W3C SRI · A02/A08:2025.",
        False,
        "Configuración y exposición",
    ),
    (
        "CSRF (pasivo)",
        "Formularios sin protección anti-falsificación.",
        "Revisa los formularios que hacen cambios (POST) para ver si llevan un token anti-CSRF. Sin él, un "
        "sitio malicioso puede hacer que la víctima, ya logueada, envíe acciones sin querer (cambiar su "
        "correo, transferir dinero, etc.).",
        "OWASP A01:2025 · CWE-352.",
        False,
        "Configuración y exposición",
    ),
    # ── Pasivos · Componentes y dependencias ────────────────────────────────
    (
        "Fingerprint",
        "Qué CMS, framework y librerías usa.",
        "Deduce las tecnologías del sitio (WordPress, Laravel, React, versión del servidor…) a partir del "
        "HTML, las cabeceras y pistas del código. Conocer la tecnología y su versión es el primer paso "
        "para buscar vulnerabilidades específicas de ella.",
        "HTML/headers/meta generator · A03:2025.",
        False,
        "Componentes y dependencias",
    ),
    (
        "Stack (Wappalyzer)",
        "Tecnologías con versión y sus CVEs.",
        "Identifica cientos de tecnologías con su versión exacta y las cruza contra la base de "
        "vulnerabilidades (NVD) para listar los CVEs conocidos de cada componente. Así se ven fallos no "
        "solo del servidor, sino de cada librería que el sitio usa.",
        "Wappalyzer → NVD · A03:2025. Corre solo si está instalado.",
        False,
        "Componentes y dependencias",
    ),
    (
        "Librerías JS (retire.js)",
        "Librerías JavaScript viejas y vulnerables.",
        "Compara las librerías JavaScript del sitio (jQuery, Angular…) contra una base de versiones "
        "vulnerables conocidas. Una librería desactualizada arrastra fallos ya públicos que un atacante "
        "puede explotar directamente en el navegador.",
        "Base retire.js · A03:2025.",
        False,
        "Componentes y dependencias",
    ),
    (
        "Supply chain / SBOM",
        "Inventario de componentes y dependencias sospechosas.",
        "Genera una lista completa de los componentes del sitio (un SBOM en formato CycloneDX) y marca "
        "dependencias con nombres que parecen internos y podrían ser suplantadas (dependency confusion). "
        "Sirve para saber exactamente qué se usa y detectar riesgos en la cadena de suministro.",
        "CycloneDX 1.5 · A03:2025.",
        False,
        "Componentes y dependencias",
    ),
    (
        "CVE (NVD) + por componente",
        "Vulnerabilidades públicas de cada componente.",
        "Cruza cada tecnología detectada (no solo el servidor) contra la base nacional de vulnerabilidades "
        "(NVD) y prioriza los CVEs según su probabilidad de ser explotados (EPSS) y si ya se explotan en "
        "el mundo real (lista CISA KEV). Así se atiende primero lo que de verdad es peligroso.",
        "NVD + EPSS + CISA KEV · A03:2025.",
        False,
        "Componentes y dependencias",
    ),
    # ── Pasivos · Aplicación y datos sensibles ──────────────────────────────
    (
        "WordPress (dirigido)",
        "Fugas típicas de sitios WordPress.",
        "En sitios WordPress revisa puntos conocidos: wp-json (que puede listar usuarios o filtrar la IP "
        "interna), xmlrpc (usado para fuerza bruta y amplificación), el archivo readme (revela la versión) "
        "y la página de login. Estas fugas ayudan a enumerar cuentas y a planear el ataque.",
        "Endpoints WordPress · A07/A05:2025.",
        False,
        "Aplicación y datos sensibles",
    ),
    (
        "Frameworks / CMS (dirigido)",
        "Puntos débiles de Drupal, Joomla, Laravel y paneles.",
        "Busca rutas y páginas conocidas de cada tecnología: el depurador Ignition de Laravel, paneles "
        "como phpMyAdmin, y endpoints de Drupal o Joomla. Un panel de administración o un depurador "
        "accesible puede entregar el control del sitio o de la base de datos.",
        "Endpoints por stack · A02/A05:2025.",
        False,
        "Aplicación y datos sensibles",
    ),
    (
        "Secretos",
        "Contraseñas o claves filtradas en el código.",
        "Busca en el HTML y el JavaScript claves de API, tokens y contraseñas dejadas por error, usando "
        "patrones conocidos y medición de aleatoriedad (entropía). Una clave filtrada puede dar acceso "
        "directo a servicios de pago, de nube o a bases de datos.",
        "Regex + detect-secrets · A04:2025.",
        False,
        "Aplicación y datos sensibles",
    ),
    (
        "JWT",
        "Tokens de sesión mal firmados.",
        "Analiza los tokens JWT que el sitio entrega al navegador para detectar firmas inseguras: "
        "algoritmo 'none' (sin firma), secreto débil de HS256 o falta de caducidad. Estos fallos permiten "
        "falsificar un token y hacerse pasar por cualquier usuario.",
        "RFC 7519 · A07:2025.",
        False,
        "Aplicación y datos sensibles",
    ),
    (
        "Superficie de API",
        "Documentación de API expuesta.",
        "Busca definiciones de API públicas (OpenAPI/Swagger) e introspección de GraphQL. Exponerlas "
        "revela todos los endpoints, parámetros y datos internos, entregándole a un atacante el mapa "
        "completo de la API.",
        "OWASP API Top 10 · API9:2023.",
        False,
        "Aplicación y datos sensibles",
    ),
    (
        "Cloud",
        "Almacenamiento en la nube abierto.",
        "Busca referencias a buckets de almacenamiento (S3, GCS, Azure) que estén públicos y a endpoints "
        "de metadata de la nube. Un bucket abierto puede exponer archivos privados; el acceso a metadata "
        "puede filtrar credenciales del servidor.",
        "A02:2025 / A01 (SSRF).",
        False,
        "Aplicación y datos sensibles",
    ),
    # ── Activos · Sesión y navegador ────────────────────────────────────────
    (
        "Cookies",
        "Si las cookies de sesión están protegidas.",
        "Revisa que las cookies lleven los indicadores Secure (viajan solo por HTTPS), HttpOnly (no "
        "accesibles por scripts) y SameSite (no se envían desde otros sitios). Sin ellos, una cookie de "
        "sesión puede ser robada o usada en un ataque CSRF.",
        "RFC 6265 · A02:2025.",
        True,
        "Sesión y navegador",
    ),
    (
        "CORS",
        "Permisos de acceso entre sitios demasiado abiertos.",
        "Comprueba si el sitio permite que cualquier otro dominio lea sus respuestas (CORS permisivo) o si "
        "refleja el origen sin validarlo. Una configuración abierta permite que una web maliciosa robe "
        "datos privados del usuario mientras está logueado.",
        "A02:2025 · CWE-942.",
        True,
        "Sesión y navegador",
    ),
    # ── Activos · Inyección y descubrimiento ────────────────────────────────
    (
        "Inyección",
        "XSS, SQLi y otras inyecciones de código.",
        "Envía cargas de prueba inofensivas para detectar si el sitio ejecuta la entrada del usuario: XSS "
        "(scripts en la página), SQLi (consultas a la base de datos), LFI (leer archivos del servidor), "
        "plantillas (SSTI) y comandos del sistema. Son de los fallos más graves: pueden robar datos, "
        "sesiones o tomar el control del servidor.",
        "A05:2025 · CWE-79/89/22/78/93.",
        True,
        "Inyección y descubrimiento",
    ),
    (
        "Open redirect",
        "Redirecciones que apuntan a sitios externos.",
        "Prueba si el sitio puede usarse para redirigir al usuario a un destino externo elegido por el "
        "atacante. Se usa en phishing: el enlace parece legítimo (tu dominio) pero termina en una web "
        "falsa.",
        "A01:2025 · CWE-601.",
        True,
        "Inyección y descubrimiento",
    ),
    (
        "Fuzzing de rutas",
        "Archivos y directorios ocultos.",
        "Prueba una lista de rutas y archivos comunes (paneles de administración, copias de seguridad, "
        ".git, configuraciones) para encontrar recursos que existen pero no están enlazados. Un archivo o "
        "panel oculto puede exponer datos o funciones sin protección.",
        "A02:2025 · CWE-538.",
        True,
        "Inyección y descubrimiento",
    ),
    (
        "SSRF / Host header",
        "Si al servidor se le puede engañar para pedir recursos internos.",
        "Prueba si se puede forzar al servidor a pedir recursos internos (SSRF, por ejemplo la metadata de "
        "la nube) y si respeta una cabecera Host falsificada. Un SSRF puede filtrar credenciales internas "
        "o alcanzar sistemas que no están expuestos a internet.",
        "A01:2025 · API7 · CWE-918.",
        True,
        "Inyección y descubrimiento",
    ),
    # ── Activos · Acceso y autenticación ────────────────────────────────────
    (
        "Control de acceso",
        "Si se puede ver datos o paneles ajenos.",
        "Prueba a cambiar identificadores en la URL para acceder a datos de otro usuario (IDOR/BOLA) y a "
        "entrar a paneles de administración sin estar logueado (forced browsing). Es el fallo n.º 1 de "
        "OWASP: permite ver o modificar información que no te corresponde.",
        "A01:2025 · API1/3/5.",
        True,
        "Acceso y autenticación",
    ),
    (
        "Autenticación",
        "Debilidades en el inicio de sesión.",
        "Comprueba si el login revela qué usuarios existen (enumeración), si acepta contraseñas por "
        "defecto, si no limita los intentos (fuerza bruta) y si la sesión no se renueva tras entrar "
        "(session fixation). Estas fallas facilitan tomar cuentas ajenas.",
        "A07:2025 · API2.",
        True,
        "Acceso y autenticación",
    ),
    # ── Activos · Abuso de recursos ─────────────────────────────────────────
    (
        "Manejo de errores",
        "Errores que filtran información interna.",
        "Provoca errores controlados para ver si el sitio muestra trazas de código (stack traces) o está "
        "en modo depuración en producción. Esos mensajes revelan rutas internas, versiones y a veces "
        "credenciales, útiles para preparar un ataque.",
        "A10:2025 (categoría nueva).",
        True,
        "Abuso de recursos",
    ),
    (
        "Rate limiting",
        "Si el sitio limita el volumen de peticiones.",
        "Envía una ráfaga controlada de peticiones para ver si el sitio las limita. Sin límite, un "
        "atacante puede abusar por fuerza bruta, saturar recursos o disparar costos (consumo no "
        "restringido de recursos).",
        "OWASP API4:2023.",
        True,
        "Abuso de recursos",
    ),
    (
        "Fuzzing de API (schemathesis)",
        "Respuestas de la API fuera de lo esperado.",
        "A partir de la definición de la API genera peticiones automáticas para encontrar errores de "
        "servidor (500) y respuestas que no cumplen su propio contrato. Esas grietas suelen esconder "
        "fallos de validación explotables.",
        "schemathesis · A08:2025. Corre solo si está instalado.",
        True,
        "Abuso de recursos",
    ),
    # ── Activos · Motores externos ──────────────────────────────────────────
    (
        "nuclei",
        "Miles de plantillas de fallos conocidos.",
        "Si <strong>nuclei</strong> está instalado, lanza su enorme colección de plantillas de la "
        "comunidad que detectan CVEs, exposiciones, configuraciones inseguras y paneles conocidos. Es uno "
        "de los motores más completos para hallazgos conocidos; corre solo con tu autorización.",
        "nuclei (motor externo). Opcional.",
        True,
        "Motores externos",
    ),
    (
        "nmap (scripts vuln)",
        "Puertos y scripts de vulnerabilidad.",
        "Si <strong>nmap</strong> está instalado, mapea puertos y corre sus scripts de detección de "
        "vulnerabilidades (--script vuln) contra los servicios encontrados. Aporta profundidad a nivel de "
        "red y de servicio.",
        "nmap NSE (motor externo). Opcional.",
        True,
        "Motores externos",
    ),
    (
        "WPScan",
        "Vulnerabilidades específicas de WordPress.",
        "Si <strong>WPScan</strong> está instalado, usa su base especializada para encontrar "
        "vulnerabilidades de WordPress, sus plugins y temas, y enumerar usuarios. Va mucho más a fondo que "
        "el chequeo propio de WordPress.",
        "WPScan (motor externo). Opcional.",
        True,
        "Motores externos",
    ),
)

# Orden de las categorías dentro de cada grupo (para la navegación).
_CATEGORIAS_PASIVAS = (
    "Reconocimiento y red",
    "Cifrado y correo",
    "Configuración y exposición",
    "Componentes y dependencias",
    "Aplicación y datos sensibles",
)
_CATEGORIAS_ACTIVAS = (
    "Sesión y navegador",
    "Inyección y descubrimiento",
    "Acceso y autenticación",
    "Abuso de recursos",
    "Motores externos",
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
.covgrid{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media (max-width:640px){.covgrid{grid-template-columns:1fr;gap:14px}}
.covhd{font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin:0 0 9px;font-weight:700}
.covhd-ok{color:var(--ok)}.covhd-skip{color:var(--warn)}
.covlist{list-style:none;margin:0;padding:0;font-size:13.5px}
.covlist li{position:relative;padding:6px 0 6px 20px;border-bottom:1px solid var(--line);color:var(--ink)}
.covlist.ok li::before{content:"✓";position:absolute;left:0;color:var(--ok);font-weight:700}
.covlist.no li::before{content:"—";position:absolute;left:0;color:var(--warn);font-weight:700}
.covlist.no li em{display:block;font-style:normal;font-size:11.5px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.covlist .cov-none{padding-left:0;color:var(--muted)}.covlist .cov-none::before{content:""}
.pendiente{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn);border-radius:12px;padding:12px 16px;margin:0 0 18px;font-size:14px}
.pendiente b{color:var(--warn)}
.proflist{list-style:none;margin:0;padding:0;font-size:14px}
.proflist li{position:relative;padding:9px 0 9px 26px;border-bottom:1px solid var(--line);color:var(--ink)}
.proflist li:last-child{border-bottom:0}
.proflist .prof-ic{position:absolute;left:0;top:9px}
.proflist .prof-n{font-weight:600}
.proflist li em{display:block;font-style:normal;font-size:12px;color:var(--muted);font-family:var(--mono);margin-top:2px;overflow-wrap:anywhere}
.proflist .prof-run .prof-ic,.proflist .prof-run .prof-n{color:var(--warn)}
.proflist .prof-skip .prof-ic{color:var(--muted)}
.proflist .prof-fail .prof-ic{color:var(--crit)}
.proflist .prof-ok .prof-ic{color:var(--ok)}
.kv dt{color:var(--muted);font-weight:600}.kv dd{margin:0;font-family:var(--mono);font-size:13px;overflow-wrap:break-word}
.modlist{display:flex;flex-direction:column;gap:8px;margin-bottom:6px}
.modindex{display:flex;flex-wrap:wrap;gap:7px;align-items:center;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin:6px 0 4px}
.modindex .idxlead{font-size:12.5px;color:var(--muted);font-weight:600;margin-right:2px}
.modindex .jump{font-size:12.5px;text-decoration:none;color:var(--accent-ink);background:var(--surface-2);border:1px solid var(--line);padding:3px 10px;border-radius:20px;transition:background .15s,color .15s}
.modindex .jump:hover{background:var(--accent);color:#fff;border-color:var(--accent)}
.modindex .jump-p{font-weight:650;color:var(--low)}.modindex .jump-a{font-weight:650;color:var(--crit)}
h4.subcat{display:flex;align-items:center;gap:8px;font-size:13px;letter-spacing:.02em;text-transform:uppercase;color:var(--muted);margin:18px 0 2px;scroll-margin-top:12px}
h4.subcat .subcount{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--accent-ink);background:var(--surface-2);border-radius:20px;padding:1px 8px;text-transform:none;letter-spacing:0}
.group[id]{scroll-margin-top:12px}
details.mod{border:1px solid var(--line);border-radius:11px;background:var(--surface);box-shadow:var(--shadow)}
details.mod summary{position:relative;list-style:none;cursor:pointer;padding:13px 42px 13px 16px;display:flex;align-items:baseline;gap:3px 11px;flex-wrap:wrap;user-select:none;border-radius:11px;transition:background .15s}
details.mod summary::-webkit-details-marker{display:none}
details.mod summary::after{content:"";position:absolute;right:18px;top:18px;width:7px;height:7px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .2s}
details.mod[open] summary::after{transform:rotate(225deg);top:21px}
details.mod summary:hover{background:var(--surface-2)}details.mod summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.mod-nombre{font-weight:650;color:var(--ink);font-size:14.5px}.mod-revisa{color:var(--muted);font-size:13.5px}
.mod-detalle{padding:13px 16px 15px;border-top:1px solid var(--line)}
.mod-detalle p{margin:0;max-width:72ch;font-size:14px;line-height:1.65;color:var(--ink)}
.mod-detalle strong{color:var(--accent-ink);font-weight:650}
.mod-detalle .mod-segun{margin-top:10px;font-size:12px;color:var(--muted);font-family:var(--mono);line-height:1.6}.mod-detalle .mod-segun b{font-family:var(--sans);color:var(--accent-ink)}
@media (prefers-reduced-motion:reduce){details.mod summary::after{transition:none}}
@media print{.tabnav,.modindex{display:none}.panel-view{display:block !important}.panel-view+.panel-view{margin-top:18px}details.mod{break-inside:avoid;box-shadow:none}details.mod>*:not(summary){display:block !important}details.mod summary::after{display:none}details.mod summary{cursor:default}}
.compliance{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}@media (max-width:620px){.compliance{grid-template-columns:1fr}}
.fw{border:1px solid var(--line);border-radius:10px;padding:14px 16px;background:var(--surface)}.fw h5{margin:0 0 8px;font-size:14px}.fw .ctrl{font-family:var(--mono);font-size:12px;color:var(--muted);line-height:1.9}
.mnote{font-size:13.5px;color:var(--muted);margin:8px 0 0}.mnote code{font-family:var(--mono);font-size:.9em;background:var(--surface-2);padding:1px 5px;border-radius:5px;color:var(--accent-ink)}.mnote em{font-style:normal;color:var(--ink);font-weight:600}
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


def _es_profundo(label: str) -> bool:
    """True si el módulo es una herramienta de análisis profundo (lenta/externa)."""
    return "externo" in label or "sslyze" in label or "schemathesis" in label


def _seccion_profundo(result: ScanResult) -> str:
    """Espacio dedicado a las herramientas lentas: 'en progreso' o su resultado."""
    filas = [(lbl, s) for lbl, s in result.estado_modulos.items() if _es_profundo(lbl)]
    if not filas:
        return ""

    def _clase(s: str) -> str:
        if s.startswith("en progreso"):
            return "run"
        if s.startswith("omitido"):
            return "skip"
        return "fail" if s == "falló" else "ok"

    _ICONO = {"run": "⏳", "skip": "✗", "fail": "⚠", "ok": "✓"}
    items = "".join(
        f'<li class="prof-{(c := _clase(s))}"><span class="prof-ic">{_ICONO[c]}</span>'
        f'<span class="prof-n">{_e(lbl)}</span><em>{_e(s)}</em></li>'
        for lbl, s in filas
    )
    pendiente = any(s.startswith("en progreso") for _, s in filas)
    nota = (
        "⏳ Estas herramientas tardan más; el informe se actualiza solo cuando terminan."
        if pendiente
        else "Resultados de las herramientas de análisis profundo (sus hallazgos ya están arriba por severidad)."
    )
    return (
        '<section><h2 class="sec">🔬 Análisis profundo (herramientas externas)</h2>'
        f'<div class="panel"><p class="mnote" style="margin:0 0 12px">{nota}</p>'
        f'<ul class="proflist">{items}</ul></div></section>'
    )


def _tab_informe(result: ScanResult, ts: str, pendiente: bool = False) -> str:
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

    banner = (
        '<div class="pendiente">⏳ <b>Análisis profundo en curso</b> (nuclei, testssl, nmap…). '
        "Este informe se actualizará automáticamente al terminar.</div>"
        if pendiente
        else ""
    )

    return f"""<div id="v-inf" class="panel-view">
  {banner}
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
  {_seccion_profundo(result)}
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
        f'escaneo (no vulnerabilidades):</p><dl class="kv">{"".join(kv)}</dl></div></section>'
        + _seccion_cobertura(result)
        + "</div>"
    )


def _seccion_cobertura(result: ScanResult) -> str:
    """Qué módulos analizaron el objetivo y cuáles no (con el motivo)."""
    estado = result.estado_modulos
    if not estado:
        return ""
    ok = [m for m, s in estado.items() if s == "analizado"]
    no = [(m, s) for m, s in estado.items() if s != "analizado"]
    items_ok = "".join(f"<li>{_e(m)}</li>" for m in ok) or '<li class="cov-none">—</li>'
    items_no = (
        "".join(f"<li>{_e(m)}<em>{_e(s)}</em></li>" for m, s in no)
        or '<li class="cov-none">Todos los módulos ejecutados analizaron el objetivo.</li>'
    )
    return (
        '<section><h2 class="sec">Cobertura del análisis</h2><div class="panel">'
        f'<p class="mnote" style="margin:0 0 14px">De <b>{len(estado)}</b> módulos ejecutados, '
        f"<b>{len(ok)}</b> analizaron el objetivo y <b>{len(no)}</b> no "
        "(dependencia externa ausente o error). Los omitidos se activan instalando su motor.</p>"
        '<div class="covgrid">'
        f'<div><h4 class="covhd covhd-ok">Analizaron · {len(ok)}</h4>'
        f'<ul class="covlist ok">{items_ok}</ul></div>'
        f'<div><h4 class="covhd covhd-skip">No analizaron · {len(no)}</h4>'
        f'<ul class="covlist no">{items_no}</ul></div>'
        "</div></div></section>"
    )


def _tab_modulos() -> str:
    def _card(n: str, rev: str, det: str, seg: str) -> str:
        return (
            f'<details class="mod"><summary>'
            f'<span class="mod-nombre">{_e(n)}</span>'
            f'<span class="mod-revisa">{_e(rev)}</span></summary>'
            f'<div class="mod-detalle"><p>{det}</p>'
            f'<p class="mod-segun"><b>Referencia:</b> {_e(seg)}</p></div></details>'
        )

    def _slug(txt: str) -> str:
        return "cat-" + re.sub(r"[^a-z0-9]+", "-", txt.lower()).strip("-")

    def _grupo(activo: bool, cats: tuple[str, ...]) -> tuple[str, str]:
        # Devuelve (html de sub-grupos, html de chips de índice) para un grupo.
        secciones, chips = [], []
        for cat in cats:
            items = [
                (n, rev, det, seg) for n, rev, det, seg, act, c in _MODULOS_INFO if act == activo and c == cat
            ]
            if not items:
                continue
            sid = _slug(cat)
            cards = "".join(_card(n, rev, det, seg) for n, rev, det, seg in items)
            secciones.append(
                f'<h4 class="subcat" id="{sid}">{_e(cat)}'
                f'<span class="subcount">{len(items)}</span></h4>'
                f'<div class="modlist">{cards}</div>'
            )
            chips.append(f'<a class="jump" href="#{sid}">{_e(cat)}</a>')
        return "".join(secciones), "".join(chips)

    pas = [m for m in _MODULOS_INFO if not m[4]]
    act = [m for m in _MODULOS_INFO if m[4]]
    pas_html, pas_chips = _grupo(False, _CATEGORIAS_PASIVAS)
    act_html, act_chips = _grupo(True, _CATEGORIAS_ACTIVAS)

    return f"""<div id="v-mod" class="panel-view">
  <section><h2 class="sec">Qué revisa la herramienta</h2>
  <div class="panel"><p class="mnote" style="margin:0">Esta herramienta audita la seguridad de un sitio
  web desde afuera — como lo haría un atacante — y explica cada hallazgo en términos de riesgo,
  clasificado por OWASP Top 10 2025, API Top 10 2023, CWE y CVSS. Cubre <b>{len(_MODULOS_INFO)} módulos</b>
  (motores externos incluidos). Tocá cualquiera para ver, en palabras simples, qué revisa y qué
  vulnerabilidad busca.</p></div></section>
  <nav class="modindex" aria-label="Índice de módulos">
    <span class="idxlead">Ir a:</span>
    <a class="jump jump-p" href="#g-pasivos">🔎 Pasivos ({len(pas)})</a>{pas_chips}
    <a class="jump jump-a" href="#g-activos">🎯 Activos ({len(act)})</a>{act_chips}
  </nav>
  <div class="group" id="g-pasivos"><span class="badge" style="background:var(--low-bg);color:var(--low)">Pasivos · {len(pas)}</span>
  <h3>🔎 Módulos pasivos</h3><span class="rule"></span></div>
  <p class="mnote">Solo observan lo que el sitio ya muestra en público. No envían ningún ataque:
  es totalmente seguro correrlos.</p>
  {pas_html}
  <div class="group" id="g-activos"><span class="badge" style="background:var(--crit-bg);color:var(--crit)">Escaneo activo · {len(act)}</span>
  <h3>🎯 Módulos activos</h3><span class="rule"></span></div>
  <p class="mnote">Envían peticiones de prueba (inofensivas) para <em>confirmar</em> un fallo. Corren
  siempre — la herramienta escanea con todo. Usá solo sobre objetivos propios o autorizados.</p>
  {act_html}
</div>"""


def generar(result: ScanResult, *, timestamp: str | None = None) -> str:
    """Devuelve el informe completo de 3 pestañas (HTML autocontenido).

    Si hay módulos "en progreso" (análisis profundo en 2ª fase), agrega un
    auto-refresh para que el informe abierto se actualice solo al terminar.
    """
    ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pendiente = any("en progreso" in s for s in result.estado_modulos.values())
    refresh = '<meta http-equiv="refresh" content="15">' if pendiente else ""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">{refresh}
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
  {_tab_informe(result, ts, pendiente)}
  {_tab_inteligencia(result)}
  {_tab_modulos()}
</div></body></html>"""
