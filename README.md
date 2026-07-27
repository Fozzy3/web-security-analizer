# WebVulnScanner 2.0 — Auditoría de Seguridad Web

**Materia:** Redes de Computadores · **Autor:** fozzy3
**Enfoque:** Ético y académico. Pasivo por defecto; el modo activo exige autorización explícita.

Auditor de la superficie de seguridad *externa* de un dominio. Clasifica cada hallazgo por riesgo
(🔴 Alto / 🟡 Medio / 🟢 Bajo / 🔵 Info / ✅ Buenas prácticas), calcula una **nota A–F** y exporta el
reporte en **TXT, JSON, HTML y SARIF**.

---

## Capacidades

### Módulos pasivos (por defecto — no envían payloads al objetivo)

| Módulo | Qué analiza |
|--------|-------------|
| **Reconocimiento** | DNS A/AAAA (IPv4+IPv6), cabeceras `Server`/`X-Powered-By`, producto+versión |
| **Puertos + banners** | TCP connect scan a 17 puertos + *banner grabbing* de versión |
| **TLS/HTTPS** | Enumera versiones (detecta SSLv3/TLS 1.0/1.1), **ciphers débiles**, validez/CN/SAN, **fuerza de clave** (RSA<2048, firma SHA-1), redirección HTTP→HTTPS |
| **Headers HTTP** | Evalúa el **valor** de CSP (unsafe-inline, wildcards) y HSTS (max-age, includeSubDomains) |
| **DNS y correo** | MX, **SPF/DMARC/DKIM/BIMI**, **CAA**, **DNSSEC** y prueba de **transferencia de zona (AXFR)** |
| **Subdominios** | Enumeración vía **Certificate Transparency** (crt.sh) + detección de **subdomain takeover** (CNAME colgante) |
| **Exposición** | `.git/`, `.env`, backups, `robots.txt`, `security.txt` |
| **WAF/CDN** | Cloudflare, Akamai, Sucuri, Fastly, Vercel… |
| **Fingerprint** | CMS/frameworks (WordPress, Drupal, Laravel, Django…) |
| **CVEs (NVD)** | Correlación **por CPE** del producto+versión (elimina falsos positivos del keyword search) |
| **Shodan** *(opcional)* | Inteligencia de la IP vía Shodan (requiere `SHODAN_API_KEY`) |

### Módulos activos (`--authorized` — envían peticiones al objetivo)

> ⚠️ **Solo en objetivos propios o con autorización expresa.** Sin el flag `--authorized` ni siquiera se cargan.

| Módulo | Qué prueba |
|--------|-----------|
| **Cookies** | Flags `Secure`, `HttpOnly`, `SameSite` |
| **CORS** | Reflexión de `Origin` arbitrario y `Allow-Credentials` |
| **Inyección** | XSS reflejado (marcador) y SQLi error-based (comilla) |
| **Fuzzing** | Rutas comunes por diccionario (concurrente) |

---

## Instalación

Requiere **Python 3.10+**.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .            # núcleo (CLI): dnspython + cryptography
pip install -e ".[gui]"     # + interfaz gráfica (customtkinter)
pip install -e ".[api]"     # + API REST (FastAPI + uvicorn)
pip install -e ".[dev]"     # + pytest, ruff, mypy

# o todo de una:
make dev
```

---

## Uso

### CLI

```bash
webvulnscanner example.com                 # escaneo pasivo completo → TXT/JSON/HTML
webvulnscanner example.com --profile quick # perfil rápido (recon, tls, headers, waf, fingerprint)
webvulnscanner example.com --only tls,dns  # solo ciertos módulos
webvulnscanner example.com --sarif         # además exporta .sarif (CI/GitHub Security)
webvulnscanner example.com --diff prev.json  # regresiones vs. un reporte anterior
webvulnscanner miweb.com   --authorized    # habilita módulos ACTIVOS (con autorización)
webvulnscanner example.com -o reportes/ -q # carpeta de salida, sin log de progreso
```

Perfiles disponibles: `full` (def), `quick`, `tls`, `web`, `dns`.
Devuelve **código de salida 2** si hay hallazgos de riesgo alto (útil para CI).

### Interfaz gráfica

```bash
python gui.py
```

### API REST

```bash
uvicorn webvulnscanner.api:app --reload     # o: make api
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
     -d '{"dominio": "example.com", "activos": ["recon","tls","headers"]}'
```

El modo activo **no** se expone por HTTP a propósito (la autorización es por objetivo).

### Docker

```bash
make docker                                 # construye webvulnscanner:2.0
docker run --rm -v "$PWD/reportes:/reports" webvulnscanner:2.0 example.com
```

---

## Sitios de prueba autorizados

| Sitio | Descripción |
|-------|-------------|
| `scanme.nmap.org` | Nmap — autorizado explícitamente para escaneos |
| `testphp.vulnweb.com` | Acunetix — PHP vulnerable de prueba |
| `example.com` | IANA — dominio de referencia |

⚠️ **NUNCA** use esta herramienta —y menos el modo activo— en sitios sin autorización explícita.

---

## Arquitectura

```
src/webvulnscanner/
├── models.py         # Núcleo puro: Finding, Risk, ScanResult (sin red ni UI)
├── net.py            # Utilidades HTTP/socket compartidas
├── cache.py          # Caché en disco con TTL (crt.sh, NVD, Shodan)
├── scoring.py        # Nota A–F ponderada
├── orchestrator.py   # Coordina módulos en paralelo, aísla fallos, gatea lo activo
├── report.py         # Render TXT/JSON (puro) + guardado (único I/O)
├── html.py           # Reporte HTML autocontenido (escapa contenido remoto)
├── sarif.py          # Export SARIF 2.1.0
├── diff.py           # Comparación entre escaneos
├── cli.py / api.py   # Entradas de consola y REST
└── modules/          # Un módulo por capacidad (10 pasivos + 4 activos + shodan)
gui.py                # Interfaz (customtkinter), habla con el núcleo vía logging
tests/                # 59 tests (lógica pura, orquestador, red simulada)
```

**Decisiones de diseño:**
- **Concurrencia**: los módulos independientes corren en paralelo (escaneo ~6× más rápido).
- **Sin acoplamiento por `print`**: progreso vía `logging`; CLI, GUI y API enganchan sus handlers.
- **Render puro separado de I/O**: `render_*` son funciones sin efectos → testeables sin filesystem/red.
- **Fallo aislado por módulo**: si uno revienta, el escaneo continúa y lo reporta.
- **Caché que no se envenena**: los fallos de red no se persisten (no bloquean el TTL).
- **Modo activo estrictamente gateado**: `autorizado=True` es la única vía de cargarlo.

### Calidad

```bash
make check      # ruff (lint+format) + mypy (tipado) + pytest
make cov        # cobertura
```

CI en GitHub Actions corre lint, tipos y tests sobre Python 3.10–3.12 en cada push.

---

## Ética y alcance

El núcleo es **pasivo**: peticiones HTTP normales, handshakes TLS y consultas a fuentes públicas
(crt.sh, NVD, Shodan). El **modo activo** (`--authorized`) envía peticiones elaboradas (payloads no
destructivos) y **solo** debe usarse sobre objetivos propios o con permiso expreso.

## Limitaciones / trabajo futuro

- El modo activo es de superficie (parámetros a nivel raíz); un **crawler** para descubrir parámetros
  y formularios sería el siguiente incremento.
- No se detectan Heartbleed/ROBOT (requieren manipulación TLS de bajo nivel).
- Diccionario de fuzzing corto (10 rutas); ampliable.
- Posibles extensiones: dashboard web, publicación en PyPI, integración Censys.
