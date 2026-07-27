# WebVulnScanner 2.0 — Auditoría Pasiva de Seguridad Web

**Materia:** Redes de Computadores
**Autor:** fozzy3
**Enfoque:** Ético, académico y **no intrusivo** (solo reconocimiento pasivo, sin inyección de payloads ni fuerza bruta).

---

## ¿Qué hace?

Audita la superficie de seguridad *externa* de un dominio en **10 módulos**, clasifica cada hallazgo por riesgo (🔴 Alto / 🟡 Medio / 🟢 Bajo / 🔵 Info / ✅ Buenas prácticas) y exporta un reporte en `.txt` y `.json`.

| # | Módulo | Qué analiza | Concepto de redes |
|---|--------|-------------|-------------------|
| 1 | **Reconocimiento** | DNS A/AAAA (IPv4+IPv6), cabeceras `Server`/`X-Powered-By`, producto+versión | DNS, HTTP |
| 2 | **Puertos + banners** | TCP connect scan a 17 puertos + *banner grabbing* de versión | TCP, servicios |
| 3 | **TLS/HTTPS** | Enumera **versiones** (detecta SSLv3/TLS 1.0/1.1), **ciphers débiles**, validez/CN/SAN del certificado, redirección HTTP→HTTPS | TLS, PKI |
| 4 | **Headers HTTP** | Evalúa el **valor** de CSP (unsafe-inline, wildcards) y HSTS (max-age, includeSubDomains), no solo presencia | Seguridad web |
| 5 | **DNS y correo** | MX, **SPF/DMARC** (antispoofing), **CAA**, y prueba de **transferencia de zona (AXFR)** | DNS, correo |
| 6 | **Subdominios** | Enumeración pasiva vía **Certificate Transparency** (crt.sh) | PKI, CT logs |
| 7 | **Exposición** | Detecta `.git/`, `.env`, backups, `robots.txt` con rutas sensibles, `security.txt` | HTTP |
| 8 | **WAF/CDN** | Identifica Cloudflare, Akamai, Sucuri, Fastly… por firmas | Infraestructura |
| 9 | **Fingerprint** | CMS/frameworks (WordPress, Drupal, Laravel…) por headers/cookies/HTML | App web |
| 10 | **CVEs** | Correlaciona producto+versión con la API pública del **NVD** | Gestión de vulnerabilidades |

---

## Instalación

Requiere **Python 3.10+**. Se instala como paquete:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .                   # núcleo (CLI) + dnspython
pip install -e ".[gui]"            # + interfaz gráfica (customtkinter)
pip install -e ".[dev]"            # + pytest para tests
```

---

## Uso

### Línea de comandos

```bash
webvulnscanner example.com                 # escaneo completo
webvulnscanner example.com --only tls,dns  # solo ciertos módulos
webvulnscanner example.com --skip cve      # todo menos CVEs
webvulnscanner example.com -o reportes/    # carpeta de salida
webvulnscanner example.com --no-save -q    # sin archivos, sin log de progreso
webvulnscanner --version
```

Devuelve **código de salida 2** si hay hallazgos de riesgo alto (útil para CI).

### Interfaz gráfica

```bash
python gui.py
```

Panel izquierdo: log en vivo + tarjetas de resumen. Panel derecho: pestañas de Problemas / Buenas prácticas / Informativo / Reporte completo.

---

## Sitios de prueba autorizados

| Sitio | Descripción |
|-------|-------------|
| `scanme.nmap.org` | Nmap — autorizado explícitamente para escaneos |
| `testphp.vulnweb.com` | Acunetix — PHP vulnerable de prueba |
| `example.com` | IANA — dominio de referencia |

⚠️ **NUNCA** use esta herramienta en sitios sin autorización explícita.

---

## Arquitectura

```
src/webvulnscanner/
├── models.py         # Núcleo puro: Finding, Risk, ScanResult (sin red ni UI)
├── net.py            # Utilidades HTTP/socket compartidas
├── orchestrator.py   # Coordina los módulos, aísla fallos
├── report.py         # Render texto/JSON (puro) + guardado (único I/O)
├── cli.py            # Entrada de consola (argparse)
└── modules/          # Un módulo por capacidad (recon, ports, tls, …)
gui.py                # Interfaz (customtkinter), habla con el núcleo vía logging
tests/                # Suite de la lógica pura (parsing, clasificación, render)
```

Decisiones de diseño:
- **Sin acoplamiento por `print`**: los módulos emiten progreso vía `logging`; CLI y GUI enganchan sus propios handlers.
- **Render puro separado de la escritura**: `report.render_texto/json` son funciones sin efectos → testeables sin filesystem.
- **Fallo aislado por módulo**: si uno revienta, el escaneo continúa y lo reporta.

### Tests

```bash
pytest        # 16 tests sobre lógica pura (sin red)
```

---

## Ética y alcance

Todo es **pasivo**: peticiones HTTP normales, handshakes TLS y consultas a fuentes públicas (crt.sh, NVD). **No** hay inyección de payloads, fuzzing de directorios ni fuerza bruta. La prueba de AXFR y la solicitud de rutas como `/.env` consultan recursos que el propio servidor decide exponer; úselas solo sobre objetivos autorizados.

## Limitaciones conocidas / trabajo futuro

- La correlación de CVEs usa *keyword search* del NVD (no CPE): puede traer falsos positivos.
- No se detectan Heartbleed/ROBOT (requieren manipulación TLS a bajo nivel).
- Detección activa (XSS/SQLi, fuzzing) queda fuera por diseño ético.
- Posibles extensiones: integración con Shodan, scoring ponderado tipo SSL Labs, export a SARIF/HTML.
