# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/).

## [No publicado]

### Añadido — Informe de 3 pestañas auto-generado (`informe.py`)
- La herramienta genera **automáticamente** `informe.html` (pestañas 📋 Informe · 🗂️ Inteligencia · 🔍 Qué revisa) desde el resultado del escaneo — ya no se cura a mano.
- Data-driven: la pestaña "Qué revisa" sale de una tabla única de módulos (fuente de verdad). Tema claro/oscuro, responsive, CSS puro, HTML escapado.
- El CLI escribe `informe.html` en cada escaneo.

### Añadido — Laboratorio de red: canal encubierto en IP ID (subpaquete `covert`, capa 3/4)
- Nuevo CLI **`webvulnscanner-covert`** (demo/send/recv/detect/mitigate) para el Taller de Redes.
- **Implementación**: `ipid.py` codifica/decodifica datos en el campo IP Identification.
- **Detección**: `detector.py` (entropía + secuencialidad → `Finding`) y `ml.py` (clasificador RandomForest, la parte de "IA").
- **Mitigación**: `mitigador.py` aleatoriza el IP ID (`normalizar` puro + gateway NFQUEUE inline).
- Capas de red con scapy/netfilterqueue (extra `netlab`), degradación elegante. Núcleo puro con tests. Ver `covert/README.md`.

### Añadido — Motores externos opcionales (extras `enhanced`/`apifuzz`)
- **sslyze** (`tls_deep`): análisis TLS profundo — Heartbleed, ROBOT, CCS-injection, protocolos obsoletos.
- **Wappalyzer** (`stack`): fingerprint de cientos de tecnologías con versión + **correlación CVE por componente** (NVD, no solo el servidor). Dedup de CVEs repetidos.
- **detect-secrets**: booster de secretos por entropía en el módulo `secrets`.
- **schemathesis** (`api_fuzz`, activo): fuzzing de API contra su OpenAPI — detecta errores 5xx no manejados, respuestas fuera de contrato y códigos no documentados. Wrapper del CLI (invocado desde el venv), reporte JUnit parseado. Se auto-gatea: solo corre si hay OpenAPI expuesto.
- **PyJWT / nvdlib**: disponibles como extra para robustez.
- Todos con **degradación elegante**: si la librería no está instalada, el módulo se omite.

### Añadido — Pruebas dirigidas al backend
- **`wordpress`** (pasivo): enumeración de usuarios (wp-json/?author), **divulgación de IP interna** vía wp-json, xmlrpc, readme, wp-login, uploads.
- **`frameworks`** (pasivo): Drupal, Joomla, Laravel (Ignition/Telescope) y paneles (phpMyAdmin, Adminer, server-status).

### Añadido — Fases L→O (ciberseguridad de frontera)
- **Fase L — transporte**: `net.request()` con métodos/cuerpo (POST/PUT/DELETE/PATCH, form o JSON), escaneo **autenticado** (`--cookie/--bearer/--header`) y **throttle** (`--delay/--rps`). `fetch()` intacto (delega GET).
- **Fase M — inyección profunda** (activo, gateado): sobre **formularios y POST**, **por-parámetro**, con **LFI, SSTI, CRLF, command injection y SQLi ciega time-based** (confirmación por firma, no destructivo). Nuevo módulo **CSRF** pasivo.
- **Fase N — superficie moderna** (pasivo): **OpenAPI/Swagger + GraphQL introspection**, **análisis JWT** (alg:none, secreto HS256 trivial, exp), **misconfig cloud** (buckets públicos, metadata/SSRF) y **MTA-STS/TLS-RPT**.
- **Fase O — inteligencia de reporte**: **CWE + CVSS v3.1 nativo** por hallazgo, **baseline** de supresión (`--baseline/--write-baseline`, `.wvsignore`) y **mapeo a compliance** (PCI-DSS/ISO 27001/NIST 800-53).
- **Migración OWASP a Top 10 2025**: A03 Software Supply Chain y A10 Mishandling of Exceptional Conditions nuevas; SSRF fusionado en A01; normalización 2021→2025.
- **Fase Q — control de acceso** (activo): **IDOR/BOLA** (identificador ajeno accesible) y **forced browsing** (paneles admin sin sesión) — A01:2025.
- **Fase R — autenticación** (activo): **enumeración de usuarios**, **credenciales por defecto** y **ausencia de rate-limit en login** — A07:2025.
- **Fase S — SSRF activo** (activo): SSRF confirmado por metadata + **Host Header Injection** + indicio de cache poisoning — A01:2025.
- **Fase T — supply chain** (pasivo): **SBOM CycloneDX 1.5** (`--sbom`) y **dependency confusion** (paquetes con scope) — A03:2025.
- **Fase U — condiciones excepcionales** (activo suave): **stack traces** y **modo debug** en producción — A10:2025.
- **Fase V — consumo de recursos** (activo suave): detección de **ausencia de rate-limiting** — API4:2023.
- Cobertura resultante: **≥8/10 OWASP Top 10 2025** y **≥7/10 API Security Top 10 2023**. 170→285 tests.

### Añadido
- **Validación del objetivo** (`net.normalizar_dominio`): punto único de confianza.
  Acepta URLs completas y extrae el host; rechaza rutas, credenciales y valores
  que empiecen por `-` (que nuclei/nmap/wpscan leerían como opciones). El CLI
  responde con código 1 y la API con HTTP 400 en vez de reventar.
- Tests de CLI (0 % → 97 %), API REST (0 % → 100 %), wrappers externos
  (27 % → 100 %) y TLS (13 % → 45 %). Total: 74 → 170 tests, 58 % → 72 % cobertura.
- `httpx` en el extra `dev` (lo necesita `fastapi.testclient`).

### Corregido
- La caché de EPSS nunca acertaba: la clave usaba `hash()` de un str, que va
  sembrado al azar por proceso (`PYTHONHASHSEED`). Cada escaneo reconsultaba la API.
- `--profile full --authorized` descartaba en silencio todos los módulos activos;
  `full` ahora significa "todo lo disponible".
- Sin dominio y sin TTY (pipe o CI), el CLI se colgaba en `input()`.
- `subfinder` tomaba por subdominio cualquier línea de stdout, incluidos sus
  propios avisos y errores; ahora filtra a hostnames válidos.
- Un `notAfter` con formato inesperado abortaba el módulo TLS entero.

## [2.0.0] — 2026-07-27

Reescritura completa: de 3 scripts sueltos a un paquete profesional.

### Añadido
- **Empaquetado**: `pyproject.toml`, instalable, `src/`-layout, `py.typed`, entry point `webvulnscanner`.
- **Ingeniería**: CI (GitHub Actions, Py 3.10–3.12), ruff, mypy, pytest (59 tests), Makefile, Docker.
- **Concurrencia**: los módulos independientes corren en paralelo.
- **Caché** en disco con TTL para crt.sh, NVD y Shodan (no se envenena con fallos).
- **Profundidad**:
  - CVEs por **CPE** (antes keyword, con falsos positivos).
  - **Nota A–F** ponderada.
  - TLS: enumeración de versiones, ciphers débiles, fuerza de clave/firma.
  - DNS: SPF/DMARC/DKIM/BIMI, CAA, DNSSEC, AXFR.
  - Subdominios vía CT logs + detección de **subdomain takeover**.
  - WAF/CDN y fingerprint de tecnologías.
- **Salida**: reporte HTML autocontenido, export **SARIF 2.1.0**, **diff** entre escaneos, perfiles de escaneo.
- **Modo activo** (`--authorized`): cookies, CORS, XSS/SQLi reflejado, fuzzing — estrictamente gateado.
- **Interfaces**: CLI (argparse), GUI (logging en vez de secuestrar stdout), API REST (FastAPI).

### Cambiado
- `Finding` pasó de dict a dataclass tipada con `Risk` enum.
- Reportes separan render puro de la escritura a disco.

### Corregido
- Rutas de reporte inconsistentes entre CLI y GUI.
- Fallos silenciosos y textos contradictorios del scanner original.
- Falso positivo de "cipher débil" con suites AEAD de TLS 1.3.

## [1.0.0]
- Versión académica inicial: `scanner.py` + `gui.py` (4 módulos, sin tests ni empaquetado).
