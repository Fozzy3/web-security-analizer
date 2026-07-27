# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/).

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
