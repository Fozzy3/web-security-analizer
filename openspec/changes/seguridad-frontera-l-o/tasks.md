# Tasks: Ciberseguridad de frontera — Fases L→V

TDD estricto: cada bloque RED (test que falla) → GREEN (implementar) → gate `make check`.
Cada fase = 1 commit. Orden obligatorio: L primero (desbloquea M/Q/R/S); N, O, T independientes;
Q depende de L; R, S dependen de L; U, V activos suaves independientes.
Meta de cobertura OWASP: ≥8/10 Top 10 2025 y ≥7/10 API Top 10 2023.

## Fase L — Transporte (fundacional)

- [x] 1.1 RED: `test_net.py` — `request()` POST form, JSON body, throttle (medir delay), `fetch()` intacto
- [x] 1.2 GREEN: `net.py` — `request(method,data,json,headers)`, `Sesion` dataclass, sesión activa (global de módulo, ver desviación)
- [x] 1.3 GREEN: `net.py` — `fetch()` delega en `request(method="GET")`; throttle vía `Sesion.delay`
- [x] 1.4 GREEN: `cli.py` — flags `--cookie/--header/--bearer/--delay/--rps` → `_construir_sesion`; no loguear auth
- [x] 1.5 GREEN: `orchestrator.py` — recibir `Sesion`, activarla con `configurar_sesion` antes de los módulos
- [x] 1.6 Verificar `make check` limpio (188 tests); commit `feat(fase-l)` [pendiente de confirmación del usuario]

## Fase M — Profundidad activa

- [x] 2.1 RED: `test_injection_depth.py` — XSS vía POST, cobertura por-parámetro (2 params), LFI y SSTI por firma, blind SQLi consistente
- [x] 2.2 GREEN: `active.py` — inyección sobre `crawl.forms` por método real (`_enviar` usa `request` en POST)
- [x] 2.3 GREEN: `active.py` — loop por-parámetro con dedup `(ruta,param,clase)`, sin cortar al primero
- [x] 2.4 GREEN: `active.py` — clases LFI/SSTI/CRLF/cmdi + blind SQLi time-based (base vs sleep, 2ª confirmación)
- [x] 2.5 GREEN: inyección profunda dentro de `inyeccion` (ya en `MODULOS_ACTIVOS`, gate `autorizado`)
- [x] 2.6 RED+GREEN: `csrf.py` (PASIVO) — form POST sin token/SameSite; registrado en `MODULOS`
- [x] 2.7 Test gate: csrf pasivo / inyección activa; `make check` (205 tests); commit `feat(fase-m)` [pendiente confirmación]

## Fase N — Superficie moderna (pasivo)

- [x] 3.1 RED+GREEN: `api_discovery.py` — OpenAPI/Swagger + GraphQL introspection (respuestas de ejemplo)
- [x] 3.2 RED+GREEN: `jwt_audit.py` — alg:none, HS256 secreto trivial (lista embebida), sin exp, vencido
- [x] 3.3 RED+GREEN: `cloud.py` — bucket S3/GCS/Azure público (ListBucketResult), metadata 169.254.169.254
- [x] 3.4 RED+GREEN: `mail_transport.py` — MTA-STS (TXT+policy) y TLS-RPT (reusa `_consultar`)
- [x] 3.5 Registrados los 4 en `MODULOS`; `make check` (226 tests); commit `feat(fase-n)` [pendiente confirmación]

## Fase O — Inteligencia de reporte

- [x] 4.1 RED: `test_classify.py` — score CVSS v3.1 con vectores conocidos (7.5/9.8/6.1/0.0); retrocompat `from_dict`
- [x] 4.2 GREEN: `models.py` — `Finding.cwe`, `Finding.cvss`; to_dict/from_dict retrocompat
- [x] 4.3 GREEN: `classify.py` — mapa tipo→CWE + fórmula CVSS base nativa; enganchado tras `enrich`/`owasp`
- [x] 4.4 RED+GREEN: `baseline.py` — huella `hash(modulo,hallazgo,ref)`, cargar/filtrar/escribir; flags `--baseline/--write-baseline`
- [x] 4.5 RED+GREEN: `compliance.py` — OWASP 2025 → PCI/ISO/NIST; sección "Controles afectados"
- [x] 4.6 GREEN: `report.py`/`sarif.py` — render CWE/CVSS/OWASP + resumen compliance (html pendiente, opcional)
- [x] 4.7 RED+GREEN: `owasp.py` — migrado a Top 10 2025 (A03/A10 nuevas, remap 2021→2025, SSRF→A01)
- [x] 4.8 `make check` (249 tests); commit `feat(fase-o)` [pendiente confirmación]

## Fase Q — Control de acceso / autorización (A01 2025, API1/3/5)

- [x] 5.1 RED: `test_access_control.py` — read-IDOR objeto ajeno 2xx; denegado 403; mismo contenido no marca; forced browsing panel sin sesión
- [x] 5.2 GREEN: `modules/access_control.py` — IDOR/BOLA sobre ids numéricos (lectura, GET), _segmento_numerico/_vecino puros
- [x] 5.3 GREEN: forced browsing sin sesión (`sin_sesion=True`, rutas admin); registrado en `MODULOS_ACTIVOS`
- [x] 5.4 Test gate: activo (no pasivo); escritura → verificación manual (proof no destructiva); `make check`; commit `feat(fase-q)`

## Fase R — Autenticación (A07 2025, API2)

- [x] 6.1 RED: `test_auth.py` — enumeración por respuesta diferencial; default creds set; sin rate-limit login
- [x] 6.2 GREEN: `modules/auth_test.py` — enumeración de usuarios (respuesta diferencial)
- [x] 6.3 GREEN: default creds (set de credenciales comunes, _es_exito_login heurístico)
- [x] 6.4 GREEN: ausencia de rate-limit (ráfaga de intentos, 429 esperado)
- [x] 6.5 Registrado en `MODULOS_ACTIVOS`; test gate `autorizado`; `make check` (265 tests); commit `feat(fase-r)`

## Fase S — SSRF activo + Host Header Injection (A01/API7)

- [x] 7.1 RED: `test_ssrf.py` — metadata reflejada; host header reflejado; cache poisoning indicio
- [x] 7.2 GREEN: `modules/ssrf.py` — SSRF sobre params URL (169.254.169.254/localhost), confirmación por firma metadata
- [x] 7.3 GREEN: Host Header Injection (`Host`/`X-Forwarded-Host` reflejado) + cache poisoning básico
- [x] 7.4 Registrado en `MODULOS_ACTIVOS`; `make check`; commit `feat(fase-s)`

## Fase T — Supply chain + SBOM (A03 2025 🆕)

- [x] 8.1 RED: `test_sbom.py` — CycloneDX 1.5 válido con componentes; SBOM vacío válido; dependency confusion scoped
- [x] 8.2 GREEN: `sbom.py` — CycloneDX 1.5 desde fingerprint+retire.js+CVE; flag `--sbom PATH`
- [x] 8.3 GREEN: indicio dependency confusion (paquetes `@scope/…`); registrado en `MODULOS` (pasivo)
- [x] 8.4 `make check`; commit `feat(fase-t)`

## Fase U — Condiciones excepcionales (A10 2025 🆕)

- [x] 9.1 RED: `test_error_audit.py` — stack trace por firma; error limpio no marca; panel debug framework
- [x] 9.2 GREEN: `modules/error_audit.py` — inducir error (sondas), detectar traza y modo debug
- [x] 9.3 Registrado en `MODULOS_ACTIVOS` (activo suave); `make check`; commit `feat(fase-u)`

## Fase V — Consumo de recursos / rate-limit (API4)

- [x] 10.1 RED: `test_rate_limit.py` — sin 429 → hallazgo; con 429/header → no marca; respeta `burst`
- [x] 10.2 GREEN: `modules/rate_limit.py` — ráfaga configurable `burst`, cabeceras de límite
- [x] 10.3 Registrado en `MODULOS_ACTIVOS`; `make check`; commit `feat(fase-v)`

## Fase de cierre

- [x] 11.1 Categorías OWASP/CWE/CVSS visibles por hallazgo + sección compliance en el reporte
- [x] 11.2 Actualizar `README.md`, `CHANGELOG.md`; 285 tests (>72% cobertura de flujo)
- [x] 11.3 `make check` limpio; listo para `/sdd-verify`
