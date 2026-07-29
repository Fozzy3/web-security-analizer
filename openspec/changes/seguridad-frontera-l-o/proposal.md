# Proposal: Ciberseguridad de frontera — Fases L→V

## Intent

La herramienta es un auditor pasivo sólido con una capa activa **acotada por una limitación fundacional**: `net.fetch()` solo hace GET, por lo que todo lo activo prueba únicamente query-string. Formularios, cuerpos POST y APIs modernas son inalcanzables, y sin sesión no se auditan zonas autenticadas. Además, el etiquetado OWASP apunta al **Top 10 2021** (desactualizado: el **2025** fusionó SSRF en A01 y añadió A03 Supply Chain y A10 Exceptional Conditions), y no cubre el **API Security Top 10 2023** — donde vive el mayor hueco: **autorización/autenticación** (A01/A07 web, API1/2/3/5). Este cambio profundiza el nicho (auditor autocontenido, ético, no destructivo) sin reimplementar Burp/ZAP, apuntando al máximo cobertura defendible para un scanner de caja negra.

## Scope

### In Scope
- **L**: transporte con métodos/body (POST/PUT/DELETE/PATCH), escaneo autenticado (cookie/header/bearer), throttle (--delay/--rps).
- **M**: inyección sobre formularios y POST; SQLi blind time-based; clases nuevas (path-traversal/LFI, SSTI, command injection, CRLF); detección CSRF; cobertura por-parámetro.
- **N**: descubrimiento OpenAPI/Swagger y GraphQL introspection; análisis JWT (alg:none, exp, secreto débil); misconfig cloud (buckets públicos, metadata); MTA-STS/TLS-RPT.
- **O**: CWE + vector CVSS para hallazgos propios; baseline/supresión de FP (`.wvsignore`); mapeo a compliance (PCI-DSS/ISO 27001/NIST 800-53); **migración del tagging OWASP a Top 10 2025**.
- **Q**: control de acceso/autorización (IDOR/BOLA por manipulación de object-IDs, forced browsing autenticado) — A01 2025, API1/3/5.
- **R**: autenticación (enumeración de usuarios, default creds, ausencia de rate-limit en login, session fixation) — A07 2025, API2.
- **S**: SSRF activo + Host Header Injection + cache poisoning básico — A01/API7.
- **T**: supply chain — SBOM CycloneDX (retire.js+fingerprint) + dependency confusion — A03 2025.
- **U**: manejo de condiciones excepcionales (disparar errores → stack traces, modo debug, verbosidad) — A10 2025.
- **V**: consumo de recursos — detección de rate-limiting del objetivo (sin DoS) — API4.

### Out of Scope
- Fase P (triage LLM, auto-selección nuclei) — diferida (SBOM se adelanta a T).
- Motor headless/DOM XSS, stored XSS, wordlists masivas, explotación real más allá de PoC.
- Inherentemente manual/caja-blanca: A06 Insecure Design, A09 Logging, API6 business flows, API10 unsafe consumption.

## Capabilities

### New Capabilities
- `http-transport`: capa de request con método, body/json, throttle y passthrough de sesión (base de todo lo activo).
- `active-injection-depth`: inyección en form/POST, blind SQLi, LFI/SSTI/cmdi/CRLF, por-parámetro.
- `csrf-detection`: formularios sensibles sin token anti-CSRF.
- `api-surface-discovery`: OpenAPI/Swagger + GraphQL introspection.
- `jwt-analysis`: debilidades en JWT servidos al cliente.
- `cloud-misconfig`: almacenamiento público y metadata endpoints.
- `mail-transport-security`: MTA-STS y TLS-RPT (complementa DNS de correo).
- `finding-classification`: CWE + CVSS v3.1 vector/score por hallazgo.
- `baseline-suppression`: archivo de baseline para ignorar hallazgos aceptados.
- `compliance-mapping`: etiquetado PCI/ISO/NIST por hallazgo.
- `access-control-testing`: IDOR/BOLA y forced browsing autenticado (activo).
- `authentication-testing`: enumeración de usuarios, default creds, rate-limit de login, session fixation (activo).
- `ssrf-header-injection`: SSRF activo, Host Header Injection, cache poisoning básico (activo).
- `supply-chain-sbom`: SBOM CycloneDX + dependency confusion.
- `error-handling-audit`: stack traces, modo debug y fugas en errores (activo suave).
- `resource-consumption`: detección de rate-limiting del objetivo (activo suave).

### Modified Capabilities
- `owasp-tagging` (código existente `owasp.py`): migrar de Top 10 2021 a **2025** — remapear SSRF→A01, añadir A03 Supply Chain y A10 Exceptional Conditions. Cubierto por la spec `owasp-2025-mapping`.

## Approach

**Orden**: L primero (desbloquea M, Q, R, S). N, O, T independientes (pasivo/reporte). Q depende de L (sesión); R y S dependen de L. U y V son activos suaves independientes. Cada capability = módulo aislado nuevo o extensión de `net.py`/`models.py`/`owasp.py`. Activos (M, Q, R, S; suaves U, V) gateados tras `autorizado=True`; nunca expuestos por la API. Pasivos (N, T, csrf) disponibles siempre. TDD: red simulada por monkeypatch.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `net.py` | Modified | `request()` con method/data/throttle/sesión |
| `modules/active.py` | Modified | form/POST injection, clases nuevas, CSRF |
| `modules/` (nuevos N) | New | api_discovery, jwt, cloud, mail_transport |
| `modules/` (nuevos Q-V) | New | access_control, auth_test, ssrf, error_audit, rate_limit |
| `models.py` | Modified | campos cwe/cvss en Finding |
| `owasp.py` | Modified | migrar tagging a Top 10 2025 (A03/A10 nuevas, SSRF→A01) |
| nuevos `classify.py`/`compliance.py`/`baseline.py`/`sbom.py` | New | CWE/CVSS, compliance, baseline, SBOM |
| `orchestrator.py`, `cli.py`, `report.py` | Modified | registrar módulos, flags, render |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Activo intrusivo daña objetivo | Med | Payloads no destructivos, gate autorizado, throttle |
| Falsos positivos inflan reporte | Med | Confirmación por firma; baseline de supresión (Fase O) |
| Secreto de sesión se filtra al log | Low | No loguear headers de auth; redacción |
| Scope creep hacia reimplementar Burp | Med | Out-of-scope explícito; delegar a nuclei/nmap |
| Write-IDOR daña datos del cliente | Med | Proof no destructiva (operación benigna/idempotente o detección por código), no payloads que borren |
| Pruebas activas sin consentimiento | — | Gate `--authorized` como única frontera; el operador confirma autorización |

## Rollback Plan

Cada fase es un commit independiente. `net.request()` se añade sin tocar `fetch()` (compat hacia atrás), así que revertir una fase = `git revert` de su commit sin romper las previas. Módulos nuevos se desregistran quitándolos de `MODULOS`/`MODULOS_ACTIVOS`.

## Dependencies

- Ninguna dependencia nueva obligatoria. CVSS/CWE se computan nativo (sin libs). Cloud/JWT usan stdlib + regex.

## Success Criteria

- [ ] `net.request()` soporta POST/body/sesión/throttle con tests; `fetch()` intacto.
- [ ] Inyección cubre formularios/POST y ≥3 clases nuevas, gateadas y no destructivas.
- [ ] Módulos N (api/jwt/cloud/mail) producen findings con red simulada en tests.
- [ ] Hallazgos llevan CWE+CVSS; baseline suprime; compliance mapea; tagging OWASP en **2025**.
- [ ] Q/R detectan IDOR y fallos de autenticación con sesión, sin métodos mutantes ni bloqueo de cuentas.
- [ ] T emite SBOM CycloneDX válido; U detecta stack traces/debug; V mide rate-limiting.
- [ ] Cobertura OWASP: **≥8/10 Top 10 2025** y **≥7/10 API Top 10 2023** trazables en el reporte.
- [ ] `make check` limpio; cobertura de tests no baja de 72%.
