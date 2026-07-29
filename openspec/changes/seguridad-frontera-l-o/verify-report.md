# Verification Report — seguridad-frontera-l-o

**Change**: seguridad-frontera-l-o  
**Mode**: Strict TDD  
**Method**: 15 agentes de verificación (1 por spec/grupo) cruzando cada escenario Given/When/Then contra implementación real y tests ejecutados.  
**Generated from**: workflow wf_c5c61be0-07d (17 specs, 0 errores)

---

## Gate ejecutado (real, vía `rtk proxy make check`)

| Paso | Resultado |
|------|-----------|
| ruff check | ✅ All checks passed |
| mypy | ✅ Success, no issues (64 files) |
| pytest | ✅ 332 passed, 2 skipped, 0 failed |
| skips | ⚠️ 2 — extras opcionales (fastapi, weasyprint), no relacionados con el cambio |
| cobertura total | ✅ 75% (umbral 72%) |

> Nota: el entorno estaba roto al iniciar (paquete sin instalar, faltaban dnspython/mypy/pytest-cov, editable stale apuntando a ~/Downloads). Reparado; el 'make check limpio' de tasks.md no era reproducible hasta el fix.

---

## Spec Compliance Matrix — 44/67 escenarios COMPLIANT

| Spec | Escenario | Test | Resultado |
|------|-----------|------|-----------|
| http-transport | POST con cuerpo form | `tests/test_net.py:104 test_request_post_form` | ✅ COMPLIANT |
| http-transport | JSON body | `tests/test_net.py:114 test_request_json_body` | ✅ COMPLIANT |
| http-transport | fetch sin cambios | `tests/test_net.py:131 test_fetch_sigue_funcionando; tests/test_net.py:147 test_fetch_fallback_https_a_http; tests/test_net.py:123 test_request_get_por_defecto` | ✅ COMPLIANT |
| http-transport | cookie de sesión | `tests/test_net.py:161 test_sesion_headers_se_aplican; tests/test_cli.py:167 test_cookie_va_a_header_cookie; tests/test_cli.py:192 test_main_propaga_sesion_al_scan; tests/test_orchestrator.py:70 test_run_scan_activa_la_sesion` | ✅ COMPLIANT |
| http-transport | no fuga en log | `tests/test_net.py:171 test_sesion_no_filtra_secreto_en_log` | ⚠️ PARTIAL |
| http-transport | delay aplicado | `tests/test_net.py:189 test_throttle_espacia_peticiones` | ✅ COMPLIANT |
| active-injection-depth | XSS reflejado vía POST: form POST cuyo input se refleja, se envía el marcador wvs9z7xq"<x> por POST, se reporta XSS ALTO con parámetro y método | `test_xss_via_post_form` | ✅ COMPLIANT |
| active-injection-depth | form GET también cubierto: form con method=get, el payload va en query-string | `(ninguno)` | ❌ UNTESTED |
| active-injection-depth | dos params vulnerables: dos parámetros reflejan el payload, se reportan ambos no solo el primero | `test_xss_por_parametro_reporta_todos` | ✅ COMPLIANT |
| active-injection-depth | retardo confirmado: endpoint cuyo tiempo sube con el sleep, se mide base y payload dos veces, se reporta SQLi blind ALTO solo si el retardo es consistente | `test_es_retardo_requiere_dos_confirmaciones` | ⚠️ PARTIAL |
| active-injection-depth | LFI confirmado por firma: ?file=../../../../etc/passwd, la respuesta contiene root:.*:0:0:, se reporta path traversal ALTO | `test_lfi_detectado (+ test_confirma_lfi_por_firma_passwd)` | ✅ COMPLIANT |
| active-injection-depth | SSTI confirmado por evaluación: payload ${7*7}/{{7*7}}, la respuesta contiene 49, se reporta SSTI ALTO | `test_ssti_detectado (+ test_confirma_ssti_solo_si_evalua)` | ✅ COMPLIANT |
| csrf-detection | POST sin token | `tests/test_csrf.py::test_form_post_sin_token_es_medio` | ✅ COMPLIANT |
| csrf-detection | form con token no se marca | `tests/test_csrf.py::test_form_con_token_no_se_marca` | ✅ COMPLIANT |
| csrf-detection | SameSite mitiga | `tests/test_csrf.py::test_samesite_baja_a_bajo` | ✅ COMPLIANT |
| api-surface-discovery | openapi.json expuesto: /openapi.json responde 200 con {"openapi":"3..."} → se reporta superficie de API INFO/BAJO con cantidad de endpoints | `tests/test_api_discovery.py::test_openapi_expuesto_se_reporta` | ⚠️ PARTIAL |
| api-surface-discovery | ruta ausente: todas las rutas devuelven 404 → no se reporta hallazgo | `tests/test_api_discovery.py::test_sin_openapi_ni_graphql_no_reporta` | ✅ COMPLIANT |
| api-surface-discovery | introspección abierta: /graphql responde el __schema completo → se reporta introspección habilitada MEDIO con el número de tipos | `tests/test_api_discovery.py::test_graphql_introspeccion_abierta_es_medio` | ⚠️ PARTIAL |
| api-surface-discovery | introspección deshabilitada: /graphql rechaza la introspección → no se reporta hallazgo de introspección | `tests/test_api_discovery.py::test_graphql_deshabilitada_no_reporta` | ✅ COMPLIANT |
| jwt-analysis | alg none — JWT con header {"alg":"none"} => ALTO "JWT acepta alg:none" | `tests/test_jwt_audit.py::test_alg_none_es_alto` | ✅ COMPLIANT |
| jwt-analysis | secreto débil HS256 — JWT HS256 firmado con `secret` => ALTO con el secreto encontrado (redactado parcialmente) | `tests/test_jwt_audit.py::test_hs256_secreto_debil_es_alto` | ⚠️ PARTIAL |
| jwt-analysis | sin exp — JWT sin claim `exp` => MEDIO "JWT sin expiración" | `tests/test_jwt_audit.py::test_sin_exp_es_medio` | ✅ COMPLIANT |
| jwt-analysis | JWT válido y fuerte — RS256 con exp futuro => no se reporta debilidad | `tests/test_jwt_audit.py::test_jwt_fuerte_no_marca` | ✅ COMPLIANT |
| jwt-analysis | (sin escenario formal, exigido en el texto del requirement) exp ya vencido en token activo => BAJO | `tests/test_jwt_audit.py::test_exp_vencido_es_bajo` | ✅ COMPLIANT |
| cloud-misconfig | bucket S3 listable: GIVEN URL de bucket S3 referenciada, WHEN la raíz devuelve ListBucketResult XML, THEN ALTO 'bucket público listable' con el nombre | `tests/test_cloud.py::test_bucket_s3_publico_listable_es_alto` | ✅ COMPLIANT |
| cloud-misconfig | bucket privado: GIVEN bucket referenciado que devuelve AccessDenied, WHEN corre el módulo, THEN no se reporta (o INFO de bucket referenciado) | `—` | ❌ UNTESTED |
| cloud-misconfig | metadata endpoint en JS: GIVEN un script referencia 169.254.169.254, WHEN corre el módulo, THEN MEDIO indicio de SSRF hacia metadata | `tests/test_cloud.py::test_referencia_metadata_es_medio (+ helper tests/test_cloud.py::test_detecta_referencia_metadata)` | ⚠️ PARTIAL |
| mail-transport-security | MTA-STS en enforce: existe TXT _mta-sts y policy con mode: enforce -> OK "MTA-STS en enforce" | `tests/test_mail_transport.py::test_mta_sts_enforce_es_ok` | ✅ COMPLIANT |
| mail-transport-security | MTA-STS ausente: no existe registro _mta-sts -> BAJO "sin MTA-STS: downgrade de TLS posible" | `tests/test_mail_transport.py::test_mta_sts_ausente_es_bajo` | ✅ COMPLIANT |
| mail-transport-security | policy en testing: mode: testing -> INFO "MTA-STS en testing (no fuerza TLS aún)" | `tests/test_mail_transport.py::test_mta_sts_testing_es_info (+ test_modo_mta_sts_parsea pin del parser)` | ✅ COMPLIANT |
| mail-transport-security | sin TLS-RPT: no existe _smtp._tls -> INFO "sin TLS-RPT: no hay visibilidad de fallos TLS de correo" | `tests/test_mail_transport.py::test_sin_tls_rpt_es_info` | ✅ COMPLIANT |
| finding-classification | retrocompatibilidad de deserialización: GIVEN reporte .json anterior sin cwe/cvss WHEN Finding.from_dict THEN cwe y cvss son None y no falla | `tests/test_models.py::test_finding_retrocompat_sin_cwe_cvss` | ✅ COMPLIANT |
| finding-classification | XSS reflejado clasificado: GIVEN hallazgo de XSS reflejado WHEN corre la clasificación THEN se asigna CWE-79 y vector CVSS con score >= 6.1 | `tests/test_classify.py::test_clasifica_xss_con_cwe_79` | ⚠️ PARTIAL |
| finding-classification | score derivado del vector: GIVEN CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N WHEN se computa el score THEN redondea a 7.5 según la fórmula oficial v3.1 | `tests/test_classify.py::test_cvss_score_7_5` | ✅ COMPLIANT |
| finding-classification | [fuera de la spec, observado] hallazgo sin mapeo no recibe CWE/CVSS | `tests/test_classify.py::test_hallazgo_sin_mapeo_queda_sin_cwe` | ✅ COMPLIANT |
| finding-classification | [fuera de la spec, observado] integración en el pipeline: escanear() debe dejar los findings clasificados | `(ninguno)` | ❌ UNTESTED |
| baseline-suppression | hallazgo suprimido: baseline con la huella -> se excluye del reporte y del conteo de riesgo | `tests/test_baseline.py::test_filtrar_suprime_los_del_baseline (+ test_round_trip_escribir_cargar)` | ⚠️ PARTIAL |
| baseline-suppression | hallazgo nuevo pasa: baseline sin la huella -> se reporta normalmente | `tests/test_baseline.py::test_filtrar_suprime_los_del_baseline` | ✅ COMPLIANT |
| baseline-suppression | escribir baseline: escaneo con N hallazgos + --write-baseline -> archivo con N huellas y siguiente escaneo idéntico reporta 0 | `tests/test_baseline.py::test_round_trip_escribir_cargar` | ✅ COMPLIANT |
| compliance-mapping | TLS obsoleto mapeado: hallazgo de protocolo TLS obsoleto -> PCI-DSS 4.1 (o equivalente), ISO A.10, y un control NIST SC-* | `tests/test_compliance.py::test_controles_por_categoria_owasp (usa A02:2025, no TLS) + tests/test_advanced.py::test_owasp_etiqueta_por_modulo (prueba TLS/HTTPS -> A04:2025)` | ⚠️ PARTIAL |
| compliance-mapping | hallazgo sin mapeo conocido: hallazgo informativo sin control asociado -> sin controles y no falla | `tests/test_compliance.py::test_sin_owasp_no_mapea y tests/test_compliance.py::test_categoria_desconocida_no_falla` | ✅ COMPLIANT |
| compliance-mapping | sección de compliance: escaneo con hallazgos mapeados -> resumen 'Controles afectados' por marco con el conteo | `tests/test_report.py::test_render_texto_muestra_cwe_cvss_y_compliance + tests/test_compliance.py::test_resumen_agrupa_por_marco_y_control` | ⚠️ PARTIAL |
| owasp-2025-mapping | catálogo actualizado: contiene A03:2025 Software Supply Chain Failures y A10:2025 Mishandling of Exceptional Conditions, y NO contiene A10:2021 SSRF | `—` | ❌ UNTESTED |
| owasp-2025-mapping | SSRF ahora es A01: hallazgo de indicio SSRF (metadata endpoint) → categoría A01:2025 | `tests/test_advanced.py::test_owasp_normaliza_ssrf_2021_a_a01_2025 (línea 82)` | ✅ COMPLIANT |
| owasp-2025-mapping | componente vulnerable es A03: hallazgo de librería JS obsoleta (retire.js) → categoría A03:2025 | `tests/test_advanced.py::test_owasp_normaliza_componentes_2021_a_supply_chain_2025 (línea 89)` | ✅ COMPLIANT |
| owasp-2025-mapping | stack trace es A10: hallazgo de stack trace expuesto → categoría A10:2025 | `—` | ❌ UNTESTED |
| access-control-testing | read-IDOR: GET /api/user/1002 responde 2xx con datos de otro usuario -> IDOR de lectura ALTO (A01:2025) | `test_idor_objeto_ajeno_accesible_es_alto` | ✅ COMPLIANT |
| access-control-testing | write-IDOR (proof no destructiva): PUT /api/user/1002 aceptada (2xx) sin ser el dueño -> IDOR de escritura ALTO (A01:2025) | `—` | ❌ UNTESTED |
| access-control-testing | acceso correctamente denegado: el objeto ajeno responde 403/404 -> no se reporta hallazgo | `test_idor_denegado_no_reporta` | ✅ COMPLIANT |
| access-control-testing | panel admin sin control: /admin(/users) responde 200 sin sesión -> control de acceso roto ALTO (A01:2025) | `test_forced_browsing_panel_sin_sesion_es_alto` | ✅ COMPLIANT |
| authentication-testing | mensajes diferenciados: usuario probable vs aleatorio con mensaje/código consistente distinto => enumeración MEDIO | `test_enumeracion_por_respuesta_diferencial (positivo) y test_sin_diferencia_no_enumera (negativo)` | ✅ COMPLIANT |
| authentication-testing | default creds válidas: alguna autentica => credenciales por defecto ALTO con la combinación | `test_default_creds_validas_es_alto` | ✅ COMPLIANT |
| authentication-testing | ninguna default cred funciona => no se reporta hallazgo | `—` | ❌ UNTESTED |
| authentication-testing | sin throttling: serie de intentos fallidos sin 429 ni retardo creciente => ausencia de rate-limit MEDIO | `test_sin_rate_limit_es_medio (positivo) y test_con_rate_limit_no_reporta (negativo, 429 => sin hallazgo)` | ✅ COMPLIANT |
| authentication-testing | id de sesión no rota: cookie de sesión pre-login que no cambia tras autenticarse => posible session fixation MEDIO | `—` | ❌ UNTESTED |
| ssrf-header-injection | metadata reflejada (inyectar http://169.254.169.254/latest/meta-data/ -> SSRF ALTO A01:2025) | `tests/test_ssrf.py::test_ssrf_por_parametro_es_alto` | ✅ COMPLIANT |
| ssrf-header-injection | sin SSRF (parámetro no dispara petición server-side -> no reporta) | `tests/test_ssrf.py::test_sin_ssrf_ni_reflejo_no_reporta` | ✅ COMPLIANT |
| ssrf-header-injection | host reflejado (Host: evil -> respuesta/redirect contiene evil -> Host Header Injection MEDIO) | `tests/test_ssrf.py::test_host_header_reflejado_es_medio` | ✅ COMPLIANT |
| ssrf-header-injection | reflejo cacheable (X-Forwarded-Host reflejado + Cache-Control: public -> cache poisoning MEDIO) | `tests/test_ssrf.py::test_cache_poisoning_cuando_cacheable` | ✅ COMPLIANT |
| supply-chain-sbom | SBOM válido: escaneo detectó jQuery 1.8 y Apache 2.4.29 → --sbom sbom.json produce CycloneDX 1.5 válido con esos componentes y versión | `tests/test_sbom.py::test_sbom_cyclonedx_valido_con_componentes + tests/test_sbom.py::test_componentes_de_findings_extrae_nombre_version` | ⚠️ PARTIAL |
| supply-chain-sbom | sin componentes: escaneo sin tecnologías versionadas → --sbom emite SBOM válido con lista de componentes vacía | `tests/test_sbom.py::test_sbom_vacio_es_valido` | ⚠️ PARTIAL |
| supply-chain-sbom | paquete interno referenciado: el frontend referencia @corp/internal-utils → se reporta indicio de dependency confusion BAJO (A03:2025) | `tests/test_sbom.py::test_analizar_reporta_dependency_confusion + tests/test_sbom.py::test_detecta_paquete_interno_scoped (+ negativo: test_analizar_limpio_no_reporta)` | ⚠️ PARTIAL |
| error-handling-audit | stack trace expuesto: endpoint con tipo inválido → respuesta con firma de traza → fuga MEDIO (A10:2025) | `tests/test_error_audit.py::test_stack_trace_expuesto_es_medio (+ unitario ::test_detecta_stack_trace)` | ✅ COMPLIANT |
| error-handling-audit | error manejado limpiamente: 400/500 genérico sin detalle → sin hallazgo | `tests/test_error_audit.py::test_error_limpio_no_reporta` | ✅ COMPLIANT |
| error-handling-audit | debug de framework: panel interactivo (Werkzeug, Symfony, Rails) → modo debug en producción ALTO (A10:2025) | `tests/test_error_audit.py::test_modo_debug_es_alto (+ ::test_detecta_modo_debug)` | ⚠️ PARTIAL |
| resource-consumption | sin límite observado: ráfaga completa sin 429 ni cabeceras de rate-limit → ausencia de rate-limiting BAJO (API4:2023) | `tests/test_rate_limit.py::test_sin_rate_limit_es_bajo (+ ::test_respeta_burst)` | ⚠️ PARTIAL |
| resource-consumption | rate-limit presente: 429 o X-RateLimit-Remaining → sin hallazgo (o INFO) | `tests/test_rate_limit.py::test_con_429_no_reporta y ::test_con_header_ratelimit_no_reporta` | ✅ COMPLIANT |

---

## Correctness (estructural) — requirements por spec

| Spec | Requirement | Status |
|------|-------------|--------|
| http-transport | Request con método y cuerpo | ✅ implemented |
| http-transport | Passthrough de sesión | ✅ implemented |
| http-transport | Throttle de cortesía | ✅ implemented |
| active-injection-depth | Inyección en formularios y POST | ✅ implemented |
| active-injection-depth | Cobertura por-parámetro | ✅ implemented |
| active-injection-depth | SQLi ciega basada en tiempo | ✅ implemented |
| active-injection-depth | Clases de inyección adicionales | ✅ implemented |
| csrf-detection | Formulario sin token anti-CSRF | ✅ implemented |
| api-surface-discovery | Documentación OpenAPI/Swagger expuesta | ⚠️ partial |
| api-surface-discovery | GraphQL introspection habilitada | ✅ implemented |
| jwt-analysis | Debilidades estructurales de JWT (alg:none ALTO, HS256 secreto trivial ALTO, sin exp MEDIO, exp vencido BAJO) | ✅ implemented |
| cloud-misconfig | Almacenamiento cloud público | ⚠️ partial |
| cloud-misconfig | Referencia a metadata cloud | ✅ implemented |
| mail-transport-security | Política MTA-STS | ✅ implemented |
| mail-transport-security | Reporte TLS-RPT | ✅ implemented |
| finding-classification | Campos CWE y CVSS en el modelo | ✅ implemented |
| finding-classification | Asignación de CWE/CVSS por tipo de hallazgo | ✅ implemented |
| baseline-suppression | Archivo de baseline (--baseline PATH, def .wvsignore; huella estable de modulo/hallazgo/referencia) | ✅ implemented |
| baseline-suppression | Generación de baseline (--write-baseline PATH) | ✅ implemented |
| compliance-mapping | Etiquetado de compliance por hallazgo (PCI-DSS, ISO 27001, NIST 800-53 derivados de OWASP/CWE) | ⚠️ partial |
| compliance-mapping | Resumen de cumplimiento en el reporte (agrupado por control incumplido, por marco) | ✅ implemented |
| owasp-2025-mapping | Catálogo de categorías 2025 | ✅ implemented |
| owasp-2025-mapping | Remapeo de hallazgos existentes | ✅ implemented |
| owasp-2025-mapping | Errores excepcionales bajo A10 | ✅ implemented |
| access-control-testing | IDOR / BOLA por manipulación de object-ID | ⚠️ partial |
| access-control-testing | Forced browsing autenticado | ✅ implemented |
| authentication-testing | Enumeración de usuarios | ✅ implemented |
| authentication-testing | Credenciales por defecto | ✅ implemented |
| authentication-testing | Ausencia de rate-limit en login | ✅ implemented |
| authentication-testing | Session fixation | ❌ missing |
| ssrf-header-injection | SSRF activo sobre parámetros tipo URL | ✅ implemented |
| ssrf-header-injection | Host Header Injection | ✅ implemented |
| ssrf-header-injection | Cache poisoning básico | ⚠️ partial |
| supply-chain-sbom | SBOM CycloneDX | ⚠️ partial |
| supply-chain-sbom | Indicio de dependency confusion | ⚠️ partial |
| error-handling-audit | Stack traces y errores verbosos | ⚠️ partial |
| error-handling-audit | Modo debug activo | ⚠️ partial |
| resource-consumption | Detección de rate-limiting | ⚠️ partial |

---

## Issues — CRITICAL (9)

- **[cloud-misconfig]** Escenario 'bucket privado' (bucket referenciado que devuelve AccessDenied -> no se reporta) SIN test: test_contenido_limpio_no_reporta no referencia ningún bucket, así que la rama no-listable de cloud.py:61 nunca se ejercita y una regresión que reportara ALTO ante cualquier respuesta pasaría desapercibida.
- **[owasp-2025-mapping]** Escenario 'catálogo actualizado' sin test: nada asserta el contenido de owasp.CATEGORIAS (/home/war-machine/Documents/repos/webSecurityAnalizer/src/webvulnscanner/owasp.py:14-25). No existe tests/test_owasp.py.
- **[owasp-2025-mapping]** Escenario 'stack trace es A10' sin test: el override de owasp.py:82-83 tiene 0% de ejecución en la suite (línea 83 = único miss del módulo). Ningún test asserta owasp=='A10:2025' en ninguna parte (ni en tests/test_error_audit.py).
- **[access-control-testing]** Escenario 'write-IDOR (proof no destructiva)' del requirement 'IDOR / BOLA por manipulación de object-ID' NO está implementado ni cubierto por tests. El requirement exige SHOULD probar métodos mutantes (POST/PUT/PATCH/DELETE) con MUST proof no destructiva, pero access_control.py solo prueba GET y el docstring (líneas 4-5) delega explícitamente la escritura a revisión manual. Contradicción directa spec vs. implementación.
- **[authentication-testing]** Requirement 'Session fixation' NO implementado: no existe función de detección de rotación de id de sesión y analizar() (auth_test.py:123-127) no la invoca. El escenario 'id de sesión no rota' queda sin implementación y sin test.
- **[supply-chain-sbom]** Requirement 'SBOM CycloneDX' incumple una cláusula explícita: el documento debe llevar 'y sus CVEs conocidos', pero generar() (src/webvulnscanner/sbom.py, líneas 26-36) solo emite components con type/name/version — no existe ninguna clave `vulnerabilities` ni ninguna referencia a CVE en el SBOM, pese a que 'CVE' sí está en _MODULOS_COMP para extraer nombre/versión.
- **[supply-chain-sbom]** El WHEN de ambos escenarios del requirement 'SBOM CycloneDX' es la invocación CLI `--sbom PATH`, y esa ruta no tiene ningún test: tests/test_cli.py no menciona 'sbom' (0 coincidencias), por lo que cli.py:148-151 (sbom.generar(sbom.componentes_de(result.findings)) + Path(args.sbom).write_text(...)) nunca se ejecuta en la suite. El THEN 'el archivo es CycloneDX 1.5 válido' está probado solo sobre el dict en memoria, nunca sobre un archivo escrito.
- **[error-handling-audit]** Requirement 'Modo debug activo': el indicador `X-Debug` citado en la spec no está implementado — `error_audit.analizar` (src/webvulnscanner/modules/error_audit.py:44-81) solo evalúa `r.body`, nunca `r.header(...)`. Búsqueda 'X-Debug' en src/ = 0 coincidencias.
- **[resource-consumption]** Requirement 'Detección de rate-limiting': el flag `--rl-burst` exigido por la spec no existe. `cli.py` no lo registra (no aparece en ningún `add_argument`) y `orchestrator.py:205` invoca `rate_limit.analizar(dominio)` sin propagar burst; la configurabilidad existe solo como kwarg de Python. Además el docstring de `src/webvulnscanner/modules/rate_limit.py:4` afirma que `--rl-burst` existe, lo que es documentación incorrecta.

## Issues — WARNING (52)

- **[http-transport]** Escenario 'no fuga en log': el test que lo cubre (tests/test_net.py:171) es vacuo — net.py no emite ningún LogRecord, así que la aserción `"SUPERSECRETO" not in caplog.text` pasaría igual con cualquier implementación. El WHEN de la spec ('se emite log de progreso') apunta al logger del orchestrator, que ningún test ejercita con una sesión activa.
- **[http-transport]** `Sesion` es un dataclass con `headers` en el repr por defecto (net.py:73; solo `_ultima` lleva `repr=False`), de modo que cualquier `log.debug("%s", sesion)`, traceback o `repr()` futuro imprimiría el bearer/cookie en claro. Hoy nadie lo hace, pero nada lo impide y ningún test lo previene.
- **[http-transport]** modules/tls.py:245 `_redireccion_https()` hace una petición al objetivo con `urllib.request` directo (opener sin redirecciones), saltándose `net.request`: esa petición no lleva los headers de sesión ni pasa por `_throttle`, lo que debilita tanto el 'toda petición incluye Cookie' como el 'limitar la tasa de peticiones por objetivo'.
- **[http-transport]** El requirement enumera GET/POST/PUT/DELETE/PATCH pero solo hay tests para GET y POST (test_request_get_por_defecto, test_request_post_form). PUT/DELETE/PATCH funcionan por passthrough a urllib y no se usan en ningún módulo del repo — no hay evidencia de test para ellos.
- **[http-transport]** El throttle es best-effort bajo concurrencia: `_ultima` se lee y escribe sin lock desde los hilos del ThreadPoolExecutor (el propio comentario en net.py:79-82 lo reconoce). El test solo cubre el caso secuencial.
- **[active-injection-depth]** Escenario 'form GET también cubierto' (Requirement: Inyección en formularios y POST) no tiene test: la rama GET-desde-formulario está implementada pero ningún test usa un Form con method='get'.
- **[active-injection-depth]** Escenario 'retardo confirmado' (Requirement: SQLi ciega basada en tiempo) solo tiene cobertura parcial: se pinea el helper _es_retardo pero no hay test de integración que produzca un Finding real de SQLi ciega time-based vía analizar_inyeccion con latencia simulada.
- **[csrf-detection]** Detección de SameSite frágil ante múltiples cookies: `net.py:162` construye los headers con `{k.lower(): v for k, v in resp.headers.items()}`, así que varias cabeceras `Set-Cookie` colapsan y solo sobrevive la última. Si el sitio emite `Set-Cookie: sid=..; SameSite=Lax` y luego `Set-Cookie: ab=..` (sin SameSite), `csrf.py:41` no verá 'samesite' y reportará MEDIO; en el caso inverso reportará BAJO aunque la cookie de sesión no tenga SameSite. Ningún test cubre el caso multi-cookie.
- **[csrf-detection]** La mitigación se evalúa solo sobre la respuesta raíz (`respuesta`), no sobre la respuesta que realmente entrega la cookie de sesión del form ni sobre las páginas crawleadas; un login que setea la cookie en otra ruta no se considera. No hay test para ese escenario (queda fuera de lo escrito en la spec).
- **[api-surface-discovery]** Requirement 1: la spec enumera `/swagger-ui.html` entre las rutas conocidas y `_OPENAPI_PATHS` no la incluye; adicionalmente `_doc_openapi()` solo valida JSON (`json.loads` + clave `openapi`/`swagger`), por lo que una Swagger UI HTML nunca produciría hallazgo aunque se añadiera la ruta. La spec usa SHOULD, pero la cobertura de rutas es 4/5 respecto al texto.
- **[api-surface-discovery]** Ningún test afirma el nivel de riesgo del hallazgo OpenAPI (`Risk.BAJO`), ni el campo `evidencia`, ni el tag `owasp="A05:2021"` de ninguno de los dos hallazgos; un cambio accidental de severidad u OWASP no rompería la suite.
- **[api-surface-discovery]** Línea 45 sin cubrir (`if doc is None: continue`): no hay test para una respuesta 200 que NO sea un documento OpenAPI (caso realista de SPA que devuelve index.html con 200 en cualquier ruta). Es justamente el camino que evita falsos positivos y no está pineado.
- **[api-surface-discovery]** Líneas 73-74 sin cubrir: el fallback `n = 0` ante `JSONDecodeError/KeyError/TypeError` en el parseo del `__schema` (cuerpo con las cadenas '__schema' y 'types' pero JSON inválido o estructura distinta) no tiene test.
- **[jwt-analysis]** Escenario "secreto débil HS256": el THEN pide el secreto "redactado parcialmente" y la implementación lo publica íntegro en `Finding.evidencia` (jwt_audit.py:103). No existe redacción en ningún punto del pipeline (búsqueda de 'redact|redacc|***' en src/ -> 0 coincidencias), así que el secreto viaja tal cual a report/sarif/informe.
- **[jwt-analysis]** El Purpose de la spec dice "JWTs que aparecen en contenido servido al cliente o en cookies/headers", pero `analizar` (jwt_audit.py:133-153) solo cosecha del body del home y de hasta `max_scripts=15` scripts. No inspecciona cabeceras de respuesta ni Set-Cookie. Ningún test cubre esa fuente porque no está implementada.
- **[jwt-analysis]** La cosecha desde scripts no está ejercitada: test_analizar_cosecha_tokens_del_contenido pasa `set()` vacío, así que el bucle de scripts, el recorte por `max_scripts` y la lógica de derivación de ruta (`url.split(dominio, 1)[-1]`) quedan sin test.
- **[cloud-misconfig]** Escenario 'metadata endpoint en JS' cubierto solo parcialmente: el contenido llega por el home, nunca por un script; el bucle de scripts (cloud.py:47-51) queda a 0% de cobertura pese a que en producción el orquestador lo alimenta con `crawl.scripts` (orchestrator.py:182 `cloud.analizar(dominio, crawl.scripts)`).
- **[cloud-misconfig]** La verificación de listado público es efectivamente solo-S3: `_RE_BUCKET` descarta el path, por lo que para GCS se consulta 'https://storage.googleapis.com' (raíz del proveedor) y para Azure 'https://cuenta.blob.core.windows.net' sin container; el requirement pide verificar el listado para los tres proveedores.
- **[cloud-misconfig]** `fetch_url()` (cloud.py:36-39) nunca se ejecuta de verdad: los 3 tests de comportamiento lo monkeypatchean, así que el mapeo urlparse -> `fetch(netloc, path)` (que además descarta query string, necesario para el listado de Azure `?restype=container&comp=list`) no está verificado.
- **[mail-transport-security]** Rama no cubierta por ningún test: línea 49 de src/webvulnscanner/modules/mail_transport.py, el fallback Finding('MTA-STS','MTA-STS declarado en DNS pero sin política válida',Risk.BAJO) — se alcanza cuando el TXT _mta-sts existe pero el fetch falla/devuelve !=200 o la policy no define 'mode'. Confirmado con `pytest tests/test_mail_transport.py --cov=webvulnscanner.modules.mail_transport --cov-report=term-missing` -> Missing: 49.
- **[mail-transport-security]** Los 4 tests de escenario assertan únicamente el enum Risk (OK/BAJO/INFO) vía el helper _nivel(); ninguno asserta el texto del hallazgo ni el tag owasp='A05:2021'. Un cambio de redacción o la pérdida del tag OWASP no rompería ningún test.
- **[finding-classification]** tests/test_classify.py::test_clasifica_xss_con_cwe_79 asserta `score >= 6.0` mientras la spec exige `>= 6.1`; el valor real es 6.1, pero la aserción deja 0.1 de holgura y no detectaría una degradación del vector mapeado para XSS.
- **[finding-classification]** La llamada `classify.clasificar(...)` en /home/war-machine/Documents/repos/webSecurityAnalizer/src/webvulnscanner/orchestrator.py:235 no tiene ningún test de integración: borrarla no rompería la suite.
- **[baseline-suppression]** Escenario 'hallazgo suprimido': la parte del THEN sobre el conteo de riesgo (exit code 2 vs 0 tras suprimir el único hallazgo ALTO) no está cubierta por ningún test; solo por la posición del código en cli.py.
- **[baseline-suppression]** El default documentado en la spec ('.wvsignore si existe') está implementado en cli.py:157 pero no tiene test: nadie verifica que se autodetecte ni que --baseline gane sobre el default.
- **[baseline-suppression]** baseline.cargar() no valida el formato de la huella: cualquier token inicial se acepta como huella (test_cargar_ignora_comentarios_y_vacios pasa con 'abc123', que no es un sha256[:16] válido). Un baseline corrupto se cargaría en silencio.
- **[compliance-mapping]** Escenario 'TLS obsoleto': la cadena TLS->A04->PCI 4.1/ISO/NIST SC-* nunca se asserta end-to-end; se prueba el eslabón OWASP (test_advanced.py:69) y el eslabón de mapeo genérico (con otra categoría, A02) por separado.
- **[compliance-mapping]** Divergencia textual con la spec: la spec pide 'ISO A.10' y la implementación emite 'A.8.24'. Es la traducción correcta a ISO 27001:2022, pero la spec no lo autoriza explícitamente (el '(o equivalente)' solo califica a PCI-DSS).
- **[compliance-mapping]** Requirement 1 dice 'OWASP/CWE' pero controles_de() ignora por completo f.cwe; hallazgos con CWE y sin categoría OWASP quedan sin controles.
- **[compliance-mapping]** La sección HTML informe.py:297 _seccion_compliance() no está cubierta por tests/test_informe.py; solo la variante texto de report.py tiene una aserción (y débil).
- **[compliance-mapping]** Los controles no viajan en Finding.to_dict(), así que el JSON y el SARIF no contienen la evidencia de compliance por hallazgo — solo el agregado en el texto/HTML.
- **[owasp-2025-mapping]** owasp.CATEGORIAS es código muerto: no lo importa ningún módulo. report.py:26-27, informe.py:210-214 y sarif.py:42 imprimen solo el código (f.owasp), nunca el nombre oficial, así que 'Software Supply Chain Failures' / 'Mishandling of Exceptional Conditions' jamás llegan al reporte y el requisito 'nombres oficiales' no es observable end-to-end.
- **[owasp-2025-mapping]** El requisito de supply-chain está probado solo por la vía retire.js. Las otras fuentes citadas en la spec (CVE, Fingerprint con versión, Shodan, SBOM → A03:2025 vía _POR_MODULO y sbom.py:88) no tienen ninguna aserción de categoría en tests/test_sbom.py ni tests/test_stack.py.
- **[owasp-2025-mapping]** El sistema convive con dos generaciones de códigos: 18 emisiones de owasp='Axx:2021' siguen vivas en src (mail_transport, jwt_audit, auth_test, webchecks, api_discovery, secrets, retire_js, csrf, cloud). Funciona porque _REMAP cubre las 10 claves, pero cualquier módulo nuevo que emita un código 2021 fuera del mapa quedaría sin normalizar y ningún test lo detectaría.
- **[access-control-testing]** El requirement 'Forced browsing autenticado' pide solicitar rutas 'con y sin sesión', pero _forced_browsing solo solicita SIN sesión (sin_sesion=True); no hay comparación diferencial con/sin sesión ni detección de exposición de función admin estando autenticado con rol insuficiente.
- **[access-control-testing]** La detección IDOR solo prueba el vecino +1 (_vecino suma 1); el requirement menciona ±1 u 'otro id'. No se prueba el vecino -1 ni identificadores alternativos, reduciendo la cobertura de manipulación de object-ID.
- **[authentication-testing]** Escenario 'ninguna default cred funciona' (Credenciales por defecto) sin test que fije el negativo: ningún assert verifica la ausencia del hallazgo de credenciales por defecto (UNTESTED).
- **[authentication-testing]** Rate-limit: la detección solo cubre HTTP 429; la señal 'ni retardo creciente' del escenario no se detecta en _rate_limit ni se prueba (cobertura parcial de la condición WHEN).
- **[authentication-testing]** El parámetro 'producto' de analizar() (auth_test.py:118) se ignora: la spec pide probar 'las credenciales propias de la tecnología detectada', pero _default_creds usa un set genérico fijo (_DEFAULTS).
- **[ssrf-header-injection]** La rama de 'parámetros descubiertos' (crawl.params) del Requirement 1 no está cubierta por un test dedicado: todos los tests pasan Crawl() vacío, por lo que solo se ejercita la lista _PARAMS_SSRF por defecto.
- **[ssrf-header-injection]** Cache poisoning: la spec nombra X-Forwarded-Scheme como header no cacheable a detectar, pero _probar_host_header nunca lo envía ni lo comprueba (solo Host / X-Forwarded-Host).
- **[supply-chain-sbom]** Heurística de dependency confusion incompleta y con falsos positivos: el requirement pide marcar paquetes 'que parezcan internos (scoped @empresa/…, nombres no publicados en registros públicos)'. La implementación (_RE_SCOPED en sbom.py) marca CUALQUIER paquete con scope. Verificado ejecutando el módulo: '@babel/core' produce indicio. No hay allowlist de scopes públicos ni consulta a registro.
- **[supply-chain-sbom]** Ningún test asserta f.owasp == 'A03:2025' en los findings de dependency confusion, que es parte literal del THEN del escenario. El código sí lo fija (sbom.py, kwarg owasp='A03:2025') y owasp.categoria() lo preserva, pero no hay pin de regresión.
- **[supply-chain-sbom]** Cobertura del módulo 87% (medido: 47 stmts, 6 miss). Líneas sin cubrir: 46 (continue cuando _RE_COMP no matchea), 50 (rama de deduplicado por (nombre, version)) y 66-70 (bucle de descarga de scripts en analizar(): derivación `ruta = url.split(dominio,1)[-1] if dominio in url else url`, el fetch con max_body=400_000 y el tope max_scripts=15). El módulo se registra en el orquestador (orchestrator.py:77 y :184 → sbom.analizar(dominio, crawl.scripts)) pasando crawl.scripts real, justo la ruta sin cobertura; tests/test_orchestrator.py:40 la mockea con lambda *a, **k: [].
- **[supply-chain-sbom]** El comentario del test test_componentes_de_findings_extrae_nombre_version es engañoso: el Finding('Reconocimiento', 'IP resuelta 1.2.3.4', ...) lleva el comentario '# sin versión → se ignora', pero en realidad se descarta por el filtro `f.modulo not in _MODULOS_COMP` antes de llegar al regex (por eso la línea 46 queda sin cubrir). Es decir, el lookahead anti-IP (?!\.\d) —que sí funciona, lo verifiqué con un Finding de módulo 'Fingerprint'— no está realmente pinneado por ningún test.
- **[error-handling-audit]** Requirement 'Stack traces y errores verbosos': los vectores 'parámetro faltante' y 'método inesperado' no se ejercitan; las 5 sondas de `_SONDAS` son todas GET sobre path/query.
- **[error-handling-audit]** Escenario 'debug de framework': cobertura de test limitada a Werkzeug; Symfony y Rails quedan sin test pese a estar nombrados en el Given.
- **[error-handling-audit]** Ningún test asserta la etiqueta `owasp='A10:2025'` de los Findings, que es la parte taxonómica del THEN de ambos escenarios de reporte.
- **[error-handling-audit]** El respeto a `Sesion.delay` (mencionado en el Purpose como activo suave/cortés) se hereda de `net.request` → `_throttle` (src/webvulnscanner/net.py:96-102,153), pero los tests monkeypatchean `request`, así que no hay verificación directa para este módulo.
- **[resource-consumption]** El THEN del escenario 'sin límite observado' pide atribución API4:2023 y la implementación emite `owasp='A02:2025'`; no hay ningún campo ni test que registre la categoría API Top 10 en el Finding.
- **[resource-consumption]** 'sin caída de tasa' del requirement no está implementado: `_tiene_rate_limit` (rate_limit.py:20-23) solo mira status 429 y cabeceras; un throttling silencioso por degradación de latencia o descarte pasaría inadvertido y produciría un falso 'Ausencia de rate-limiting'.
- **[resource-consumption]** El respeto a `Sesion.delay` (MUST del requirement) es correcto por delegación a `net.request`, pero ningún test de tests/test_rate_limit.py lo verifica: los cuatro monkeypatchean `rate_limit.request`, saltándose `_throttle`.

## Issues — SUGGESTION (65)

- **[http-transport]** Convertir test_sesion_no_filtra_secreto_en_log en un pin real: ejercitar `orchestrator.run_scan` (o el CLI) con `Sesion(headers={"Authorization": "Bearer SUPERSECRETO"})` capturando el logger 'webvulnscanner', de modo que el test fallaría si alguien añade un `log.debug("sesion=%s", sesion)`.
- **[http-transport]** Añadir `repr=False` (o un `__repr__` que redacte) al campo `headers` de `Sesion` en net.py:73, y un test que asegure que `repr(Sesion(headers={"Authorization": "Bearer X"}))` no contiene el token. Es la defensa barata contra la fuga por traceback.
- **[http-transport]** Redirigir `_redireccion_https()` (modules/tls.py:240) a `net.request(..., method="GET")` con un parámetro `seguir_redirecciones=False`, para que toda petición al objetivo pase por la única frontera de red y respete sesión + throttle.
- **[http-transport]** Añadir un test parametrizado sobre `method` in {"PUT", "DELETE", "PATCH"} que compruebe `req.get_method()`, cerrando la enumeración explícita del requirement con una sola prueba barata.
- **[http-transport]** En test_throttle_espacia_peticiones, subir el umbral a `d >= 0.5` (o afirmar `sum(dormidas) >= 1.0`) para que la aserción refleje literalmente el THEN de la spec sin perder la ventaja del sleep mockeado.
- **[active-injection-depth]** Reconciliar la spec con la implementación en SSTI: el escenario cita {{7*7}}/49 pero el código usa {{113*131}}/14803 (mejor para evitar falsos por azar). Actualizar el texto de la spec o añadir nota de racional.
- **[active-injection-depth]** Añadir un test de integración de blind SQLi que parchee active.fetch/active.request con un time.sleep condicional al payload de retardo y verifique el Finding 'SQL injection ciega (time-based)' Risk.ALTO.
- **[active-injection-depth]** Añadir un test con Form(method='get') que verifique que el payload viaja en la query-string (fetch) y no en data (request).
- **[active-injection-depth]** En test_xss_via_post_form aseverar explícitamente Risk.ALTO además de la presencia de 'POST'.
- **[csrf-detection]** `SameSite=None` se trata como mitigación: el check es un substring `"samesite" in header` (csrf.py:41), y `SameSite=None` NO mitiga CSRF (permite envío cross-site). Convendría exigir `samesite=lax` o `samesite=strict` y añadir un test negativo `test_samesite_none_no_mitiga`.
- **[csrf-detection]** Añadir tests parametrizados para los nombres de token restantes de la spec (`csrf`, `authenticity_token`, `__requestverificationtoken`, `xsrf`) y para variantes de mayúsculas (`_TOKEN`, `X-CSRF-Token`), ya que `_tiene_token()` normaliza con `.lower()` pero eso no está anclado por ningún test.
- **[csrf-detection]** Assertar en `test_samesite_baja_a_bajo` que `descripcion` contiene '(mitigado parcialmente por SameSite)' y que `owasp == "A01:2021"`, para pinear el contenido del Finding y no solo el nivel de riesgo.
- **[csrf-detection]** No hay test de integración que confirme que 'csrf' se ejecuta sin `--authorized` (orchestrator.py:70 vs `MODULOS_ACTIVOS`); un test sobre `MODULOS` protegería esa garantía del Purpose ante refactors.
- **[api-surface-discovery]** Añadir aserciones explícitas de contrato en los tests existentes: `f.riesgo in (Risk.BAJO, Risk.INFO)` y `f.evidencia == "3 endpoints"` en test_openapi_expuesto_se_reporta; `f.evidencia == "2 tipos"` en test_graphql_introspeccion_abierta_es_medio.
- **[api-surface-discovery]** Añadir un test de falso positivo: 200 con cuerpo HTML/JSON no-OpenAPI en `/openapi.json` debe devolver [] (cubre línea 45).
- **[api-surface-discovery]** Decidir explícitamente sobre `/swagger-ui.html`: o bien añadir la ruta con detección por marcador HTML (p.ej. 'swagger-ui' en el body), o bien actualizar la spec para eliminarla y reflejar `/swagger/v1/swagger.json` que sí está implementada.
- **[api-surface-discovery]** `api_fuzz.py` importa los internos `api_discovery._OPENAPI_PATHS` y `api_discovery._doc_openapi` (líneas 37 y 39): considerar promoverlos a API pública del módulo para que el acoplamiento entre fases quede explícito y verificable.
- **[jwt-analysis]** Si se quiere honrar el THEN al pie de la letra, redactar el secreto en la evidencia (p. ej. `secreto: se****`) y añadir un test que asserte que el valor completo NO aparece. Alternativa con tradeoff: dejarlo íntegro (los secretos son de diccionario público y el valor exacto es accionable para el pentester) y corregir el texto de la spec para que deje de pedir redacción — hoy spec e implementación se contradicen.
- **[jwt-analysis]** Añadir un test para la deduplicación por `vistos` en `analizar` (mismo token repetido en home y en un script debería producir hallazgos una sola vez) y otro con `scripts` no vacío para cubrir el bucle de fetch.
- **[jwt-analysis]** El regex `_RE_JWT` (jwt_audit.py:25) exige prefijo `eyJ` en header Y payload; un JWT cuyo JSON no empiece exactamente por `{"` (p. ej. con espacio inicial) no se cosecha. No es un fallo de la spec, pero conviene documentarlo o relajar el patrón.
- **[cloud-misconfig]** Añadir un test 'bucket referenciado devuelve AccessDenied' (home con URL de bucket + `fetch_url` stub devolviendo '<Error><Code>AccessDenied</Code></Error>') y assertar `== []` o el INFO opcional que permite la spec.
- **[cloud-misconfig]** Reforzar test_bucket_s3_publico_listable_es_alto assertando que el nombre/URL del bucket aparece en `f.hallazgo` o `f.referencia` ('mibucket'), para pinear la parte 'con el nombre' del THEN.
- **[cloud-misconfig]** Añadir un caso que llame `cloud.analizar('ej.com', {'https://ej.com/app.js'})` con un stub de `fetch` que devuelva el JS con 169.254.169.254 solo para esa ruta, cubriendo cloud.py:47-51 y la heurística de recorte de ruta (que para scripts de host externo pasa la URL completa como `ruta` a `fetch(dominio, ruta)`).
- **[cloud-misconfig]** Conservar el path al construir la URL del bucket (GCS: primer segmento; Azure: container) y contemplar el marcador 'EnumerationResults' para Azure, de lo contrario documentar en la spec que la verificación de listado aplica solo a S3.
- **[mail-transport-security]** El requirement de MTA-STS menciona validar el modo 'none', pero mode:none cae en el fallback cuyo mensaje dice 'la política no es accesible o no define mode' — descripción imprecisa para ese caso; convendría una rama explícita para 'none'.
- **[mail-transport-security]** Asimetría: MTA-STS enforce emite un Finding Risk.OK, pero un TLS-RPT presente no emite nada (ni OK). Añadir un Finding OK para _smtp._tls presente haría el reporte consistente y permitiría un test del camino positivo.
- **[mail-transport-security]** La spec dice recuperar la policy por HTTPS; fetch() (src/webvulnscanner/net.py:176) delega en request() que intenta HTTPS y luego HTTP como fallback. Para MTA-STS una policy servida por HTTP plano no es válida según RFC 8461; podría forzarse solo-HTTPS en esta llamada.
- **[mail-transport-security]** Añadir un test para el fallback (TXT presente + fetch None/404 o body sin 'mode:') cerraría la línea 49 y llevaría el módulo a 100%.
- **[finding-classification]** Endurecer test_clasifica_xss_con_cwe_79 a `assert fs[0].cvss["score"] == 6.1` (o al menos `>= 6.1`) para alinearlo con el THEN de la spec.
- **[finding-classification]** classify.py:29 (`return entero / 100_000.0`, rama de múltiplo exacto de _roundup) no está cubierta por ningún test; falta un vector cuyo score bruto caiga exacto en un decimal.
- **[finding-classification]** El matching por subcadena en classify.clasificar es sensible al texto: el hallazgo real de CSP inseguro es "CSP contiene 'unsafe-inline'" (headers.py:114 hace `msg.split(":")[0]`), que NO contiene la subcadena "content-security-policy" del mapa, así que esos hallazgos quedan sin CWE/CVSS pese a existir la entrada CWE-693. Añadir "csp" al mapa o clasificar también sobre `descripcion`.
- **[finding-classification]** Riesgo latente de colisión de orden: la entrada ("xss", CWE-79) es la primera de _MAPA, así que cualquier hallazgo futuro que mencione XSS en su título (headers, retire.js) se clasificaría como CWE-79 en vez de su CWE propio. Conviene un test que pinnee la precedencia esperada.
- **[finding-classification]** Añadir un test de orquestación (tests/test_orchestrator.py) que verifique que tras `escanear` un hallazgo de inyección sale con cwe/cvss poblados, para pinnear el wiring de orchestrator.py:235.
- **[baseline-suppression]** Añadir un test en tests/test_cli.py con el fixture fake_scan existente: escanear con --write-baseline en tmp_path y volver a correr con --baseline apuntando a ese archivo, asertando exit code 0 (hoy 2) y que el hallazgo no aparece en capsys — cerraría el único hueco real de esta spec.
- **[baseline-suppression]** Cubrir el fallback '.wvsignore' con monkeypatch.chdir(tmp_path) para probar la autodetección.
- **[baseline-suppression]** La huella no incluye el dominio escaneado: un mismo .wvsignore compartido suprimiría el hallazgo en todos los targets. Considerar documentarlo o incluir result.dominio en la huella.
- **[compliance-mapping]** Añadir en tests/test_compliance.py un test explícito del escenario de la spec: Finding('TLS/HTTPS', 'Protocolo TLS 1.0 habilitado', ...) -> owasp.etiquetar() -> controles_de() y assertar '4.1' in ctr['PCI-DSS'] y any(c.startswith('SC-') for c in ctr['NIST 800-53']).
- **[compliance-mapping]** Reforzar test_report.py para assertar el formato con conteo (p.ej. 'PCI-DSS:' en el texto y un '(2)') y añadir en test_informe.py una aserción de 'Controles de cumplimiento afectados'.
- **[compliance-mapping]** Decidir y reflejar en la spec la numeración ISO objetivo (2013 A.10 vs 2022 A.8.24), o emitir ambas.
- **[compliance-mapping]** Si 'OWASP/CWE' es intencional, añadir un fallback por CWE en controles_de(); si no, corregir el texto de la spec a 'derivados de su categoría OWASP'.
- **[owasp-2025-mapping]** Añadir tests/test_owasp.py con: (a) assert set(CATEGORIAS) == {A01..A10}:2025, (b) assert CATEGORIAS['A03:2025'] == 'Software Supply Chain Failures' y CATEGORIAS['A10:2025'] == 'Mishandling of Exceptional Conditions', (c) assert not any(k.endswith(':2021') for k in CATEGORIAS).
- **[owasp-2025-mapping]** Añadir un test de etiquetado para A10: Finding('Errores', 'Stack trace expuesto en respuesta de error', ...) → owasp.etiquetar → 'A10:2025', y otro con 'Modo debug expuesto en producción'; eso cerraría la línea 83 sin cobertura.
- **[owasp-2025-mapping]** Reforzar tests/test_error_audit.py assertando f.owasp == 'A10:2025' en test_stack_trace_expuesto_es_medio y test_modo_debug_es_alto (hoy solo se verifica el riesgo).
- **[owasp-2025-mapping]** Meta-test de consistencia: recorrer los Finding emitidos (o el propio _REMAP) y assertar que todo código ':2021' emitido en src tiene entrada en _REMAP, y que toda salida de categoria() pertenece a CATEGORIAS — así el catálogo deja de ser código muerto y se convierte en la fuente de verdad.
- **[access-control-testing]** Implementar la prueba write-IDOR con proof no destructiva (p.ej. OPTIONS/HEAD para descubrir métodos permitidos, o distinguir 401/403 vs 2xx/405 en PUT/PATCH sin cuerpo destructivo) y añadir un test que pine el reporte ALTO cuando la operación mutante es aceptada sobre un objeto ajeno.
- **[access-control-testing]** Actualizar el docstring del módulo (líneas 4-5, 'Solo lectura (GET)') una vez implementada la escritura para eliminar la contradicción con la spec.
- **[access-control-testing]** Añadir prueba del vecino -1 y de al menos otro identificador para ampliar la cobertura de IDOR/BOLA conforme al '±1, otro id' del requirement.
- **[authentication-testing]** Discrepancia de tag OWASP: la spec referencia A07:2025 pero los Findings usan owasp='A07:2021' (auth_test.py:81,97,114). Alinear la etiqueta.
- **[authentication-testing]** _FALLO incluye el término genérico 'error' (auth_test.py:30), que puede clasificar como fallo páginas legítimas que contengan esa palabra y provocar falsos negativos en _es_exito_login/_default_creds. Considerar restringirlo.
- **[authentication-testing]** Enumeración: la spec menciona diferencia por tiempo de respuesta; _enumeracion solo compara status/body. Considerar añadir señal temporal o documentar el alcance.
- **[ssrf-header-injection]** Añadir un test que pase un Crawl() con params.values() conteniendo un nombre de _PARAMS_SSRF descubierto para pinnear la unión de parámetros descubiertos.
- **[ssrf-header-injection]** Incluir X-Forwarded-Scheme entre los headers inyectados/comprobados para alinear plenamente con el Requirement 'Cache poisoning básico'.
- **[ssrf-header-injection]** El hallazgo de cache poisoning usa owasp='A02:2025' mientras el resto usa 'A01:2025'; confirmar si la divergencia de tag OWASP es intencional.
- **[supply-chain-sbom]** Añadir un test en tests/test_cli.py que ejecute el CLI con --sbom tmp_path/'sbom.json' (mockeando el escaneo) y assertar que json.loads del archivo cumple specVersion=='1.5' y contiene los componentes esperados — cerraría el WHEN de los dos escenarios del requirement 1.
- **[supply-chain-sbom]** Extender generar() con la sección `vulnerabilities` de CycloneDX 1.5 (id CVE + bom-ref al componente) usando los findings del módulo 'CVE', para cumplir la cláusula 'y sus CVEs conocidos'.
- **[supply-chain-sbom]** Filtrar scopes públicos conocidos (@babel, @angular, @vue, @types, @aws-sdk, @nestjs, …) en _paquetes_internos() o degradar el hallazgo, y añadir un test que asserte que '@babel/core' NO genera finding.
- **[supply-chain-sbom]** Añadir assert f.owasp == 'A03:2025' dentro de test_analizar_reporta_dependency_confusion.
- **[supply-chain-sbom]** Añadir dos tests baratos que cierren las líneas 46/50: (a) un Finding('Fingerprint','IP resuelta 1.2.3.4') que NO debe producir componente (pin del lookahead anti-IP), y (b) el mismo componente en dos módulos distintos (p.ej. 'JS vulnerable' y 'CVE' con jQuery 1.8) que debe aparecer una sola vez (pin del dedup).
- **[supply-chain-sbom]** Añadir un test de analizar() con scripts={'https://ej.com/static/app.js'} para cubrir el bucle 66-70 y la derivación de ruta.
- **[error-handling-audit]** `_FIRMAS_TRACE` incluye subcadenas genéricas ('exception in', 'stack trace') que pueden dar falsos positivos en prosa de una página de error o documentación; considerar anclarlas a contexto (status>=400 o proximidad a otra firma).
- **[error-handling-audit]** `_FIRMAS_DEBUG` contiene el literal `"whoops\\"` (cadena real `whoops\`) junto a `"whoops "` — el backslash parece un artefacto; revisar la intención.
- **[error-handling-audit]** Añadir un test que asserte `f.owasp == 'A10:2025'` y `f.referencia` en la sonda, para pinear la atribución OWASP además del riesgo.
- **[resource-consumption]** Registrar `--rl-burst` en `cli.py` y propagarlo por `run_scan` hasta `rate_limit.analizar(dominio, burst=...)`, o corregir spec y docstring para que reflejen que burst no es configurable desde CLI.
- **[resource-consumption]** La ráfaga siempre golpea `/` (rate_limit.py:28); un endpoint dinámico o de API (p.ej. de los descubiertos por api_discovery) daría una señal más representativa, ya que `/` suele servirse desde caché/CDN sin tocar el rate-limiter de aplicación.
- **[resource-consumption]** Añadir un test que asserte la categoría OWASP/API del Finding para pinear la taxonomía declarada en la spec.

---

## Verdict (verificación inicial)

**PASA EL GATE CI · NO LISTO PARA ARCHIVE** (estado ANTES de remediar)

El código compilaba, tipaba, linteaba y pasaba 332 tests con 75% de cobertura. Pero solo 44/67 escenarios de spec estaban COMPLIANT: 9 issues CRITICAL (features de spec no implementadas + escenarios sin test) a resolver o reconciliar antes de archivar.

---

## Remediación + Re-verificación (post)

Los 9 CRITICAL se cerraron: 4 features implementadas con TDD estricto (session fixation, `--rl-burst`, header X-Debug, CVEs por componente en el SBOM), tagging **API Top 10 2023** nuevo (`Finding.api`, 8 categorías, render en texto/HTML/SARIF), tests de cierre (owasp A10, bucket privado cloud, `--sbom` CLI), y 2 specs reconciliadas (write-IDOR → verificación manual; ISO A.8.24).

**Gate final:** ruff ✓ · mypy ✓ (64 files) · pytest **359 passed / 2 skipped** · cobertura ≥75%.

**Re-verificación adversarial (6 áreas remediadas, mutación para descartar tests vacuos):** 6/6 **COMPLIANT**, ninguna vacua.

Brechas residuales (no bloqueantes, WARNING/SUGGESTION):
- **Session fixation (la más relevante):** heurística débil — compara la cookie de un GET anónimo vs la del POST de login sin reenviar la cookie pre-login → alto riesgo de **falso negativo** contra servidores reales; `_es_exito_login` trata cualquier 3xx como éxito (riesgo de falso positivo). Cumple la spec y el test lo pinea, pero la detección real es limitada. Recomendado: reenviar la cookie pre-login durante el login y endurecer el criterio de éxito.
- Menores: falta pin de `owasp='A10:2025'` en el finding X-Debug; falta test e2e de que un finding real de rate_limit lleve `api='API4:2023'`; validez CycloneDX comprobada estructuralmente (no contra JSON-schema); API3/API6 sin mapear (8/10 alcanzables, criterio ≥7/10 cumplido); sin test de regresión de ausencia de métodos mutantes en access-control.

**Veredicto final: LISTO PARA ARCHIVE** (con la limitación de session fixation documentada como known-limitation).
