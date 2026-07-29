# Roadmap — WebVulnScanner + Laboratorio de Red

Plan de todo lo implementable, priorizado y con evaluación honesta de valor,
esfuerzo y factibilidad. El proyecto tiene hoy **dos ejes**:

- **Eje A — Escáner web (capa 7):** `webvulnscanner <dominio>`
- **Eje B — Laboratorio de red (capa 3/4):** `webvulnscanner-covert` (`covert/`)

Leyenda: 🟢 alto valor · 🟡 medio · ⚪ opcional/nicho · **[R]** detectable en remoto ·
**[L]** requiere laboratorio/on-path/root · **[✓]** ya hecho.

---

## Estado actual (hecho)

| Área | Cubierto |
|---|---|
| Fases L→V | transporte, inyección profunda, API/JWT/cloud/mail, CWE/CVSS/baseline/compliance, control de acceso, auth, SSRF, SBOM, errores, rate-limit |
| OWASP | Top 10 **2025** + API Top 10 2023 (tagging) |
| Backend dirigido | WordPress, Drupal/Joomla/Laravel/paneles |
| Motores externos | sslyze, Wappalyzer + CVE por componente, schemathesis, detect-secrets |
| Reporte | 3 pestañas (informe / inteligencia / qué revisa), PDF |
| Red L3/4 | canal encubierto en IP ID (implementar + detectar + mitigar) |
| Calidad | 325 tests, ruff + mypy limpios |

---

## Eje A — Escáner web: mejoras

### A1. Generación automática del informe desde el JSON 🟢 (prioridad #1)
Hoy el `informe.html` de 3 pestañas se mantiene a mano → no escala (con 45 hallazgos
es frágil). **Generar las 3 pestañas programáticamente desde el `.json`** del escaneo:
plantillas + los datos → informe completo sin edición manual, cada vez.
- Esfuerzo: medio · Valor: muy alto (elimina el trabajo manual recurrente).

### A2. Cobertura OWASP restante (lo automatizable)
| Falta | Cómo | |
|---|---|---|
| Stored XSS | requiere estado (crear→leer) — semi-automatizable | 🟡 |
| Host header / cache poisoning avanzado | ya hay base en `ssrf`; profundizar | 🟡 |
| GraphQL profundo | field suggestion, batching, introspección→abuso | 🟡 |
| Deserialización insegura | firmas en cookies/parámetros (Java/PHP/Python) | 🟡 |

### A3. Más backend dirigido 🟡
Joomla/Drupal **profundo** (no solo detección): CVEs de módulos, rutas conocidas,
enum de usuarios. Magento, Django admin, Spring Actuator, Jenkins, GitLab.

### A4. Correlación e inteligencia de vulns 🟡
- **grype/syft** (externos): escanear el SBOM que ya generamos contra bases de vulns.
- **nuclei dirigido**: auto-seleccionar plantillas por tecnología detectada (fingerprint→tags).
- CVSS temporal/environmental (lib `cvss`) sobre el base que ya calculamos.

### A5. Escaneo autenticado avanzado 🟡
Secuencia de login automatizada, extracción de token CSRF de formularios,
replay de sesión, detección de logout/expiración.

### A6. Calidad de vida ⚪
Config file (`.wvsconfig` para escaneos repetibles), modo *diff/monitor* programado,
informe bilingüe (ES/EN), throttle adaptativo.

---

## Eje B — Laboratorio de red (Taller UNAL): los 12 casos restantes

Cada caso = **implementar + detectar + mitigar**, en `covert/`, con el mismo patrón
(núcleo puro testeable + scapy/NFQUEUE guardado + `Finding` + ML opcional).

### B1. Canales encubiertos — extender 🟢 [L]
Ya está IP ID. Añadir los otros campos con el **mismo detector**: **ISN de TCP**, **TTL**,
**flags reservados TCP**, **opciones/padding TCP**. Reutiliza `detector`/`ml`.
- Esfuerzo: bajo (framework ya existe) · Valor: alto (completa el caso 1-2 del taller).

### B2. Timing Covert Channels 🟢 [L]
Codificar bits en el retardo entre paquetes. Detección por **series temporales**
(autocorrelación, varianza del inter-packet delay — numpy/scipy). Mitigación:
normalización de tráfico (jitter/shaping).

### B3. Fragmentación IP + evasión de IDS 🟡 [L]
Fragmentos solapados/teardrop que el IDS reensambla distinto al host. Detección:
reglas de reensamblaje anómalo. Mitigación: normalizar reensamblaje en el gateway.

### B4. Idle/Zombie Scan + Session Hijacking 🟡 [L]+[R]
Implementar el idle scan (host con IP ID incremental como zombie). **La precondición
SÍ es detectable en remoto** → puente al escáner web (ver C-bridge).

### B5. ICMP Tunneling 🟡 [L]
Encapsular datos en payload de ICMP echo. Detección: entropía/tamaño del payload ICMP.
Mitigación: inspección/filtrado de payload ICMP.

### B6. Off-Path con ICMP forjado 🟡 [L]
ICMP falsificado (dest unreachable/redirect) para manipular conexiones sin estar
on-path. Detección: validación estricta de ICMP. Mitigación: filtrado/rate-limit ICMP.

### B7. ARP Spoofing silencioso ⚪ [L]
Solo LAN. Detección: monitoreo de tabla ARP (cambios MAC↔IP). Mitigación: ARP estático / DAI.

### B8. LDoS/Shrew y Low-and-Slow ⚪ [L]
Ráfagas de baja tasa sincronizadas con el control de congestión TCP. Detección: análisis
de patrón de ráfagas (ML de anomalías). Mitigación: tuning de congestión / rate-limit.

### B9. DNS Cache Poisoning y Slow DNS Exfiltration 🟡 [R]+[L]
- **Susceptibilidad del resolver ES detectable en remoto**: randomización de puerto de
  origen, 0x20 encoding, DNSSEC → puede enriquecer el módulo DNS del escáner web.
- Exfiltración lenta: detección por tasa/entropía de subdominios en una captura.

### B10. Downgrade Attacks 🟡 [R]
Forzar TLS 1.0/SSHv1. **Parcialmente ya cubierto** por sslyze/TLS (protocolos obsoletos).
Extender a SSH y detección de ausencia de TLS_FALLBACK_SCSV.

---

## Eje C — Inteligencia Artificial (lo que enfatiza el taller)

### C1. Detectores ML por canal 🟢
Extender `covert/ml.py`: features + clasificadores para timing, ICMP tunneling, DNS
exfil. **IsolationForest/autoencoder** para detección de anomalías **sin etiquetas**
(clave para low-and-slow y covert cifrado).

### C2. Triage con LLM (agente) 🟢
Usar la API de Claude para: reducir falsos positivos, **priorizar** hallazgos, redactar
remediación accionable y un **resumen ejecutivo narrativo** desde el `.json`. Es la
parte de "modelos fundacionales / agentes avanzados" que menciona el taller.

### C3. Puente red→web (detección remota de preconditions) 🟡 [R]
Módulo en `webvulnscanner` (via nmap `-O`) que reporta: **ISN débil** (session hijacking),
**IP ID incremental** (idle-scan zombie), susceptibilidad DNS. Lo único de capa 3/4 que
un escáner remoto sí puede evaluar.

---

## Eje D — Infraestructura y empaquetado

| | | |
|---|---|---|
| D1 | **Imagen Docker** con todos los extras (sslyze, weasyprint, netlab, libnetfilter-queue-dev) | 🟢 |
| D2 | CI/CD: probar cada extra por separado; publicar a PyPI | 🟡 |
| D3 | Cobertura de tests ≥85%; smoke tests de integración | 🟡 |
| D4 | Documentación unificada (mkdocs) | ⚪ |

---

## Priorización recomendada

**Ahora (máximo valor / esfuerzo razonable):**
1. **A1** — informe auto-generado desde JSON (elimina el mantenimiento manual).
2. **B1 + B2** — extender canales encubiertos (ISN/TTL/flags) + timing → completa el taller.
3. **C1 + C2** — detectores ML de anomalías + triage con LLM (la "IA" del taller).

**Después:**
4. **C3** — puente nmap (preconditions TCP/IP en el escáner web).
5. **B9/B10** — DNS resolver + downgrade (detectables en remoto, enriquecen el escáner).
6. **A4** — grype/syft + nuclei dirigido.

**Cuando toque:**
7. **B3–B8** — resto de ataques de laboratorio (fragmentación, ICMP, ARP, LDoS).
8. **D1–D4** — Docker, CI, docs.

**Fuera de alcance realista** (inherentemente manual / caja blanca): OWASP A06 Insecure
Design, A09 Logging; lógica de negocio (API6/API10); DOM XSS (requiere motor headless).
