# Playbook: generar un informe de seguridad para cualquier página

> **El informe de 3 pestañas (`informe.html`) ahora lo genera la propia herramienta**
> automáticamente en cada escaneo — ya NO se arma a mano. Este playbook es el flujo.
>
> **Único parámetro de entrada:** `URL` (la página a analizar). Reemplaza `{URL}`
> por el valor real. Ejemplo: `https://ejemplo.edu.co/`.
>
> **REGLA FIJA:** cada análisis se guarda en su propia subcarpeta con el **nombre del
> dominio** dentro de `informes/` → `informes/<dominio>/`. Nunca en otra ubicación.
>
> **NUNCA publiques el informe en enlaces externos (Claude/artefactos/hosting).** El
> entregable es siempre el archivo local `informes/<dominio>/informe.html`.
>
> ## Flujo mínimo (una línea)
> ```bash
> DOMINIO=$(python -c "from urllib.parse import urlparse;print(urlparse('{URL}' if '//' in '{URL}' else '//{URL}').hostname)")
> .venv/bin/webvulnscanner "{URL}" --authorized --pdf -o "informes/$DOMINIO" -q
> # deja informe.html (3 pestañas) + informe.pdf + reporte_*.{txt,json,html}; conserva solo:
> .venv/bin/python -c "import glob,os; [os.remove(f) for f in glob.glob(f'informes/$DOMINIO/reporte_*.txt')+glob.glob(f'informes/$DOMINIO/reporte_*.html')]"
> ```
> El resto de este documento explica los detalles. La generación manual del HTML
> quedó **obsoleta**: `webvulnscanner.informe.generar(result)` la produce sola.

---

## Regla de ejecución (obligatoria)

- **SIEMPRE se ejecuta el análisis COMPLETO: pasivo + activo, con `--authorized`.**
  El operador de esta herramienta trabaja siempre con autorización, así que el
  informe debe incluir todos los módulos (control de acceso, autenticación,
  inyección, SSRF, rate-limit…). **Nunca entregues un informe solo pasivo.**
- Los módulos activos envían pruebas **controladas y no destructivas** (lecturas,
  marcadores, payloads que no alteran datos).

---

## Paso 0 — Preparar el entorno (una sola vez)

```bash
cd <ruta-del-proyecto>            # carpeta que contiene pyproject.toml
python -m venv .venv
.venv/bin/pip install -e ".[api,dev]"
```

Verificar:

```bash
.venv/bin/webvulnscanner --version    # → WebVulnScanner 2.0
```

---

## Paso 1 — Ejecutar el escaneo

`{DOMINIO}` es solo el host de la URL (sin `https://` ni ruta). Derivarlo así:

```bash
DOMINIO=$(python -c "from urllib.parse import urlparse;print(urlparse('{URL}' if '//' in '{URL}' else '//{URL}').hostname)")
mkdir -p "informes/$DOMINIO"
```


**Comando ÚNICO — siempre completo (pasivo + activo):**

```bash
.venv/bin/webvulnscanner "{URL}" --authorized -o "./informes/{DOMINIO}" -q
```

`--authorized` va **siempre**. No existe la variante "solo pasivo" para el informe.

Opciones útiles:

| Flag | Para qué |
|------|----------|
| `--cookie "sid=…"` / `--bearer TOKEN` | escanear zonas autenticadas |
| `--delay 0.5` o `--rps 2` | cortesía: espaciar peticiones |
| `--sarif` | además, salida SARIF para CI/GitHub |
| `--sbom sbom.json` | genera SBOM CycloneDX de los componentes |
| `--baseline .wvsignore` | suprime hallazgos ya aceptados |

El comando escribe **tres archivos** en `./informes/{DOMINIO}/`
(`reporte_<dominio>_<fecha>.txt`, `.json` y `.html`), pero **solo se conservan dos**:
el `.json` (fuente de datos) y el `informe.html` (informe final). Borra el resto:

```bash
find "informes/$DOMINIO" -maxdepth 1 \( -name 'reporte_*.txt' -o -name 'reporte_*.html' \) -delete
```

Resultado final en `informes/{DOMINIO}/`:

```
informe.html                       ← informe curado (2 registros) — el entregable
reporte_<dominio>_<fecha>.json     ← datos estructurados del escaneo
```

Código de salida: `0` sin riesgo alto · `2` si hay hallazgos de riesgo ALTO ·
`1` si el dominio es inválido.

---

## Paso 2 — Leer el JSON

Estructura del `.json`:

```jsonc
{
  "meta": {
    "dominio": "ejemplo.edu.co",
    "ip": "1.2.3.4",
    "servidor": "nginx/1.18.0",
    "timestamp": "2026-07-28 12:07:19",
    "nota": "F",          // A–F
    "puntaje": 0           // 0–100
  },
  "resumen": { "alto": 7, "medio": 5, "bajo": 8, "info": 6, "ok": 2 },
  "hallazgos": [
    {
      "modulo": "TLS/HTTPS",
      "hallazgo": "Certificado expira 2026-08-04 (6 días)",
      "riesgo": "alto",                 // alto|medio|bajo|info|ok
      "descripcion": "Expira en 6 días. Renueve con urgencia.",
      "referencia": "https://…",         // puede ser null
      "evidencia": "Aug 4 …",            // puede ser null
      "owasp": "A04:2025",               // categoría OWASP Top 10 2025
      "cwe": "CWE-295",                  // puede ser null
      "cvss": { "vector": "…", "score": 4.8 }   // puede ser null
    }
  ]
}
```

Orden de gravedad (para ordenar los hallazgos de mayor a menor):
`alto(0) → medio(1) → bajo(2) → info(3) → ok(4)`.

Ejemplo para volcar los hallazgos ya ordenados:

```bash
.venv/bin/python - "{RUTA_JSON}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
orden = {"alto":0,"medio":1,"bajo":2,"info":3,"ok":4}
for h in sorted(d["hallazgos"], key=lambda x: orden[x["riesgo"]]):
    print(h["riesgo"].upper(), "|", h["modulo"], "|", h["hallazgo"])
PY
```

---

## Paso 3 — Construir el informe (reglas fijas)

El informe **siempre** cumple estas reglas:

1. **Orden:** de mayor a menor gravedad (alto → medio → bajo → info → ok).
2. **Encabezado:** dominio, IP, servidor, fecha, y la **nota A–F** destacada, más el
   conteo por severidad.
3. **Resumen ejecutivo** en lenguaje llano: las 3 prioridades principales.
4. **Cada hallazgo se presenta en DOS registros:**

   **🟢 En simple** (para cualquier persona, sin tecnicismos), con tres preguntas:
   - **¿Qué pasa?** — describe el hecho en una frase cotidiana.
   - **¿Por qué importa?** — el riesgo real, con una analogía si ayuda.
   - **¿Qué hacer?** — la acción concreta de arreglo.

   **⚙️ Detalle técnico** (desplegable), con los datos crudos del JSON:
   `owasp`, `cwe`, `cvss.score`, `evidencia`, `referencia`.

5. **Agrupar por severidad** con títulos: Críticos / Moderados / Menores /
   Informativos / Correcto.
6. **Sección de módulos:** tabla "qué encontró cada módulo" (módulo → nº de
   hallazgos → peor severidad). Deriva los módulos de `hallazgos[].modulo`.
7. **Cumplimiento:** si hay hallazgos con `owasp`, incluir la sección de controles
   PCI-DSS / ISO 27001 / NIST (aparece también en el reporte `.txt`).
8. **Pie:** metodología + aviso de alcance (análisis completo pasivo + activo) + nota ética.

### Traducir a lenguaje simple (guía)

Para el registro "En simple", no copies la `descripcion` técnica: reescríbela.
Patrón por tipo de hallazgo:

| Si el hallazgo trata de… | Analogía / frase simple |
|--------------------------|--------------------------|
| Certificado por vencer | «El candado HTTPS caduca; renuévalo o saldrá alerta de sitio no seguro» |
| Falta CSP / cabecera | «Falta una defensa que el servidor le declara al navegador» |
| CVE de una versión vieja | «El software usado tiene fallos públicos conocidos; actualízalo» |
| Contenido mixto | «Carga archivos sin cifrar dentro de una página cifrada» |
| Falta SRI | «Carga scripts de fuera sin verificar que no fueron alterados» |
| Server/versión expuesta | «Anuncia su versión exacta, como un letrero para el atacante» |
| DNS (CAA/DNSSEC) | «Faltan protecciones a nivel de dominio» |

Siempre cierra con la acción concreta (**¿Qué hacer?**).

---

## Paso 4 — Formato de salida

Dos opciones:

- **Rápida:** el propio escáner ya genera `reporte_<dominio>_<fecha>.html`
  (autocontenido). Sirve como base.
- **Informe "para todos" (recomendado):** genera un HTML nuevo siguiendo la
  plantilla de referencia `informe-doctorado.html` (dos registros por hallazgo,
  tema claro/oscuro, responsive). Reemplaza los datos por los del nuevo `.json`,
  mantén la estructura y las reglas del Paso 3.

### Las TRES pestañas de cada informe

Todo `informe.html` tiene **tres** pestañas (CSS puro, sin JS: radios `t-inf`/`t-int`/`t-mod`
+ `nav.tabnav` + paneles `v-inf`/`v-int`/`v-mod`):

1. **📋 Informe** — los hallazgos de vulnerabilidad, de mayor a menor gravedad, en dos
   registros (simple + técnico). *(reglas del Paso 3)*
2. **🗂️ Inteligencia** — información de valor recopilada, **NO vulnerabilidades**. Se arma
   con los datos de recon del `.json` (y, si hace falta, consultas puntuales como leer los
   SAN del certificado para listar TODOS los subdominios). Secciones:
   - **Objetivo y alojamiento:** dominio, IP (y a quién/dónde pertenece), puertos, servidor, WAF/CDN.
   - **Stack tecnológico:** CMS, servidor, SO, tema, plugins, librerías JS, rutas del backend.
   - **Certificado TLS:** emisor, CN, validez, si es compartido.
   - **Ecosistema de subdominios:** lista completa (los SAN del certificado + CT logs).
   - **Hosts relacionados y postura DNS/correo** (CAA, DNSSEC, MTA-STS, TLS-RPT).
3. **🔍 Qué revisa la herramienta** — anexo **fijo** (idéntico en todos los informes).

### Pestaña fija "Qué revisa la herramienta" (anexo obligatorio)

**Todo `informe.html` tiene DOS pestañas.** La segunda es **fija e idéntica** en todos
los informes: explica la herramienta y qué revisa cada módulo (y según qué estándar).
No se re-escribe; se **anexa tal cual** desde `plantilla/pestana-modulos.html`.

Cómo montar las pestañas (una sola vez por informe):

1. Incluye el CSS de pestañas y `.modcard` (está al inicio de `plantilla/pestana-modulos.html`).
2. Justo tras `<div class="wrap">` añade:
   ```html
   <input class="tabsel" type="radio" name="tab" id="t-inf" checked>
   <input class="tabsel" type="radio" name="tab" id="t-mod">
   <nav class="tabnav">
     <label for="t-inf" tabindex="0">📋 Informe</label>
     <label for="t-mod" tabindex="0">🔍 Qué revisa la herramienta</label>
   </nav>
   <div id="v-inf" class="panel-view">
   ```
3. Cierra `</div><!-- /v-inf -->` tras el `<footer>` del informe.
4. Pega el `<div id="v-mod" class="panel-view">…</div>` de `plantilla/pestana-modulos.html`.

Es pura CSS (sin JavaScript) y respeta el tema claro/oscuro del informe.

Checklist final antes de entregar:

- [ ] Hallazgos ordenados de mayor a menor.
- [ ] Cada uno tiene registro **simple** y **técnico**.
- [ ] Encabezado con nota A–F y conteos.
- [ ] Tabla "qué encontró cada módulo".
- [ ] Pie con alcance (pasivo/activo) y aviso ético.
- [ ] Pestaña "Inteligencia" con IP/hosting, stack, certificado y TODOS los subdominios.
- [ ] Pestaña fija "Qué revisa la herramienta" anexada desde `plantilla/pestana-modulos.html`.
- [ ] Ningún dato inventado: todo sale del `.json`.

---

## Resumen en una línea (para un agente)

> «Corre `.venv/bin/webvulnscanner "{URL}" --authorized -o "./informes/{DOMINIO}" -q`, lee `./informes/{DOMINIO}/*.json`,
> ordena `hallazgos` por gravedad (alto→ok), y produce un HTML donde cada hallazgo
> tiene un bloque *En simple* (¿Qué pasa?/¿Por qué importa?/¿Qué hacer?) y un
> bloque *Detalle técnico* (owasp/cwe/cvss/evidencia). Nunca uses `--authorized`
> sin autorización expresa.»
