# Design: Ciberseguridad de frontera — Fases L→O

## Technical Approach

Extender los tres puntos que ya son "columna vertebral" — `net.py` (frontera de red), `models.py` (Finding), el orquestador (registro de módulos) — y añadir módulos aislados nuevos que sigan el contrato existente `analizar(...) -> list[Finding]`. Nada rompe `fetch()`: `request()` es la primitiva nueva y `fetch()` pasa a ser un wrapper GET sobre ella. Post-proceso (clasificación/baseline/compliance) se engancha donde hoy vive `enrich`+`owasp`, tras ensamblar findings.

## Architecture Decisions

### Decision: `request()` como primitiva, `fetch()` como wrapper
| Opción | Tradeoff | Decisión |
|---|---|---|
| Añadir params a `fetch()` | rompe firma usada por ~10 módulos | ✗ |
| Nueva `request()`, `fetch()` delega GET | compat total, un solo motor | ✓ |

`request()` centraliza method/data/json/headers, sesión y throttle. `fetch()` = `request(method="GET")` con el fallback HTTPS→HTTP actual.

### Decision: Sesión y throttle como estado de módulo, no globales
**Choice**: un `Sesion` (dataclass: headers auth + delay) que el orquestador crea desde flags CLI y pasa a `request` vía contextvar o parámetro por defecto en `net`.
**Alternativas**: variable global mutable (frágil en tests/threads).
**Rationale**: los tests ya monkeypatchean `net`; un contextvar mantiene thread-safety con el ThreadPoolExecutor y no ensucia cada firma. `# ponytail: contextvar en net, no pasar Sesion por 15 firmas`.

### Decision: Activos nuevos gateados igual que hoy
**Choice**: LFI/SSTI/CRLF/cmdi/blind-SQLi/form-injection entran en `MODULOS_ACTIVOS`, solo con `autorizado=True`. CSRF y JWT y api-discovery son PASIVOS → `MODULOS`.
**Rationale**: CSRF/JWT solo leen HTML/tokens servidos; no envían payloads. Respeta la línea ética existente y la API REST (solo pasivo) los expone sin riesgo.

### Decision: CVSS nativo, sin dependencia
**Choice**: implementar la fórmula CVSS v3.1 (base score) en `classify.py` (~40 líneas, tabla de pesos).
**Alternativas**: lib `cvss`.
**Rationale**: la fórmula es cerrada y estable; una dep nueva por 40 líneas viola el criterio del proyecto. `# ponytail: base score only, temporal/environmental si algún día importan`.

## Data Flow

    CLI flags ─→ Sesion(headers,delay) ─→ net.request (contextvar)
                                              │  (todos los módulos)
    recon → crawler → módulos(pasivos+activos) → findings[]
                                              │
              enrich(EPSS/KEV) → classify(CWE/CVSS) → owasp
                                              │
              compliance.map → baseline.filtrar → report/sarif

Baseline filtra al final (antes de render y del conteo de exit-code).

## File Changes

| File | Action | Description |
|---|---|---|
| `net.py` | Modify | `request()`, `Sesion`, contextvar, throttle; `fetch` delega |
| `models.py` | Modify | `Finding.cwe`, `Finding.cvss`; to_dict/from_dict retrocompat |
| `modules/active.py` | Modify | form/POST injection, blind SQLi, LFI/SSTI/CRLF/cmdi, por-parámetro |
| `modules/csrf.py` | Create | forms POST sin token (pasivo) |
| `modules/api_discovery.py` | Create | OpenAPI/Swagger + GraphQL introspection |
| `modules/jwt_audit.py` | Create | alg:none, secreto débil, exp |
| `modules/cloud.py` | Create | buckets públicos, metadata SSRF |
| `modules/mail_transport.py` | Create | MTA-STS, TLS-RPT |
| `classify.py` | Create | CWE map + CVSS v3.1 score |
| `compliance.py` | Create | OWASP/CWE → PCI/ISO/NIST |
| `baseline.py` | Create | huella estable, cargar/filtrar/escribir |
| `orchestrator.py` | Modify | registrar módulos, Sesion, pipeline post-proceso |
| `cli.py` | Modify | `--cookie/--header/--bearer/--delay/--rps/--baseline/--write-baseline` |
| `report.py`, `html.py`, `sarif.py` | Modify | render CWE/CVSS y sección compliance |

## Interfaces / Contracts

```python
def request(
    dominio, ruta="/", *, method="GET", data=None, json=None, headers=None, max_body=200_000
) -> HttpResponse | None: ...


@dataclass
class Sesion:
    headers: dict[str, str] = field(default_factory=dict)
    delay: float = 0.0  # seg entre peticiones (throttle)


# models
cwe: str | None = None
cvss: dict | None = None  # {"vector": str, "score": float}
```

Módulos nuevos mantienen `analizar(...) -> list[Finding]`. `classify`/`compliance`/`baseline` operan in-place o filtran `list[Finding]`, como `enrich`/`owasp`.

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit | fórmula CVSS, huella baseline, parsers (JWT/openapi/bucket XML), CWE map | vectores conocidos, sin red |
| Unit | `request` POST/JSON/throttle; `fetch` intacto | monkeypatch `urlopen`; medir delay |
| Integration | módulos activos/pasivos nuevos | monkeypatch `net.request`/`_consultar` DNS, respuestas de ejemplo |
| Integration | pipeline post-proceso end-to-end | ScanResult sintético → classify→compliance→baseline |

Red SIEMPRE simulada. Gate `autorizado`: test que confirma que los activos nuevos no corren sin él y no se exponen por la API.

## Migration / Rollout

Sin migración de datos. Reportes viejos cargan (campos nuevos → None). Cada fase = commit independiente y `git revert` aislado (L no depende de M/N/O; M depende de L). Flags nuevos son opt-in con defaults compatibles.

## Open Questions

- [ ] Lista de secretos triviales para JWT HS256: set corto embebido (evitar "brute force" real). Se acota a ~20 comunes.
- [ ] Verificación de bucket público hace 1 request externa al proveedor cloud: aceptable como pasivo (lectura), pero se documenta en el output.
