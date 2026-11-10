# WebVulnScanner — texto para ángeles

> Borrador. Lo marcado **[COMPLETAR]** es un dato que solo tú tienes; lo marcado **[HIPÓTESIS]** es un número a validar con clientes antes de afirmarlo.

## En una línea

Una auditoría de seguridad web que una pyme entiende sin ser técnica: un veredicto claro (nota A–F), qué arreglar primero y cuánto riesgo corre, en minutos y no en semanas.

## El problema

Las pymes tienen sitio web, tienda o correo expuestos a internet y casi nunca saben si están seguros. Hoy tienen dos opciones malas:

- **Consultoría de pentest:** cara, lenta y entrega un PDF que el gerente no sabe leer.
- **Escáneres empresariales (Qualys, Tenable, Detectify, Intruder):** pensados para equipos de seguridad; entregan listas largas de hallazgos sin priorizar.

Resultado: la mayoría no audita nunca, y se entera cuando ya la atacaron.

## La solución (lo que existe hoy)

Un auditor de la superficie externa de un dominio que:

- Corre en un solo comando o por API REST, con más de 30 módulos: TLS, cabeceras, DNS y correo, subdominios, exposición de archivos, inyecciones, CVEs, entre otros.
- Integra motores abiertos de referencia (nuclei, sslyze, OpenVAS, testssl) y unifica sus resultados.
- Entrega primero un informe rápido y luego el completo (dos fases), con **nota A–F** y priorización de hallazgos.
- Exporta HTML, JSON y SARIF, así que también sirve a equipos de desarrollo en CI.
- Está desplegado en un servidor propio con Docker y tiene 384 tests automatizados.

Es un producto funcionando, no una idea.

## Por qué podemos ganar

- **Traducción, no solo detección:** el diferenciador es el informe ejecutivo (veredicto + qué hacer primero), que los escáneres grandes no priorizan para un no técnico. **[HIPÓTESIS: confirmar con 5 entrevistas a gerentes de pymes]**
- **Costo bajo:** se apoya en motores abiertos; el margen no depende de licencias.
- **Foco local:** informes en español para pymes de **[COMPLETAR: Colombia / LatAm]**, un segmento que los competidores globales atienden mal.

## Mercado

**[COMPLETAR con fuente verificable]**: número de pymes con presencia web en el país o la región. No pongas cifras de memoria; un ángel las busca.

## Modelo de negocio

**Recomendado: suscripción mensual por dominio** (escaneo recurrente + alertas cuando algo empeora).

| Plan | Qué incluye | Precio **[HIPÓTESIS]** |
|---|---|---|
| Básico | 1 dominio, escaneo mensual, informe ejecutivo | USD 20–30 / mes |
| Pro | 5 dominios, escaneo semanal, alertas, API | USD 80–120 / mes |

Alternativa: **auditoría puntual** (informe único, USD 150–300 **[HIPÓTESIS]**). Entra dinero más rápido, pero parece consultoría y no genera ingreso recurrente.

## Tracción

Hoy: ninguna comercial. Lo que sí hay:

- Producto funcional y desplegado.
- Informes reales sobre sitios propios o autorizados, usables como casos de estudio **[COMPLETAR: cuáles y con qué permiso]**.

**Plan de 90 días:** conseguir 5 pilotos gratuitos con pymes, medir cuántos corrigen hallazgos y cuántos pagarían, y con eso fijar precio.

## Competencia

| | Qué hacen bien | Dónde dejan espacio |
|---|---|---|
| Qualys / Tenable | Cobertura enterprise | Complejos y caros para una pyme |
| Detectify / Intruder | Escaneo continuo SaaS | Orientados a equipos técnicos, en inglés |
| Pentest a medida | Profundidad | Lento y caro, sin seguimiento |

## Riesgos (los decimos nosotros antes de que pregunten)

- **Legal:** los módulos activos prueban inyecciones contra el objetivo. Hoy la API no verifica que el usuario sea dueño del dominio. **Antes de cobrar** hay que añadir verificación de propiedad (registro TXT en DNS) y términos de uso. Está pendiente, no hecho.
- **Dependencia de motores abiertos:** si cambian de licencia, hay que reemplazarlos. Mitigación: la arquitectura ya los trata como módulos intercambiables.
- **Equipo de una persona:** **[COMPLETAR: a quién incorporarías con el dinero]**.

## Qué pides

**[COMPLETAR]**: monto, para cuántos meses alcanza y en qué se gasta (por ejemplo: 5 pilotos, verificación de dominio y términos legales, primer empleado de ventas o soporte, infraestructura).
