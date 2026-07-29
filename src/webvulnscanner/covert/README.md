# Laboratorio: Canal Encubierto en el campo IP ID (capa 3/4)

Módulo de red del proyecto (`webvulnscanner.covert`), aislado del escáner web
porque opera en **otra capa** (TCP/IP, no HTTP). Implementa las tres partes que
pide el Taller No. 2 de Redes (UNAL): **funcionamiento, detección y mitigación** de
un canal encubierto que oculta datos en el campo *IP Identification* (16 bits).

> ⚖️ **Uso estrictamente académico y en laboratorio autorizado** (Ley 1273 de 2009).
> No usar contra redes o sistemas sin autorización expresa.

## Arquitectura (misma filosofía del proyecto)

| Archivo | Rol | Capa |
|---|---|---|
| `ipid.py` | codificar/decodificar datos en el IP ID (**puro, testeable**) | — |
| `detector.py` | detección estadística (entropía, secuencialidad) → `Finding` | — |
| `ml.py` | clasificador ML (scikit-learn) covert vs. legítimo — la parte de "IA" | — |
| `emisor.py` | envía paquetes con datos ocultos (scapy, root) | L3 |
| `receptor.py` | captura y reconstruye (scapy, root) | L3 |
| `mitigador.py` | aleatoriza el IP ID (`normalizar` puro + NFQUEUE inline) | L3 |
| `cli.py` | `webvulnscanner-covert` (demo / send / recv / detect / mitigate) | — |

El núcleo (`ipid`, `detector`, `ml`, `mitigador.normalizar`) es **puro y con tests**;
las capas de red usan scapy/netfilterqueue con **degradación elegante** (si no están,
esas funciones simplemente no están disponibles).

## Instalación

```bash
pip install -e ".[netlab]"          # scapy + scikit-learn + numpy
# Mitigación inline (opcional, Linux):
sudo apt install libnetfilter-queue-dev && pip install netfilterqueue
```

## Demo sin red ni root (para sustentar)

```bash
webvulnscanner-covert demo
```
Muestra el pipeline completo: codifica un mensaje en IP IDs → el detector lo
recupera (canal activo) → el mitigador aleatoriza el IP ID → el detector ya no ve
nada (canal destruido).

## Laboratorio real (2 hosts, root)

**Receptor** (host B):
```bash
sudo webvulnscanner-covert recv --count 32
```
**Emisor** (host A):
```bash
sudo webvulnscanner-covert send <IP_del_receptor> --mensaje "clave-lab: secreto"
```

**Detección desde una captura** (tcpdump → análisis):
```bash
sudo tcpdump -i eth0 icmp -w captura.pcap        # capturar el tráfico
webvulnscanner-covert detect captura.pcap        # analizar los IP IDs
```
También acepta un archivo de texto con un IP ID por línea.

**Mitigación en el gateway** (Linux, root):
```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
sudo webvulnscanner-covert mitigate              # aleatoriza el IP ID de cada paquete
```

## Cómo funciona la detección

- **Contenido:** si la secuencia de IP IDs decodifica un marco válido (magic + longitud),
  el canal está confirmado → `Risk.ALTO`.
- **Estadística:** un IP ID que *debería* ser aleatorio pero es **secuencial** delata un
  contador (zombie para Idle Scan); si su **entropía es baja** (datos estructurados),
  es un posible canal encubierto → `Risk.MEDIO`.
- **ML (`ml.py`):** un RandomForest entrenado sobre esas características separa covert
  de legítimo — útil cuando los umbrales fijos no bastan.

## Por qué el escáner web NO detecta esto

El escáner (`webvulnscanner <dominio>`) es de capa 7: usa HTTP/DNS normales y nunca
toca cabeceras IP/TCP crudas. Los canales encubiertos son **análisis de tráfico de
capa 3/4** — por eso viven en este subpaquete aparte, con su propio CLI.
