"""CLI del laboratorio de canal encubierto en IP ID (`webvulnscanner-covert`).

Subcomandos:
  demo      pipeline completo sin red ni root (codificar → detectar → mitigar → detectar)
  send      envía datos ocultos a un host (scapy, root) — solo laboratorio autorizado
  recv      captura paquetes y reconstruye el mensaje (scapy, root)
  detect    analiza un .pcap o un archivo de IP IDs y reporta si hay canal encubierto
  mitigate  gateway NFQUEUE que aleatoriza el IP ID (root)
"""

from __future__ import annotations

import argparse
import sys

from webvulnscanner.covert import campos, detector, emisor, ipid, mitigador, receptor, timing


def _demo() -> int:
    print("── DEMO: canal encubierto en el campo IP ID ──\n")
    mensaje = b"clave-lab: SSH root@10.0.0.5"
    print(f"1) Mensaje a exfiltrar: {mensaje!r}")

    ids = ipid.codificar(mensaje)
    print(f"2) Codificado en {len(ids)} valores de IP ID: {ids[:6]}...")

    print("\n3) DETECCIÓN sobre el tráfico:")
    for f in detector.analizar(ids):
        print(f"   [{f.riesgo.value.upper()}] {f.hallazgo} — {f.evidencia}")
    print(f"   → mensaje recuperado por el receptor: {ipid.decodificar(ids)!r}")

    normalizados = mitigador.normalizar(ids)
    print("\n4) MITIGACIÓN (gateway aleatoriza el IP ID):")
    print(f"   → decodificar tras mitigar: {ipid.decodificar(normalizados)!r}")
    hallazgos = detector.analizar(normalizados)
    print(f"   → el detector ahora reporta: {len(hallazgos)} hallazgos (canal destruido)")

    print("\n5) Otros campos y timing channel:")
    for campo, bits in campos.CAMPOS.items():
        vals = campos.codificar(b"x", bits)
        print(f"   - {campo:5} ({bits} bits): detectado = {bool(detector.analizar(vals, bits))}")
    retardos = timing.codificar(b"por tiempo")
    print(f"   - timing: recuperado = {timing.decodificar(retardos)!r}")
    return 0


def _leer_ids(ruta: str) -> list[int]:
    """Lee IP IDs de un .pcap (scapy) o de un archivo de texto (uno por línea)."""
    if ruta.endswith((".pcap", ".pcapng")):
        from scapy.all import IP, rdpcap

        return [p[IP].id for p in rdpcap(ruta) if p.haslayer(IP)]
    with open(ruta, encoding="utf-8") as fh:
        return [int(x) for x in fh.read().split() if x.strip()]


def _detect(ruta: str, *, campo: str = "ipid", es_timing: bool = False) -> int:
    if es_timing:
        with open(ruta, encoding="utf-8") as fh:
            retardos = [float(x) for x in fh.read().split() if x.strip()]
        hallazgos = timing.analizar(retardos)
    else:
        ids = _leer_ids(ruta)
        hallazgos = detector.analizar(ids, campos.CAMPOS.get(campo, 16))
    if not hallazgos:
        print(f"Sin canal encubierto detectado en {len(ids)} IP IDs.")
        return 0
    for f in hallazgos:
        print(f"[{f.riesgo.value.upper()}] {f.hallazgo}")
        print(f"    {f.descripcion}")
        print(f"    evidencia: {f.evidencia}")
    return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="webvulnscanner-covert",
        description="Laboratorio: canal encubierto en el campo IP ID (académico, red autorizada).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="pipeline completo sin red ni root")
    s_send = sub.add_parser("send", help="enviar datos ocultos (scapy, root)")
    s_send.add_argument("destino")
    s_send.add_argument("--mensaje", required=True)
    s_send.add_argument("--campo", choices=sorted(campos.CAMPOS), default="ipid")
    s_send.add_argument("--timing", action="store_true", help="usar canal por temporización")
    s_recv = sub.add_parser("recv", help="capturar y reconstruir (scapy, root)")
    s_recv.add_argument("--count", type=int, default=64)
    s_det = sub.add_parser("detect", help="analizar un .pcap o archivo de valores")
    s_det.add_argument("archivo")
    s_det.add_argument("--campo", choices=sorted(campos.CAMPOS), default="ipid")
    s_det.add_argument("--timing", action="store_true", help="analizar retardos (timing channel)")
    sub.add_parser("mitigate", help="gateway NFQUEUE que aleatoriza el IP ID (root)")

    args = p.parse_args(argv)
    if args.cmd == "demo":
        return _demo()
    if args.cmd == "detect":
        return _detect(args.archivo, campo=args.campo, es_timing=args.timing)
    if args.cmd == "send":
        if not emisor.disponible():
            print("scapy no disponible (extra 'netlab') o sin permisos.", file=sys.stderr)
            return 1
        datos = args.mensaje.encode()
        n = (
            emisor.enviar_timing(args.destino, datos)
            if args.timing
            else emisor.enviar(args.destino, datos, campo=args.campo)
        )
        print(f"Enviados {n} paquetes con datos ocultos.")
        return 0
    if args.cmd == "recv":
        if not receptor.disponible():
            print("scapy no disponible (extra 'netlab') o sin permisos.", file=sys.stderr)
            return 1
        ids = receptor.capturar(args.count)
        print(f"Mensaje reconstruido: {ipid.decodificar(ids)!r}")
        return 0
    if args.cmd == "mitigate":
        mitigador.ejecutar()
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
