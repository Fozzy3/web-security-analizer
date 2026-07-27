"""Punto de entrada de línea de comandos."""

from __future__ import annotations

import argparse
import logging
import sys

from webvulnscanner import __version__
from webvulnscanner.orchestrator import MODULOS, run_scan
from webvulnscanner.report import guardar, render_texto

_MODULOS_VALIDOS = [n for n, _ in MODULOS]


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="webvulnscanner",
        description="Auditor pasivo de seguridad web (académico y ético).",
        epilog="Solo analice sitios propios o con autorización expresa.",
    )
    p.add_argument("dominio", nargs="?", help="dominio objetivo (ej: example.com)")
    p.add_argument(
        "--only", metavar="MODS", help=f"solo estos módulos (coma). Disponibles: {','.join(_MODULOS_VALIDOS)}"
    )
    p.add_argument("--skip", metavar="MODS", help="omitir estos módulos (coma)")
    p.add_argument("-o", "--output", default=".", metavar="DIR", help="carpeta de reportes (def: .)")
    p.add_argument("--no-save", action="store_true", help="no escribir archivos, solo consola")
    p.add_argument("-q", "--quiet", action="store_true", help="silenciar el log de progreso")
    p.add_argument("--version", action="version", version=f"WebVulnScanner {__version__}")
    return p.parse_args(argv)


def _resolver_activos(only: str | None, skip: str | None) -> set[str]:
    activos = set(_MODULOS_VALIDOS)
    if only:
        activos = {m.strip() for m in only.split(",") if m.strip()}
    if skip:
        activos -= {m.strip() for m in skip.split(",") if m.strip()}
    invalidos = activos - set(_MODULOS_VALIDOS)
    if invalidos:
        raise SystemExit(f"Módulos desconocidos: {', '.join(invalidos)}")
    return activos


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    dominio = args.dominio or input("\n  Dominio objetivo (ej: example.com): ").strip()
    if not dominio:
        print("Error: debe indicar un dominio.", file=sys.stderr)
        return 1

    activos = _resolver_activos(args.only, args.skip)

    print("\n" + "=" * 60)
    print("  WebVulnScanner 2.0 — Auditoría pasiva de seguridad web")
    print("=" * 60)

    result = run_scan(dominio, activos=activos)

    print("\n" + render_texto(result))

    if not args.no_save:
        txt, js = guardar(result, args.output)
        print(f"  Reportes guardados:\n  → {txt}\n  → {js}")

    # Código de salida distinto de 0 si hay hallazgos de riesgo alto.
    from webvulnscanner.models import Risk

    return 2 if result.conteo()[Risk.ALTO] else 0


if __name__ == "__main__":
    raise SystemExit(main())
