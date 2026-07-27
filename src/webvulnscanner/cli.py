"""Punto de entrada de línea de comandos."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from webvulnscanner import __version__, diff, sarif
from webvulnscanner.models import Risk
from webvulnscanner.orchestrator import MODULOS, MODULOS_ACTIVOS, run_scan
from webvulnscanner.report import guardar, render_texto

_MODULOS_VALIDOS = [n for n, _ in MODULOS]
_MODULOS_ACTIVOS = [n for n, _ in MODULOS_ACTIVOS]

# Perfiles de escaneo (C5): subconjuntos de módulos para casos comunes.
_PERFILES = {
    "full": set(_MODULOS_VALIDOS),
    "quick": {"recon", "tls", "headers", "waf", "fingerprint"},
    "tls": {"recon", "tls"},
    "web": {"recon", "headers", "waf", "fingerprint", "disclosure"},
    "dns": {"recon", "dns", "subdomains"},
}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="webvulnscanner",
        description="Auditor pasivo de seguridad web (académico y ético).",
        epilog="Solo analice sitios propios o con autorización expresa.",
    )
    p.add_argument("dominio", nargs="?", help="dominio objetivo (ej: example.com)")
    p.add_argument("--profile", choices=sorted(_PERFILES), help="perfil de escaneo (def: full)")
    p.add_argument(
        "--only", metavar="MODS", help=f"solo estos módulos (coma). Disponibles: {','.join(_MODULOS_VALIDOS)}"
    )
    p.add_argument("--skip", metavar="MODS", help="omitir estos módulos (coma)")
    p.add_argument("-o", "--output", default=".", metavar="DIR", help="carpeta de reportes (def: .)")
    p.add_argument("--sarif", action="store_true", help="además, escribir reporte .sarif (CI/GitHub)")
    p.add_argument("--diff", metavar="PREV.json", help="comparar contra un reporte .json anterior")
    p.add_argument(
        "--authorized",
        action="store_true",
        help="habilita módulos ACTIVOS (cookies, CORS, XSS/SQLi, fuzzing). "
        "SOLO en objetivos propios o con autorización expresa.",
    )
    p.add_argument("--no-save", action="store_true", help="no escribir archivos, solo consola")
    p.add_argument("--no-parallel", action="store_true", help="ejecutar módulos en secuencia")
    p.add_argument("-q", "--quiet", action="store_true", help="silenciar el log de progreso")
    p.add_argument("--version", action="version", version=f"WebVulnScanner {__version__}")
    return p.parse_args(argv)


def _resolver_activos(profile: str | None, only: str | None, skip: str | None, autorizado: bool) -> set[str]:
    base = set(_MODULOS_VALIDOS) | (set(_MODULOS_ACTIVOS) if autorizado else set())
    activos = set(_PERFILES[profile]) if profile else set(base)
    if only:
        activos = {m.strip() for m in only.split(",") if m.strip()}
    if skip:
        activos -= {m.strip() for m in skip.split(",") if m.strip()}
    invalidos = activos - base
    if invalidos:
        raise SystemExit(f"Módulos desconocidos o no autorizados: {', '.join(invalidos)}")
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

    activos = _resolver_activos(args.profile, args.only, args.skip, args.authorized)

    print("\n" + "=" * 60)
    print("  WebVulnScanner 2.0 — Auditoría de seguridad web")
    if args.authorized:
        print("  ⚠ MODO ACTIVO — solo para objetivos autorizados")
    print("=" * 60)

    result = run_scan(dominio, activos=activos, paralelo=not args.no_parallel, autorizado=args.authorized)

    print("\n" + render_texto(result))

    if args.diff:
        anterior = diff.cargar_reporte(args.diff)
        print("\n" + diff.render_texto(diff.comparar(anterior, result)))

    if not args.no_save:
        txt, js, htm = guardar(result, args.output)
        print(f"  Reportes guardados:\n  → {txt}\n  → {js}\n  → {htm}")
        if args.sarif:
            ruta_sarif = Path(txt).with_suffix(".sarif")
            ruta_sarif.write_text(sarif.render(result), encoding="utf-8")
            print(f"  → {ruta_sarif}")

    # Código de salida distinto de 0 si hay hallazgos de riesgo alto.
    return 2 if result.conteo()[Risk.ALTO] else 0


if __name__ == "__main__":
    raise SystemExit(main())
