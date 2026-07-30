"""Punto de entrada de línea de comandos."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from webvulnscanner import __version__, baseline, diff, informe, sarif, sbom, tools
from webvulnscanner.models import Risk
from webvulnscanner.net import Sesion
from webvulnscanner.orchestrator import MODULOS, MODULOS_ACTIVOS, run_scan
from webvulnscanner.report import guardar, render_texto

_MODULOS_VALIDOS = [n for n, _ in MODULOS]
_MODULOS_ACTIVOS = [n for n, _ in MODULOS_ACTIVOS]

# Perfiles de escaneo (C5): subconjuntos de módulos para casos comunes.
# "full" es None a propósito: significa "todo lo disponible", que con
# --authorized incluye los módulos activos (un set fijo los dejaría fuera).
_PERFILES: dict[str, set[str] | None] = {
    "full": None,
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
        "--baseline", metavar="FILE", help="suprimir hallazgos listados en el baseline (def: .wvsignore)"
    )
    p.add_argument(
        "--write-baseline", metavar="FILE", help="escribir el escaneo actual como baseline aceptado"
    )
    p.add_argument("--sbom", metavar="FILE", help="escribir un SBOM CycloneDX de los componentes detectados")
    p.add_argument(
        "--rl-burst",
        type=int,
        default=12,
        metavar="N",
        help="tamaño de la ráfaga del módulo rate_limit (API4:2023, def: 12); respeta --delay/--rps",
    )
    p.add_argument("--no-save", action="store_true", help="no escribir archivos, solo consola")
    p.add_argument("--no-parallel", action="store_true", help="ejecutar módulos en secuencia")
    p.add_argument("-q", "--quiet", action="store_true", help="silenciar el log de progreso")
    p.add_argument(
        "--check-tools",
        action="store_true",
        help="listar los motores externos (nuclei, nmap, wpscan…), su estado y cómo instalarlos, y salir",
    )
    p.add_argument("--version", action="version", version=f"WebVulnScanner {__version__}")

    # Sesión: credenciales para escanear zonas autenticadas + cortesía (throttle).
    g = p.add_argument_group("sesión / cortesía")
    g.add_argument("--cookie", metavar="C", help="cookie de sesión (ej: 'sid=abc')")
    g.add_argument("--bearer", metavar="TOKEN", help="token Bearer (cabecera Authorization)")
    g.add_argument(
        "--header", metavar="'K: V'", action="append", default=[], help="cabecera extra (repetible)"
    )
    g.add_argument("--delay", type=float, metavar="SEG", help="espera entre peticiones (segundos)")
    g.add_argument("--rps", type=float, metavar="N", help="límite de peticiones/segundo (alt. a --delay)")
    return p.parse_args(argv)


def _construir_sesion(args: argparse.Namespace) -> Sesion:
    """Arma la Sesion (headers de auth + throttle) desde los flags."""
    headers: dict[str, str] = {}
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.bearer:
        headers["Authorization"] = f"Bearer {args.bearer}"
    for h in args.header:
        clave, sep, valor = h.partition(":")
        if sep:
            headers[clave.strip()] = valor.strip()
    # --delay tiene prioridad; si no, se deriva de --rps; por defecto 0.
    delay = args.delay if args.delay is not None else (1.0 / args.rps if args.rps else 0.0)
    return Sesion(headers=headers, delay=delay)


def _resolver_activos(profile: str | None, only: str | None, skip: str | None) -> set[str]:
    base = set(_MODULOS_VALIDOS) | set(_MODULOS_ACTIVOS)  # siempre todo (pasivos + activos)
    seleccion = _PERFILES[profile] if profile else None
    activos = set(seleccion) if seleccion is not None else set(base)
    if only:
        activos = {m.strip() for m in only.split(",") if m.strip()}
    if skip:
        activos -= {m.strip() for m in skip.split(",") if m.strip()}
    invalidos = activos - base
    if invalidos:
        raise SystemExit(f"Módulos desconocidos o no autorizados: {', '.join(invalidos)}")
    return activos


def _imprimir_motores() -> None:
    """Doctor: estado de cada motor externo opcional y cómo instalarlo (para agentes)."""
    print("\nMotores externos (opcionales) — la herramienta los usa automáticamente si están instalados:\n")
    for _clave, (etq, chk, cmd) in tools.MOTORES.items():
        if chk():
            print(f"  [✓ instalado] {etq}")
        else:
            print(f"  [✗ falta    ] {etq}\n                 instalar: {cmd}")
    print(
        "\n  Shodan: consulta gratis vía InternetDB (sin API key). "
        "Con SHODAN_API_KEY usa además la Host API (datos más ricos)."
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    if args.check_tools:
        _imprimir_motores()
        return 0

    # Solo se pregunta en modo interactivo: en un pipe o en CI, input() colgaría
    # el proceso o reventaría con EOFError en vez de dar un error legible.
    dominio = args.dominio or ""
    if not dominio and sys.stdin.isatty():
        dominio = input("\n  Dominio objetivo (ej: example.com): ").strip()
    if not dominio:
        print("Error: debe indicar un dominio.", file=sys.stderr)
        return 1

    activos = _resolver_activos(args.profile, args.only, args.skip)

    print("\n" + "=" * 60)
    print("  WebVulnScanner 2.0 — Auditoría de seguridad web")
    print("  ⚠ ESCANEO ACTIVO COMPLETO — solo sobre objetivos propios o autorizados")
    print("=" * 60)

    def _informe_parcial(parcial: object) -> None:
        # 1ª fase: emite el informe ya (con las herramientas lentas "en progreso");
        # el auto-refresh del HTML lo actualizará cuando termine la 2ª fase.
        if args.no_save:
            return
        ruta = Path(args.output) / "informe.html"
        ruta.write_text(informe.generar(parcial), encoding="utf-8")  # type: ignore[arg-type]
        print(f"  📄 Informe parcial listo (análisis profundo en curso): {ruta}")

    try:
        result = run_scan(
            dominio,
            activos=activos,
            paralelo=not args.no_parallel,
            sesion=_construir_sesion(args),
            rl_burst=args.rl_burst,
            on_parcial=_informe_parcial,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.sbom:
        doc = sbom.generar(sbom.componentes_de(result.findings))
        Path(args.sbom).write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  SBOM CycloneDX escrito: {args.sbom} ({len(doc['components'])} componentes)")

    # Baseline: escribir el escaneo como aceptado, o suprimir lo ya aceptado.
    if args.write_baseline:
        baseline.escribir(args.write_baseline, result.findings)
        print(f"  Baseline escrito: {args.write_baseline} ({len(result.findings)} hallazgos)")
    ruta_baseline = args.baseline or (".wvsignore" if Path(".wvsignore").exists() else None)
    if ruta_baseline:
        antes = len(result.findings)
        result.findings = baseline.filtrar(result.findings, baseline.cargar(ruta_baseline))
        print(f"  Baseline aplicado ({ruta_baseline}): {antes - len(result.findings)} suprimidos")

    print("\n" + render_texto(result))

    faltantes = tools.motores_faltantes()
    if faltantes:
        print("\n  ⚙ Motores externos no instalados (instalalos para cobertura completa):")
        for etq, cmd in faltantes:
            print(f"    • {etq:14} → {cmd}")
        print("    (ver 'webvulnscanner --check-tools')")

    if args.diff:
        anterior = diff.cargar_reporte(args.diff)
        print("\n" + diff.render_texto(diff.comparar(anterior, result)))

    if not args.no_save:
        txt, js, htm = guardar(result, args.output)
        # Informe curado de 3 pestañas, generado automáticamente desde el escaneo.
        ruta_informe = Path(args.output) / "informe.html"
        ruta_informe.write_text(informe.generar(result), encoding="utf-8")
        print(f"  Reportes guardados:\n  → {ruta_informe}\n  → {js}")
        if args.sarif:
            ruta_sarif = Path(txt).with_suffix(".sarif")
            ruta_sarif.write_text(sarif.render(result), encoding="utf-8")
            print(f"  → {ruta_sarif}")

    # Código de salida distinto de 0 si hay hallazgos de riesgo alto.
    return 2 if result.conteo()[Risk.ALTO] else 0


if __name__ == "__main__":
    raise SystemExit(main())
