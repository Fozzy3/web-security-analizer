"""Exportación del informe HTML a PDF (opcional, vía weasyprint).

Degradación elegante: si weasyprint no está instalado, `disponible()` es False y
`html_a_pdf` no hace nada. Instálelo con el extra `pdf`.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("webvulnscanner.pdf")

try:
    from weasyprint import HTML

    _WEASY = True
except Exception:  # noqa: BLE001 — cualquier fallo de import/carga → sin PDF
    _WEASY = False


def disponible() -> bool:
    return _WEASY


def html_a_pdf(html_path: Path | str, pdf_path: Path | str | None = None) -> Path | None:
    """Convierte un archivo HTML en PDF. Devuelve la ruta del PDF, o None si no
    hay weasyprint o el HTML no existe."""
    if not _WEASY:
        log.info("  [i] weasyprint no instalado — export a PDF omitido (extra 'pdf')")
        return None
    html_path = Path(html_path)
    if not html_path.exists():
        log.warning("  [x] No existe el HTML para exportar: %s", html_path)
        return None
    destino = Path(pdf_path) if pdf_path else html_path.with_suffix(".pdf")
    HTML(filename=str(html_path)).write_pdf(str(destino))
    log.info("  [+] PDF generado: %s", destino)
    return destino
