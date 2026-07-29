"""Tests del export a PDF (weasyprint opcional)."""

from __future__ import annotations

import pytest

from webvulnscanner import pdf


def test_html_inexistente_devuelve_none(tmp_path):
    assert pdf.html_a_pdf(tmp_path / "no-existe.html") is None


@pytest.mark.skipif(not pdf.disponible(), reason="weasyprint no instalado")
def test_genera_pdf_real(tmp_path):
    html = tmp_path / "informe.html"
    html.write_text("<h1>Informe de prueba</h1><p>contenido</p>", encoding="utf-8")
    out = pdf.html_a_pdf(html)
    assert out is not None and out.exists() and out.suffix == ".pdf"
    assert out.read_bytes()[:4] == b"%PDF"  # firma de un PDF válido


def test_sin_weasyprint_no_falla(monkeypatch, tmp_path):
    """Si weasyprint no está, degrada a None sin lanzar."""
    monkeypatch.setattr(pdf, "_WEASY", False)
    html = tmp_path / "x.html"
    html.write_text("<p>x</p>", encoding="utf-8")
    assert pdf.html_a_pdf(html) is None
