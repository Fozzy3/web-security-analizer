"""Fase O: baseline de supresión de hallazgos aceptados (CI sin ruido)."""

from __future__ import annotations

from webvulnscanner import baseline
from webvulnscanner.models import Finding, Risk


def _f(modulo="Headers", hallazgo="CSP ausente", ref="/"):
    return Finding(modulo, hallazgo, Risk.MEDIO, "desc que puede variar", referencia=ref)


def test_huella_estable_e_independiente_de_descripcion():
    a = _f()
    b = Finding("Headers", "CSP ausente", Risk.MEDIO, "OTRA descripción distinta", referencia="/")
    assert baseline.huella(a) == baseline.huella(b)


def test_huella_cambia_con_modulo_o_hallazgo():
    assert baseline.huella(_f()) != baseline.huella(_f(hallazgo="otro"))
    assert baseline.huella(_f()) != baseline.huella(_f(modulo="TLS"))


def test_filtrar_suprime_los_del_baseline():
    f1, f2 = _f(hallazgo="uno"), _f(hallazgo="dos")
    huellas = {baseline.huella(f1)}
    quedan = baseline.filtrar([f1, f2], huellas)
    assert quedan == [f2]


def test_round_trip_escribir_cargar(tmp_path):
    ruta = tmp_path / ".wvsignore"
    fs = [_f(hallazgo="uno"), _f(hallazgo="dos")]
    baseline.escribir(ruta, fs)
    huellas = baseline.cargar(ruta)
    assert baseline.filtrar(fs, huellas) == []


def test_cargar_ignora_comentarios_y_vacios(tmp_path):
    ruta = tmp_path / ".wvsignore"
    ruta.write_text("# comentario\n\nabc123\n  \n", encoding="utf-8")
    assert baseline.cargar(ruta) == {"abc123"}


def test_cargar_inexistente_es_vacio(tmp_path):
    assert baseline.cargar(tmp_path / "no-existe") == set()
