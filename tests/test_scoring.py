from webvulnscanner import scoring
from webvulnscanner.models import Finding, Risk, ScanResult


def _res(*niveles):
    return ScanResult("ej.com", findings=[Finding("M", "h", n, "d") for n in niveles])


def test_sin_problemas_es_A():
    ltr, pts = scoring.calcular(_res(Risk.INFO, Risk.OK, Risk.OK))
    assert ltr == "A" and pts == 100


def test_un_alto_baja_la_nota():
    _, pts = scoring.calcular(_res(Risk.ALTO))
    assert pts == 75  # 100 - 25


def test_muchos_altos_dan_F():
    ltr, _ = scoring.calcular(_res(*[Risk.ALTO] * 4))
    assert ltr == "F"  # 100 - 100 = 0


def test_bonus_ok_tiene_tope():
    # 10 OK → bonus tope 10, pero no supera 100
    _, pts = scoring.calcular(_res(*[Risk.OK] * 10))
    assert pts == 100


def test_umbrales_de_letra():
    assert scoring.letra(90) == "A"
    assert scoring.letra(89) == "B"
    assert scoring.letra(49) == "F"
