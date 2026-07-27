from webvulnscanner.models import Finding, Risk, ScanResult


def test_orden_severidad():
    assert Risk.ALTO.orden < Risk.MEDIO.orden < Risk.BAJO.orden < Risk.INFO.orden < Risk.OK.orden


def test_finding_to_dict_serializa_riesgo_como_str():
    f = Finding("X", "algo", Risk.ALTO, "desc", referencia="r", evidencia="e")
    d = f.to_dict()
    assert d["riesgo"] == "alto"
    assert d["referencia"] == "r" and d["evidencia"] == "e"


def test_conteo_y_agrupacion():
    r = ScanResult(
        "ej.com",
        ip="1.2.3.4",
        findings=[
            Finding("A", "h1", Risk.ALTO, "d"),
            Finding("A", "h2", Risk.ALTO, "d"),
            Finding("B", "h3", Risk.OK, "d"),
        ],
    )
    assert r.conteo()[Risk.ALTO] == 2
    assert r.conteo()[Risk.OK] == 1
    assert len(r.por_riesgo()[Risk.ALTO]) == 2
