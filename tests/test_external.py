"""Tests de los wrappers de herramientas externas.

No se ejecuta ningún binario: se sustituye `tools.ejecutar` por salidas de
ejemplo. Lo que se prueba es el parseo y el mapeo de severidad, que es lo único
propio de este módulo.
"""

from __future__ import annotations

import json

import pytest

from webvulnscanner import tools
from webvulnscanner.models import Risk
from webvulnscanner.modules import external


@pytest.fixture
def salida(monkeypatch):
    """Fija la salida de la herramienta externa. `None` = binario ausente."""

    def _set(texto):
        monkeypatch.setattr(tools, "ejecutar", lambda cmd, **kw: texto)

    return _set


@pytest.mark.parametrize(
    "fn", [external.nuclei, external.nmap, external.testssl, external.wpscan, external.subfinder]
)
@pytest.mark.parametrize("vacio", [None, "", "   \n  "])
def test_sin_binario_o_sin_salida_devuelve_vacio(fn, vacio, salida):
    """Degradación elegante: si la herramienta no está, el módulo no estorba."""
    salida(vacio)
    assert fn("example.com") == []


@pytest.mark.parametrize(
    "fn", [external.nuclei, external.nmap, external.testssl, external.wpscan, external.subfinder]
)
def test_salida_corrupta_no_revienta(fn, salida):
    salida("esto no es json ni xml <<<")
    assert fn("example.com") == []


# ── nuclei ───────────────────────────────────────────────────


def test_nuclei_parsea_jsonl_y_severidad(salida):
    salida(
        "\n".join(
            [
                json.dumps(
                    {
                        "template-id": "cve-2021-44228",
                        "info": {"name": "Log4Shell", "severity": "critical", "description": "RCE"},
                        "matched-at": "https://example.com/api",
                    }
                ),
                "",  # línea en blanco: se ignora
                "{roto",  # JSON inválido: se salta sin abortar
                json.dumps({"template-id": "tech-detect", "info": {"severity": "info"}}),
            ]
        )
    )
    a, b = external.nuclei("example.com")
    assert (a.hallazgo, a.riesgo, a.referencia) == ("Log4Shell", Risk.ALTO, "https://example.com/api")
    assert a.evidencia == "cve-2021-44228"
    assert (b.hallazgo, b.riesgo) == ("tech-detect", Risk.INFO)  # cae al template-id


def test_nuclei_severidad_desconocida_es_info(salida):
    salida(json.dumps({"template-id": "x", "info": {"name": "N", "severity": "inventada"}}))
    assert external.nuclei("example.com")[0].riesgo is Risk.INFO


# ── nmap ─────────────────────────────────────────────────────

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port portid="443"><state state="open"/>
        <service product="nginx" version="1.18.0"/>
        <script id="ssl-heartbleed" output="  VULNERABLE: The Heartbleed Bug"/>
        <script id="http-enum" output="nada interesante"/>
      </port>
      <port portid="22"><state state="closed"/>
        <script id="ssh-vuln" output="VULNERABLE: algo"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_solo_puertos_abiertos_y_vulnerables(salida):
    salida(_NMAP_XML)
    (f,) = external.nmap("1.2.3.4")  # el puerto 22 cerrado y http-enum quedan fuera
    assert f.riesgo is Risk.ALTO
    assert f.hallazgo == "Puerto 443 (nginx 1.18.0): ssl-heartbleed"
    assert "Heartbleed" in f.descripcion


def test_nmap_sin_servicio_no_falla(salida):
    salida(
        '<nmaprun><host><ports><port portid="80"><state state="open"/>'
        '<script id="vulners" output="cpe"/></port></ports></host></nmaprun>'
    )
    (f,) = external.nmap("1.2.3.4")
    assert "Puerto 80" in f.hallazgo  # vulners entra aunque no diga VULNERABLE


# ── testssl ──────────────────────────────────────────────────


def test_testssl_filtra_ok_e_info(salida):
    salida(
        json.dumps(
            [
                {"id": "BEAST", "severity": "MEDIUM", "finding": "VULNERABLE"},
                {"id": "cert_trust", "severity": "OK", "finding": "todo bien"},
                {"id": "banner", "severity": "INFO", "finding": "nginx"},
            ]
        )
    )
    (f,) = external.testssl("example.com")
    assert f.riesgo is Risk.MEDIO
    assert f.evidencia == "BEAST"


def test_testssl_formato_scanresult(salida):
    salida(json.dumps({"scanResult": [{"id": "RC4", "severity": "HIGH", "finding": "ofrecido"}]}))
    (f,) = external.testssl("example.com")
    assert f.riesgo is Risk.ALTO


# ── wpscan ───────────────────────────────────────────────────


def test_wpscan_core_plugins_y_temas(salida):
    salida(
        json.dumps(
            {
                "version": {
                    "number": "5.8",
                    "vulnerabilities": [
                        {
                            "title": "XSS en core",
                            "references": {"url": ["https://wpvulndb/1"], "cve": ["2021-1", "2021-2"]},
                        }
                    ],
                },
                "plugins": {"contact-form-7": {"vulnerabilities": [{"title": "SQLi"}]}},
                "themes": {"twentyone": {"vulnerabilities": []}},
            }
        )
    )
    core, plugin = external.wpscan("example.com")
    assert core.hallazgo == "WordPress core 5.8: XSS en core"
    assert core.referencia == "https://wpvulndb/1"
    assert core.evidencia == "2021-1, 2021-2"
    assert plugin.hallazgo == "plugin contact-form-7: SQLi"
    assert plugin.referencia is None and plugin.evidencia is None


def test_wpscan_sin_wordpress(salida):
    salida(json.dumps({"version": None, "plugins": None, "themes": None}))
    assert external.wpscan("example.com") == []


# ── subfinder ────────────────────────────────────────────────


def test_subfinder_deduplica_y_ordena(salida):
    salida("b.example.com\na.example.com\nb.example.com\n\n  \n")
    (f,) = external.subfinder("example.com")
    assert f.riesgo is Risk.INFO
    assert "2 subdominios" in f.hallazgo
    assert f.evidencia == "a.example.com\nb.example.com"


def test_subfinder_solo_blancos_devuelve_vacio(salida):
    salida("\n\n   \n")
    assert external.subfinder("example.com") == []


def test_subfinder_descarta_lineas_que_no_son_host(salida):
    """Los avisos que subfinder mezcla en stdout no deben pasar por subdominios."""
    salida("[INF] enumerando fuentes...\napi.example.com\nerror: rate limited\n")
    (f,) = external.subfinder("example.com")
    assert f.evidencia == "api.example.com"
