"""Tests del módulo OpenVAS / Greenbone (GVM).

No se conecta a ningún daemon GVM: se prueba lo único propio del módulo, el
parseo del reporte GMP a `Finding` y el mapeo de severidad. La orquestación GMP
(crear target/task, pollear) exige una instancia real y queda fuera del test.
"""

from __future__ import annotations

from webvulnscanner import tools
from webvulnscanner.models import Risk
from webvulnscanner.modules import openvas

# Reporte GMP mínimo pero realista: un High con CVE+CVSS, un Medium y un Log.
_REPORTE = """
<get_reports_response status="200" status_text="OK">
  <report id="r1"><report id="r1">
    <results start="1" max="1000">
      <result id="a">
        <name>OpenSSL Heartbleed</name>
        <host>1.2.3.4</host>
        <port>443/tcp</port>
        <nvt oid="1.3.6.1.4.1.25623.1.0.105">
          <name>SSL/TLS Heartbleed</name>
          <cvss_base>7.5</cvss_base>
          <refs>
            <ref type="cve" id="CVE-2014-0160"/>
            <ref type="url" id="https://heartbleed.com"/>
          </refs>
          <tags>cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:N/A:N|summary=Heartbleed</tags>
        </nvt>
        <threat>High</threat>
        <severity>7.5</severity>
        <description>El servidor es vulnerable a Heartbleed.</description>
      </result>
      <result id="b">
        <name>Weak cipher suites</name>
        <host>1.2.3.4</host>
        <port>443/tcp</port>
        <nvt oid="1.3.6.1.4.1.25623.1.0.900"><name>Ciphers</name></nvt>
        <threat>Medium</threat>
        <severity>4.3</severity>
        <description>Se ofrecen cifrados débiles.</description>
      </result>
      <result id="c">
        <name>Traceroute</name>
        <host>1.2.3.4</host>
        <port>general/tcp</port>
        <nvt oid="1.3.6.1.4.1.25623.1.0.51662"><name>Traceroute</name></nvt>
        <threat>Log</threat>
        <severity>0.0</severity>
        <description>Ruta de red detectada.</description>
      </result>
    </results>
  </report></report>
</get_reports_response>
"""


def test_gate_off_devuelve_vacio(monkeypatch):
    """Degradación elegante: sin GVM disponible, el módulo se omite en silencio."""
    monkeypatch.setattr(tools, "motor_disponible", lambda clave: False)
    assert openvas.analizar("1.2.3.4") == []


def test_parsea_severidad_y_cve():
    findings = openvas._parsear_reporte(_REPORTE)
    assert len(findings) == 3

    alto = next(f for f in findings if "Heartbleed" in f.hallazgo)
    assert alto.riesgo is Risk.ALTO
    assert "CVE-2014-0160" in alto.hallazgo  # participa en el dedupe de CVEs
    assert alto.referencia == "https://heartbleed.com"
    assert alto.cvss == {"vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N", "score": 7.5}
    assert "1.2.3.4:443/tcp" in alto.evidencia

    medio = next(f for f in findings if "cipher" in f.hallazgo.lower())
    assert medio.riesgo is Risk.MEDIO
    assert medio.cvss == {"vector": None, "score": 4.3}

    log_f = next(f for f in findings if "Traceroute" in f.hallazgo)
    assert log_f.riesgo is Risk.INFO
    assert log_f.cvss is None  # severity 0 → sin CVSS


def test_xml_corrupto_no_revienta():
    assert openvas._parsear_reporte("esto no es xml <<<") == []


def test_reporte_vacio_devuelve_vacio():
    assert openvas._parsear_reporte("<get_reports_response/>") == []
