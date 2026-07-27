"""Modelo de dominio: hallazgos, niveles de riesgo y resultado del escaneo.

Núcleo puro sin dependencias de red ni de UI. Todo lo demás depende de esto,
nunca al revés.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Risk(str, Enum):
    """Nivel de riesgo de un hallazgo. Hereda de str para serializar a JSON."""

    ALTO = "alto"
    MEDIO = "medio"
    BAJO = "bajo"
    INFO = "info"
    OK = "ok"

    @property
    def emoji(self) -> str:
        return _EMOJI[self]

    @property
    def orden(self) -> int:
        """Orden de severidad para ordenar: alto=0 ... ok=4."""
        return _ORDEN[self]


_EMOJI = {
    Risk.ALTO: "🔴",
    Risk.MEDIO: "🟡",
    Risk.BAJO: "🟢",
    Risk.INFO: "🔵",
    Risk.OK: "✅",
}

_ORDEN = {Risk.ALTO: 0, Risk.MEDIO: 1, Risk.BAJO: 2, Risk.INFO: 3, Risk.OK: 4}


@dataclass
class Finding:
    """Un hallazgo individual del análisis.

    `referencia` guarda un enlace/CVE/RFC de apoyo; `evidencia` el dato crudo
    que sustenta el hallazgo (banner, valor de header, etc.).
    """

    modulo: str
    hallazgo: str
    riesgo: Risk
    descripcion: str
    referencia: str | None = None
    evidencia: str | None = None

    def to_dict(self) -> dict:
        return {
            "modulo": self.modulo,
            "hallazgo": self.hallazgo,
            "riesgo": self.riesgo.value,
            "descripcion": self.descripcion,
            "referencia": self.referencia,
            "evidencia": self.evidencia,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            modulo=d["modulo"],
            hallazgo=d["hallazgo"],
            riesgo=Risk(d["riesgo"]),
            descripcion=d.get("descripcion", ""),
            referencia=d.get("referencia"),
            evidencia=d.get("evidencia"),
        )


@dataclass
class ScanResult:
    """Resultado completo de un escaneo sobre un objetivo."""

    dominio: str
    ip: str | None = None
    servidor: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def por_riesgo(self) -> dict[Risk, list[Finding]]:
        agrupado: dict[Risk, list[Finding]] = {r: [] for r in Risk}
        for f in self.findings:
            agrupado[f.riesgo].append(f)
        return agrupado

    def conteo(self) -> dict[Risk, int]:
        return {r: len(items) for r, items in self.por_riesgo().items()}

    @classmethod
    def from_json(cls, payload: dict) -> ScanResult:
        """Reconstruye un ScanResult desde un reporte .json previo."""
        meta = payload.get("meta", {})
        return cls(
            dominio=meta.get("dominio", "?"),
            ip=meta.get("ip"),
            servidor=meta.get("servidor"),
            findings=[Finding.from_dict(h) for h in payload.get("hallazgos", [])],
        )
