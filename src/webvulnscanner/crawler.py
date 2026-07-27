"""Crawler ligero: descubre URLs, parámetros y formularios del mismo host.

Es la pieza que habilita el testing activo real (inyección sobre parámetros
descubiertos, no solo sobre la raíz). Respeta un límite de páginas y de
profundidad para no martillar el objetivo, y se queda en el mismo host.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from webvulnscanner.net import fetch

log = logging.getLogger("webvulnscanner.crawler")


@dataclass
class Form:
    action: str
    method: str
    inputs: list[str]


@dataclass
class Crawl:
    urls: set[str] = field(default_factory=set)
    params: dict[str, set[str]] = field(default_factory=dict)  # url_path -> nombres de parámetros
    forms: list[Form] = field(default_factory=list)
    scripts: set[str] = field(default_factory=set)  # URLs de <script src> (mismo host)


class _Parser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.enlaces: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        d = {k: (v or "") for k, v in attrs}
        if tag == "a" and d.get("href"):
            self.enlaces.append(urljoin(self.base, d["href"]))
        elif tag == "script" and d.get("src"):
            self.scripts.append(urljoin(self.base, d["src"]))
        elif tag == "form":
            self._form = Form(urljoin(self.base, d.get("action", "")), d.get("method", "get").lower(), [])
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and d.get("name"):
            self._form.inputs.append(d["name"])

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._form = None


def _mismo_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).hostname in (host, f"www.{host}", host.removeprefix("www."))
    except ValueError:
        return False


def rastrear(dominio: str, *, max_paginas: int = 25, max_prof: int = 2) -> Crawl:
    """Recorre el sitio en anchura y devuelve lo descubierto."""
    crawl = Crawl()
    vistos: set[str] = set()
    cola: list[tuple[str, int]] = [("/", 0)]

    while cola and len(vistos) < max_paginas:
        ruta, prof = cola.pop(0)
        if ruta in vistos:
            continue
        vistos.add(ruta)

        resp = fetch(dominio, ruta, max_body=300_000)
        if resp is None or "html" not in (resp.header("content-type") or "html"):
            continue

        base = f"{resp.esquema}://{dominio}{ruta}"
        url_completa = base
        crawl.urls.add(url_completa)

        # Parámetros de la propia URL
        q = urlparse(ruta).query
        if q:
            camino = urlparse(ruta).path
            crawl.params.setdefault(camino, set()).update(parse_qs(q).keys())

        p = _Parser(base)
        with contextlib.suppress(Exception):  # HTML roto no debe abortar el crawl
            p.feed(resp.body)

        crawl.forms.extend(p.forms)
        for s in p.scripts:
            if _mismo_host(s, dominio):
                crawl.scripts.add(s)

        # Encolar enlaces internos nuevos
        if prof < max_prof:
            for enlace in p.enlaces:
                if not _mismo_host(enlace, dominio):
                    continue
                u = urlparse(enlace)
                nueva = u.path or "/"
                if u.query:
                    nueva = f"{nueva}?{u.query}"
                    crawl.params.setdefault(u.path, set()).update(parse_qs(u.query).keys())
                if nueva not in vistos:
                    cola.append((nueva, prof + 1))

    log.info(
        "  [+] Crawler: %d páginas, %d rutas con params, %d formularios, %d scripts",
        len(crawl.urls),
        len(crawl.params),
        len(crawl.forms),
        len(crawl.scripts),
    )
    return crawl
