"""Interfaz gráfica — WebVulnScanner 2.0.

Se comunica con el núcleo vía `logging` (un handler empuja los registros a una
cola que la UI consume), no secuestrando sys.stdout. El escaneo corre en un
hilo aparte para no congelar la ventana.

Requiere: pip install -e ".[gui]"   (customtkinter)
"""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import threading

import customtkinter as ctk

from webvulnscanner import report
from webvulnscanner.models import Risk
from webvulnscanner.orchestrator import run_scan

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORES_NIVEL = {
    "alto": "#ef4444",
    "medio": "#f59e0b",
    "bajo": "#22c55e",
    "info": "#3b82f6",
    "ok": "#10b981",
}
EMOJIS_NIVEL = {"alto": "🔴", "medio": "🟡", "bajo": "🟢", "info": "🔵", "ok": "✅"}


class QueueLogHandler(logging.Handler):
    """Handler que empuja cada registro del scanner a una cola de la UI."""

    def __init__(self, q: queue.Queue):
        super().__init__()
        self._q = q

    def emit(self, record: logging.LogRecord):
        msg = record.getMessage()
        if msg.strip():
            self._q.put(("log", msg.rstrip()))


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WebVulnScanner 2.0 — Auditoría de Seguridad Web")
        self.geometry("1180x800")
        self.minsize(980, 660)

        self._q: queue.Queue = queue.Queue()
        self._result = None
        self._scanning = False
        self._rutas = None

        self._log_handler = QueueLogHandler(self._q)
        self._log_handler.setLevel(logging.INFO)

        self._build_ui()
        self._poll_queue()

    # ── UI ────────────────────────────────────────────────────
    def _build_ui(self):
        header = ctk.CTkFrame(self, height=64, corner_radius=0, fg_color="#1e293b")
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header,
            text="🔍  WebVulnScanner 2.0",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#f8fafc",
        ).pack(side="left", padx=20)
        ctk.CTkLabel(
            header,
            text="Auditoría pasiva · TLS · DNS · Subdominios · CVEs",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
        ).pack(side="left", padx=4)

        bar = ctk.CTkFrame(self, height=58, fg_color="#0f172a")
        bar.pack(fill="x")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, text="Dominio:", font=ctk.CTkFont(size=13)).pack(side="left", padx=(18, 6))
        self.entry = ctk.CTkEntry(bar, placeholder_text="ej: example.com", width=340, height=34)
        self.entry.pack(side="left", padx=(0, 10))
        self.entry.bind("<Return>", lambda _e: self._iniciar())
        self.btn_scan = ctk.CTkButton(
            bar,
            text="▶  Escanear",
            width=130,
            height=34,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._iniciar,
        )
        self.btn_scan.pack(side="left")
        self.btn_open = ctk.CTkButton(
            bar,
            text="📂  Abrir carpeta",
            width=140,
            height=34,
            font=ctk.CTkFont(size=12),
            fg_color="#334155",
            hover_color="#475569",
            state="disabled",
            command=self._abrir_carpeta,
        )
        self.btn_open.pack(side="left", padx=(10, 0))
        self.lbl_estado = ctk.CTkLabel(bar, text="", font=ctk.CTkFont(size=11), text_color="#64748b")
        self.lbl_estado.pack(side="left", padx=14)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=8)
        body.columnconfigure(0, weight=5)
        body.columnconfigure(1, weight=8)
        body.rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)
        ctk.CTkLabel(left, text="Progreso del escaneo", font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4)
        )
        self.txt_log = ctk.CTkTextbox(left, font=ctk.CTkFont(family="monospace", size=10), wrap="word")
        self.txt_log.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 6))
        self.txt_log.configure(state="disabled")
        self.resumen_frame = ctk.CTkFrame(left)
        self.resumen_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
        self._build_cards()

        right = ctk.CTkFrame(body)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)
        ctk.CTkLabel(right, text="Resultados del análisis", font=ctk.CTkFont(size=12, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4)
        )
        self.tabs = ctk.CTkTabview(right, anchor="nw")
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._t = ("🔴  Problemas", "✅  Buenas prácticas", "🔵  Informativo", "📄  Reporte completo")
        for n in self._t:
            self.tabs.add(n)
        self.sc_problemas = ctk.CTkScrollableFrame(self.tabs.tab(self._t[0]))
        self.sc_problemas.pack(fill="both", expand=True)
        self.sc_ok = ctk.CTkScrollableFrame(self.tabs.tab(self._t[1]))
        self.sc_ok.pack(fill="both", expand=True)
        self.sc_info = ctk.CTkScrollableFrame(self.tabs.tab(self._t[2]))
        self.sc_info.pack(fill="both", expand=True)
        self.txt_reporte = ctk.CTkTextbox(
            self.tabs.tab(self._t[3]), font=ctk.CTkFont(family="monospace", size=10), wrap="word"
        )
        self.txt_reporte.pack(fill="both", expand=True)
        self.txt_reporte.configure(state="disabled")

        ctk.CTkLabel(
            self,
            text="⚠  Uso académico y ético. Solo analice sitios propios o con autorización expresa.",
            font=ctk.CTkFont(size=10),
            text_color="#475569",
        ).pack(pady=(0, 6))

    def _build_cards(self):
        for w in self.resumen_frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.resumen_frame, text="Resumen", font=ctk.CTkFont(size=11, weight="bold")).grid(
            row=0, column=0, columnspan=5, sticky="w", padx=10, pady=(6, 2)
        )
        self._cards: dict[str, ctk.StringVar] = {}
        for col, (nivel, emoji, txt) in enumerate(
            [
                ("alto", "🔴", "Alto"),
                ("medio", "🟡", "Medio"),
                ("bajo", "🟢", "Bajo"),
                ("info", "🔵", "Info"),
                ("ok", "✅", "OK"),
            ]
        ):
            self.resumen_frame.columnconfigure(col, weight=1)
            card = ctk.CTkFrame(self.resumen_frame, border_color=COLORES_NIVEL[nivel], border_width=2)
            card.grid(row=1, column=col, padx=4, pady=(2, 8), sticky="ew")
            ctk.CTkLabel(card, text=emoji, font=ctk.CTkFont(size=18)).pack(pady=(6, 0))
            var = ctk.StringVar(value="—")
            self._cards[nivel] = var
            ctk.CTkLabel(
                card,
                textvariable=var,
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color=COLORES_NIVEL[nivel],
            ).pack()
            ctk.CTkLabel(card, text=txt, font=ctk.CTkFont(size=10), text_color="gray").pack(pady=(0, 6))

    # ── Escaneo ───────────────────────────────────────────────
    def _iniciar(self):
        if self._scanning:
            return
        dominio = self.entry.get().strip()
        if not dominio:
            self._log("⚠  Ingrese un dominio válido.")
            return
        self._limpiar()
        self._scanning = True
        self.btn_scan.configure(state="disabled", text="⏳  Escaneando...")
        self.btn_open.configure(state="disabled")
        self.lbl_estado.configure(text=f"Analizando {dominio}...", text_color="#60a5fa")
        threading.Thread(target=self._run, args=(dominio,), daemon=True).start()

    def _run(self, dominio: str):
        logger = logging.getLogger("webvulnscanner")
        logger.setLevel(logging.INFO)
        logger.addHandler(self._log_handler)
        try:
            result = run_scan(dominio)
            rutas = report.guardar(result)
            self._q.put(("done", (result, rutas)))
        except Exception as exc:  # noqa: BLE001
            self._q.put(("error", str(exc)))
        finally:
            logger.removeHandler(self._log_handler)

    def _poll_queue(self):
        try:
            while True:
                tipo, data = self._q.get_nowait()
                if tipo == "log":
                    self._log(data)
                elif tipo == "error":
                    self._log(f"\n❌  {data}")
                    self._reset(error=True)
                elif tipo == "done":
                    self._completo(*data)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _log(self, text: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", text + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _completo(self, result, rutas):
        self._result = result
        self._rutas = rutas
        conteo = result.conteo()
        for nivel, var in self._cards.items():
            var.set(str(conteo[Risk(nivel)]))
        self._poblar()
        self.txt_reporte.configure(state="normal")
        self.txt_reporte.insert("1.0", report.render_texto(result))
        self.txt_reporte.configure(state="disabled")
        self.tabs.set(self._t[0])
        self._reset(error=False)
        self.btn_open.configure(state="normal")
        self.lbl_estado.configure(text=f"✅  Completado · {rutas[0].name}", text_color="#22c55e")

    def _reset(self, error=False):
        self._scanning = False
        self.btn_scan.configure(state="normal", text="▶  Escanear")
        if error:
            self.lbl_estado.configure(text="Error en el escaneo.", text_color="#ef4444")

    def _limpiar(self):
        for f in (self.sc_problemas, self.sc_ok, self.sc_info):
            for w in f.winfo_children():
                w.destroy()
        for var in getattr(self, "_cards", {}).values():
            var.set("—")
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.txt_reporte.configure(state="normal")
        self.txt_reporte.delete("1.0", "end")
        self.txt_reporte.configure(state="disabled")

    def _tarjeta(self, parent, h):
        nivel = h.riesgo.value
        color = COLORES_NIVEL.get(nivel, "#64748b")
        card = ctk.CTkFrame(parent, border_color=color, border_width=2)
        card.pack(fill="x", padx=6, pady=(0, 6))
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(8, 2))
        ctk.CTkLabel(
            top,
            text=f"{EMOJIS_NIVEL.get(nivel, '')}  [{h.modulo}]",
            font=ctk.CTkFont(size=10),
            text_color=color,
            anchor="w",
        ).pack(side="left")
        ctk.CTkLabel(
            card,
            text=h.hallazgo,
            font=ctk.CTkFont(size=12, weight="bold"),
            wraplength=560,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 2))
        ctk.CTkLabel(
            card,
            text=h.descripcion,
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8",
            wraplength=560,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 8))
        if h.referencia:
            ctk.CTkLabel(
                card,
                text=f"🔗 {h.referencia}",
                font=ctk.CTkFont(size=10),
                text_color="#60a5fa",
                wraplength=560,
                justify="left",
                anchor="w",
            ).pack(fill="x", padx=14, pady=(0, 8))

    def _poblar(self):
        por = self._result.por_riesgo()
        # Problemas
        encontro = False
        for nivel in (Risk.ALTO, Risk.MEDIO, Risk.BAJO):
            items = por[nivel]
            if not items:
                continue
            encontro = True
            titulo = {
                Risk.ALTO: "🔴  Riesgo alto",
                Risk.MEDIO: "🟡  Riesgo moderado",
                Risk.BAJO: "🟢  Bajo impacto",
            }[nivel]
            ctk.CTkLabel(
                self.sc_problemas,
                text=titulo,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORES_NIVEL[nivel.value],
                anchor="w",
            ).pack(fill="x", padx=8, pady=(12, 4))
            for h in items:
                self._tarjeta(self.sc_problemas, h)
        if not encontro:
            ctk.CTkLabel(
                self.sc_problemas, text="✅  No se detectaron problemas.", font=ctk.CTkFont(size=14)
            ).pack(pady=40)
        # OK
        if por[Risk.OK]:
            for h in por[Risk.OK]:
                self._tarjeta(self.sc_ok, h)
        else:
            ctk.CTkLabel(self.sc_ok, text="Sin controles confirmados.", font=ctk.CTkFont(size=13)).pack(
                pady=40
            )
        # Info
        if por[Risk.INFO]:
            for h in por[Risk.INFO]:
                self._tarjeta(self.sc_info, h)
        else:
            ctk.CTkLabel(self.sc_info, text="Sin hallazgos informativos.", font=ctk.CTkFont(size=13)).pack(
                pady=40
            )

    def _abrir_carpeta(self):
        carpeta = os.path.dirname(os.path.abspath(self._rutas[0])) if self._rutas else os.getcwd()
        try:
            subprocess.Popen(["xdg-open", carpeta])
        except Exception:  # noqa: BLE001
            self._log(f"\n📂  Reportes en: {carpeta}")


if __name__ == "__main__":
    App().mainloop()
