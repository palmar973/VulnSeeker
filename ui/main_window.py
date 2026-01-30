#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise - FASE 20: GOLD MASTER UI (FINAL REPAIRED).
- FIX CRÍTICO: Reintegración de métodos PDF faltantes/mal indentados.
- FIX UI: Gráfico de barras ajustado + Layout optimizado + Paneles Compactos.
"""

import customtkinter as ctk
from customtkinter import CTkInputDialog
import logging
import threading
import sys
import os
import queue
import traceback
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import matplotlib
import tkinter.filedialog as filedialog

matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

# --- IMPORTS DEL BACKEND ---
from core.db_manager import DatabaseManager
from core.engine import VulnSeekerEngine
from core.config import GlobalConfig
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from modules.header_analyzer import HeaderAnalyzer
from modules.port_scanner import PortScanner
from modules.path_fuzzer import PathFuzzer
from modules.ai_analyst import GroqAIAnalyst
from reports.report_generator import ReportGenerator
from reports.pdf_generator import PDFReportGenerator
from modules.waf_detector import WAFDetector
from modules.cms_auditor import CMSAuditor
from modules.dummy_module import DummyScanner as DummyModule
# --------------------------------------

plt.style.use('dark_background')

# Paleta Cyberpunk
COLOR_BG = "#0D1117"  # Fondo principal
COLOR_SURFACE = "#161B22"  # Paneles / Sidebar
COLOR_PANEL = "#161B22"
COLOR_BORDER = "#222933"
COLOR_ACCENT = "#00E676"  # Verde neón
COLOR_ACCENT_ALT = "#00b36b"
COLOR_ACCENT_BLUE = "#4facfe"  # Azul acento
COLOR_TEXT = "#FFFFFF"
COLOR_MUTED = "#8B949E"
COLOR_DANGER = "#ff3366"
COLOR_WARNING = "#ffaa00"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

logger = logging.getLogger("VulnSeeker")


class GUILogHandler(logging.Handler):
    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            message = self.format(record)
            log_line = f"[{timestamp}] {message}\n"
            self.log_queue.put(log_line)
        except Exception:
            pass


class VulnSeekerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("VulnSeeker Enterprise")
        self.minsize(1150, 720)
        self.resizable(True, True)
        self.configure(fg_color=COLOR_BG)
        self.after(100, self._maximize_window)

        self.log_queue = queue.Queue()
        self.log_update_interval_ms = 100

        self.current_frame: ctk.CTkFrame | None = None
        self.scan_thread: Optional[threading.Thread] = None
        self.ai_thread: Optional[threading.Thread] = None
        self.log_handler: Optional[GUILogHandler] = None
        self.scan_log_textbox: Optional[ctk.CTkTextbox] = None
        self.url_entry: Optional[ctk.CTkEntry] = None
        self.start_button: Optional[ctk.CTkButton] = None
        self.crawl_checkbox: Optional[ctk.CTkCheckBox] = None
        self.ai_button: Optional[ctk.CTkButton] = None
        self.pdf_button: Optional[ctk.CTkButton] = None
        self.history_pdf_button: Optional[ctk.CTkButton] = None
        self.nav_buttons: dict = {}
        self.current_scan_id: Optional[int] = None
        self.ai_summary_cache: Dict[int, str] = {}
        self.threads_slider: Optional[ctk.CTkSlider] = None
        self.subdomains_switch: Optional[ctk.CTkSwitch] = None
        self.ua_entry: Optional[ctk.CTkEntry] = None
        self.groq_entry: Optional[ctk.CTkEntry] = None

        self.selected_history_scan_id: Optional[int] = None
        self.history_row_cache: Dict[int, Dict[str, Any]] = {}
        self.history_table_container: Optional[ctk.CTkFrame] = None

        self.db_manager = DatabaseManager()
        self.ai_analyst = GroqAIAnalyst()
        self.pdf_generator = PDFReportGenerator()

        Path("ui/assets").mkdir(exist_ok=True)
        self._build_interface()
        self.show_scan()
        self.after(self.log_update_interval_ms, self._process_log_queue)

    def _maximize_window(self) -> None:
        try:
            if os.name == 'nt':
                self.state('zoomed')
            elif sys.platform == 'darwin':
                self.attributes('-zoomed', True)
            else:
                self.geometry("1400x900")
        except Exception:
            self.geometry("1400x900")

    def _process_log_queue(self) -> None:
        try:
            if not self.log_queue.empty() and self.scan_log_textbox:
                self.scan_log_textbox.configure(state="normal")
                while not self.log_queue.empty():
                    msg = self.log_queue.get_nowait()
                    self.scan_log_textbox.insert("end", msg)
                self.scan_log_textbox.see("end")
                self.scan_log_textbox.configure(state="disabled")
        except Exception:
            pass
        finally:
            self.after(self.log_update_interval_ms, self._process_log_queue)

    def _build_interface(self) -> None:
        self.sidebar = self._build_sidebar()
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_BG)
        self.main_container.grid(row=0, column=1, sticky="nswe")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _build_sidebar(self) -> ctk.CTkFrame:
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0,
                                    fg_color=COLOR_SURFACE, border_width=1, border_color=COLOR_BORDER)
        self.sidebar.grid(row=0, column=0, sticky="nswe")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="VULN\n<SEEKER/>",
                                       font=ctk.CTkFont(size=22, weight="bold", family="Consolas"),
                                       text_color=COLOR_TEXT)
        self.logo_label.grid(row=0, column=0, padx=20, pady=(24, 16), sticky="w")

        self.nav_buttons = {
            "scan": self._create_nav_button("🚀 Nuevo Escaneo", 1, self.show_scan),
            "results": self._create_nav_button("📊 Resultados", 2, self.show_results),
            "history": self._create_nav_button("📋 Historial", 3, self.show_history),
            "settings": self._create_nav_button("⚙️ Configuración", 4, self.show_settings)
        }
        self.sidebar.grid_rowconfigure(5, weight=1)
        return self.sidebar

    def _create_nav_button(self, text: str, row: int, command) -> ctk.CTkButton:
        btn = ctk.CTkButton(self.sidebar, text=text, font=ctk.CTkFont(size=14, weight="bold"),
                            height=46, anchor="w", command=command, corner_radius=12,
                            fg_color="transparent", hover_color="#1f252d",
                            border_width=1, border_color=COLOR_BORDER, text_color=COLOR_TEXT)
        btn.grid(row=row, column=0, padx=18, pady=(0, 12), sticky="ew")
        return btn

    def show_frame(self, frame: ctk.CTkFrame) -> None:
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame
        frame.grid(row=0, column=0, sticky="nswe", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

    def _select_nav_button(self, button_key: str) -> None:
        for key, btn in self.nav_buttons.items():
            active = key == button_key
            btn.configure(fg_color=COLOR_ACCENT if active else "transparent",
                          text_color=COLOR_BG if active else COLOR_TEXT,
                          border_color=COLOR_ACCENT if active else COLOR_BORDER)

    def show_results(self) -> None:
        self._select_nav_button("results")
        if not self.current_scan_id:
            self.show_message("ℹ️ Realice un escaneo primero.", "Info")
            self.show_scan()
            return

        target_url = self.db_manager.get_scan_target(self.current_scan_id)
        scan_stats = self.db_manager.get_scan_stats(self.current_scan_id)
        subdomain_count = self.db_manager.get_subdomain_count(self.current_scan_id)
        accent_blue = globals().get("COLOR_ACCENT_BLUE", "#3b82f6")

        # Frame Principal Scrollable
        results_frame = ctk.CTkScrollableFrame(self.main_container, fg_color=COLOR_BG, corner_radius=0)
        results_frame.grid_columnconfigure(0, weight=1)

        # 1. HEADER
        header = ctk.CTkFrame(results_frame, fg_color=COLOR_BG)
        header.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        ctk.CTkLabel(header, text=f"RESULTADOS SCAN #{self.current_scan_id}",
                     font=ctk.CTkFont(size=30, weight="bold", family="Consolas"),
                     text_color=COLOR_TEXT).pack(anchor="w")
        ctk.CTkLabel(header, text=f"🎯 {target_url}",
                     font=ctk.CTkFont(size=14, family="Consolas"),
                     text_color=COLOR_ACCENT).pack(anchor="w", pady=(4, 0))

        # 2. KPIs
        kpi_frame = ctk.CTkFrame(results_frame, fg_color=COLOR_BG)
        kpi_frame.grid(row=1, column=0, padx=20, pady=(5, 15), sticky="ew")
        kpi_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self._create_metric_card(kpi_frame, 0, "🐛", "Vulnerabilidades", scan_stats["total_vulns"], COLOR_ACCENT)
        self._create_metric_card(kpi_frame, 1, "🚨", "Críticas/Alta", scan_stats["critical_high"], COLOR_DANGER)
        self._create_metric_card(kpi_frame, 2, "🌐", "Subdominios", subdomain_count, accent_blue)

        # 3. INFO PANELS (CORREGIDO: pack_propagate)
        info_row = ctk.CTkFrame(results_frame, fg_color=COLOR_BG)
        info_row.grid(row=2, column=0, padx=20, pady=(0, 15), sticky="ew")
        info_row.grid_columnconfigure(0, weight=1)
        info_row.grid_columnconfigure(1, weight=1)

        # -- Panel Tecnologías (Altura Fija: 140px) --
        tech_container = ctk.CTkFrame(info_row, fg_color=COLOR_SURFACE, corner_radius=10,
                                      border_width=1, border_color=COLOR_BORDER, height=140)
        tech_container.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="nsew")

        # ¡AQUÍ ESTABA EL ERROR! Usamos pack() adentro, así que debemos usar pack_propagate(False)
        tech_container.pack_propagate(False)

        ctk.CTkLabel(tech_container, text="🕵️ Tecnologías",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", padx=14,
                                                                                           pady=(10, 5))

        tech_scroll = ctk.CTkScrollableFrame(tech_container, fg_color="transparent", height=80)
        tech_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        tech_info_text = self.db_manager.get_scan_technologies(self.current_scan_id)
        ctk.CTkLabel(tech_scroll, text=tech_info_text, font=ctk.CTkFont(size=13, family="Consolas"),
                     text_color=COLOR_MUTED, wraplength=350, justify="left").pack(anchor="w", padx=5)

        # -- Panel Subdominios (Altura Fija: 140px) --
        sub_container = ctk.CTkFrame(info_row, fg_color=COLOR_SURFACE, corner_radius=10,
                                     border_width=1, border_color=COLOR_BORDER, height=140)
        sub_container.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="nsew")

        # ¡CORRECCIÓN AQUÍ TAMBIÉN!
        sub_container.pack_propagate(False)

        ctk.CTkLabel(sub_container, text=f"🌐 Subdominios ({subdomain_count})",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=accent_blue).pack(anchor="w", padx=14,
                                                                                            pady=(10, 5))

        sub_scroll = ctk.CTkScrollableFrame(sub_container, fg_color="transparent", height=80)
        sub_scroll.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        if subdomain_count > 0:
            for sub in self.db_manager.get_subdomains_by_scan(self.current_scan_id):
                ctk.CTkLabel(sub_scroll, text=f"• {sub}", anchor="w",
                             font=ctk.CTkFont(size=12, family="Consolas"), text_color=COLOR_TEXT).pack(anchor="w",
                                                                                                       padx=5, pady=1)
        else:
            ctk.CTkLabel(sub_scroll, text="Sin subdominios descubiertos",
                         font=ctk.CTkFont(size=12, family="Consolas"),
                         text_color=COLOR_MUTED).pack(padx=5, pady=4, anchor="w")

        # 4. GRÁFICOS
        charts_row = ctk.CTkFrame(results_frame, fg_color=COLOR_BG)
        charts_row.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="ew")
        charts_row.grid_columnconfigure((0, 1), weight=1)

        pie_container = ctk.CTkFrame(charts_row, fg_color=COLOR_SURFACE, corner_radius=10,
                                     border_width=1, border_color=COLOR_BORDER)
        pie_container.grid(row=0, column=0, padx=(0, 8), pady=5, sticky="nsew")
        ctk.CTkLabel(pie_container, text="Distribución por Severidad",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color=COLOR_TEXT).grid(row=0, column=0,
                                                                                           pady=(10, 0))
        self._create_pie_chart(pie_container, self.current_scan_id)

        bar_container = ctk.CTkFrame(charts_row, fg_color=COLOR_SURFACE, corner_radius=10,
                                     border_width=1, border_color=COLOR_BORDER)
        bar_container.grid(row=0, column=1, padx=(8, 0), pady=5, sticky="nsew")
        ctk.CTkLabel(bar_container, text="Top Vulnerabilidades",
                     font=ctk.CTkFont(size=16, weight="bold"), text_color=COLOR_TEXT).grid(row=0, column=0,
                                                                                           pady=(10, 0))
        self._create_bar_chart(bar_container, self.current_scan_id)

        # 5. FOOTER BUTTONS
        buttons_frame = ctk.CTkFrame(results_frame, fg_color=COLOR_BG)
        buttons_frame.grid(row=4, column=0, padx=20, pady=(5, 20), sticky="ew")
        buttons_frame.grid_columnconfigure(0, weight=1)

        btns = ctk.CTkFrame(buttons_frame, fg_color=COLOR_BG)
        btns.pack(anchor="e")

        self.ai_button = ctk.CTkButton(btns, text="🤖 Generar Informe IA (Llama 3)", height=50,
                                       font=ctk.CTkFont(size=15, weight="bold"),
                                       command=lambda: self.generate_ai_report(self.current_scan_id),
                                       corner_radius=8,
                                       fg_color="#9D00FF", hover_color="#7A00C4",
                                       text_color=COLOR_TEXT)
        self.ai_button.pack(side="left", padx=8, pady=4)

        self.pdf_button = ctk.CTkButton(btns, text="📄 Exportar PDF Profesional", height=50,
                                        font=ctk.CTkFont(size=15, weight="bold"),
                                        command=lambda: self.prepare_pdf_generation(self.current_scan_id),
                                        corner_radius=8,
                                        fg_color=COLOR_ACCENT, hover_color="#00e67a",
                                        text_color=COLOR_BG)
        self.pdf_button.pack(side="left", padx=8, pady=4)

        self.show_frame(results_frame)

    def _create_metric_card(self, parent: ctk.CTkFrame, column: int, icon: str, label: str,
                            value: int, border_color: str) -> None:
        card = ctk.CTkFrame(parent, fg_color=COLOR_SURFACE, corner_radius=10,
                            border_width=2, border_color=border_color, height=120)
        card.grid(row=0, column=column, padx=8, pady=5, sticky="nsew")
        card.grid_propagate(False)
        ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=26)).pack(pady=(12, 4))
        ctk.CTkLabel(card, text=str(value), font=ctk.CTkFont(size=30, weight="bold", family="Consolas"),
                     text_color=COLOR_TEXT).pack()
        ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLOR_MUTED).pack(pady=(2, 12))

    def _create_pie_chart(self, parent_frame: ctk.CTkFrame, scan_id: int) -> None:
        severity_data = self.db_manager.get_severity_distribution_by_scan(scan_id)
        if not severity_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos para graficar", font=ctk.CTkFont(size=14),
                         text_color=COLOR_MUTED).grid(row=1, column=0, pady=40)
            return
        labels = [row[0] for row in severity_data]
        sizes = [row[1] for row in severity_data]
        color_map = {'INFO': '#999999', 'LOW': '#ffff99', 'MEDIUM': '#ffcc99', 'HIGH': '#ff6666', 'CRITICAL': '#ff3333'}
        colors = [color_map.get(l, '#cccccc') for l in labels]

        fig = Figure(figsize=(6, 3.2))
        fig.patch.set_facecolor(COLOR_SURFACE)
        fig.subplots_adjust(left=0.02, right=0.7, bottom=0.1, top=0.9)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_SURFACE)

        wedges, texts, autotexts = ax.pie(sizes, labels=None, colors=colors, autopct='%1.1f%%', startangle=90,
                                          pctdistance=0.78)
        for t in texts:
            t.set_color(COLOR_TEXT)
        for autotext in autotexts:
            autotext.set_color(COLOR_BG)
            autotext.set_fontsize(9)

        ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1, 0.5),
                  facecolor=COLOR_SURFACE, labelcolor=COLOR_TEXT, ncol=1)

        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().grid(row=1, column=0, pady=5)

    def _create_bar_chart(self, parent_frame: ctk.CTkFrame, scan_id: int) -> None:
        vuln_data = self.db_manager.get_top_vulns_by_scan(scan_id, 5)
        if not vuln_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos para graficar", font=ctk.CTkFont(size=14),
                         text_color=COLOR_MUTED).grid(row=1, column=0, pady=40)
            return
        names = [row[0][:15] + "..." if len(row[0]) > 15 else row[0] for row in vuln_data]
        counts = [row[1] for row in vuln_data]

        fig = Figure(figsize=(6.6, 3.2))
        fig.patch.set_facecolor(COLOR_SURFACE)
        fig.subplots_adjust(left=0.12, right=0.99, bottom=0.3, top=0.9)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_SURFACE)

        bars = ax.bar(names, counts, color=['#4facfe', '#00f2fe', '#fa709a', '#febefe', '#ffecd2'])
        ax.margins(x=0.08)
        if counts:
            ax.set_ylim(0, max(counts) * 1.25)

        ax.tick_params(axis='x', colors=COLOR_TEXT, rotation=25, labelsize=9)
        ax.tick_params(axis='y', colors=COLOR_TEXT, labelsize=9)
        ax.set_title("Top 5", color=COLOR_TEXT, fontsize=11)

        y_limit = ax.get_ylim()[1]
        offset = y_limit * 0.02
        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width() / 2., count + offset, f'{count}',
                    ha='center', va='bottom', color=COLOR_TEXT, fontsize=9, clip_on=False, zorder=10)

        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_rowconfigure(1, weight=1)
        canvas.get_tk_widget().grid(row=1, column=0, pady=5, sticky="nsew")

    def generate_ai_report(self, scan_id_override: Optional[int] = None, auto_pdf_after: bool = False) -> None:
        scan_id = scan_id_override or self.current_scan_id
        if not scan_id:
            self.show_message("ℹ️ Seleccione un scan primero.", "Info")
            return
        saved_api_key = self.db_manager.get_api_key()
        if saved_api_key:
            logger.info("🔑 Usando API Key persistida")
            self._start_ai_analysis(saved_api_key, scan_id, auto_pdf_after)
            return
        dialog = CTkInputDialog(text="Ingrese su Groq Cloud API Key:", title="🤖 Llama 3.3 70B - Primera vez")
        api_key = dialog.get_input()
        if not api_key or api_key.strip() == "":
            self.show_message("❌ API Key requerida para análisis IA.", "Error")
            return
        try:
            self.db_manager.save_api_key(api_key)
            logger.info("💾 API Key persistida exitosamente")
            self._start_ai_analysis(api_key, scan_id, auto_pdf_after)
        except Exception as e:
            self.show_message(f"❌ Error guardando API Key: {e}", "Error")

    def _start_ai_analysis(self, api_key: str, scan_id: int, auto_pdf_after: bool) -> None:
        if self.ai_button and self.ai_button.winfo_exists():
            self.ai_button.configure(state="disabled", text="⏳ Llama 3.3 Pensando...")
        if hasattr(self, 'history_ai_button') and self.history_ai_button.winfo_exists():
            self.history_ai_button.configure(state="disabled", text="⏳ Llama 3.3 Pensando...")

        self.ai_thread = threading.Thread(target=self._run_ai_analysis, args=(api_key, scan_id, auto_pdf_after),
                                          daemon=True)
        self.ai_thread.start()

    def _run_ai_analysis(self, api_key: str, scan_id: int, auto_pdf_after: bool) -> None:
        try:
            vulns = self.db_manager.get_vulnerabilities_by_scan(scan_id)
            target_url = self.db_manager.get_scan_target(scan_id)
            report = self.ai_analyst.generate_security_report(api_key, vulns, target_url)
            self.ai_summary_cache[scan_id] = report

            if auto_pdf_after:
                self.after(0, self._reset_ai_buttons)
                self.after(100, lambda: self.start_pdf_thread(scan_id))
            else:
                self.after(0, lambda: self.show_ai_report_window(report, scan_id))
                self.after(0, self._reset_ai_buttons)

        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "authentication" in error_msg.lower() or "invalid api key" in error_msg.lower():
                self.after(0, lambda: self.show_message("🔑 API Key inválida/expirada. Se pedirá nuevamente.",
                                                        "Auth Error"))
                try:
                    self.db_manager.save_api_key("")
                except:
                    pass
            else:
                self.after(0, lambda: self.show_message(f"Error IA: {error_msg}", "Error"))
            self.after(0, self._reset_ai_buttons)

    def _reset_ai_buttons(self) -> None:
        if self.ai_button and self.ai_button.winfo_exists():
            self.ai_button.configure(state="normal", text="🤖 Generar Informe IA (Llama 3)")
        if hasattr(self, 'history_ai_button') and self.history_ai_button.winfo_exists():
            if self.selected_history_scan_id:
                self.history_ai_button.configure(state="normal")
            self.history_ai_button.configure(text="🤖 Generar Informe IA")

    def show_ai_report_window(self, report: str, scan_id: int) -> None:
        window = ctk.CTkToplevel(self)
        window.title(f"🤖 Informe IA Ejecutivo - Scan #{scan_id}")
        window.geometry("900x700")
        window.resizable(True, True)
        window.grab_set()
        header_frame = ctk.CTkFrame(window)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header_frame, text="📄 INFORME EJECUTIVO - Llama 3.3 70B",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=15)
        ctk.CTkLabel(header_frame, text="Análisis CISO automatizado para Directiva", font=ctk.CTkFont(size=14)).pack()
        textbox = ctk.CTkTextbox(window, font=ctk.CTkFont(family="Consolas", size=13), height=550)
        textbox.pack(fill="both", expand=True, padx=20, pady=10)
        textbox.insert("0.0", report)
        textbox.configure(state="disabled")
        btn_frame = ctk.CTkFrame(window)
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))

        def copy_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append(report)
            self.update()

        ctk.CTkButton(btn_frame, text="📋 Copiar al Portapapeles", command=copy_to_clipboard, fg_color="green").pack(
            side="left", padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="💾 Guardar como TXT",
                      command=lambda: self.save_report(report, f"informe_ia_scan_{scan_id}.txt"),
                      fg_color="#4facfe").pack(side="right", padx=10, pady=10)

    def save_report(self, report: str, filename: str) -> None:
        filepath = Path("reports") / filename
        filepath.parent.mkdir(exist_ok=True)
        try:
            filepath.write_text(report, encoding="utf-8")
            self.show_message(f"✅ Guardado: {filepath}", "Success")
        except Exception as e:
            self.show_message(f"❌ Error guardando: {e}", "Error")

    def show_message(self, message: str, title: str) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("400x150")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text=message, font=ctk.CTkFont(size=14)).pack(expand=True, padx=40, pady=40)
        ctk.CTkButton(dialog, text="OK", command=dialog.destroy).pack(pady=10)

    def open_reports_folder(self, reports_path: Path) -> None:
        try:
            reports_path.mkdir(exist_ok=True)
            if os.name == 'nt':
                os.startfile(reports_path)
            elif os.name == 'posix':
                os.system(f'open "{reports_path}"' if sys.platform == 'darwin' else f'xdg-open "{reports_path}"')
        except Exception as e:
            print(f"Error abriendo carpeta: {e}")

    def prepare_pdf_generation(self, scan_id: Optional[int] = None) -> None:
        scan_id = scan_id or self.current_scan_id
        if not scan_id:
            self.show_message("ℹ️ Seleccione un scan primero.", "Info")
            return

        if scan_id not in self.ai_summary_cache:
            dialog = ctk.CTkToplevel(self)
            dialog.title("⚠️ Informe IA Faltante")
            dialog.geometry("450x220")
            dialog.transient(self)
            dialog.grab_set()

            ctk.CTkLabel(dialog,
                         text="Este escaneo aún no tiene un análisis de IA.\n\n¿Desea generarlo automáticamente antes de crear el PDF?\n(Recomendado para un reporte completo)",
                         font=ctk.CTkFont(size=14), wraplength=400).pack(pady=20)

            btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            btn_frame.pack(pady=10)

            def on_yes():
                dialog.destroy()
                self.generate_ai_report(scan_id, auto_pdf_after=True)

            def on_no():
                dialog.destroy()
                self.start_pdf_thread(scan_id)

            ctk.CTkButton(btn_frame, text="Sí, Generar IA + PDF", command=on_yes, fg_color=("#10b981", "#047857")).pack(
                side="left", padx=10)
            ctk.CTkButton(btn_frame, text="No, Solo PDF (Incompleto)", command=on_no,
                          fg_color=("gray70", "gray30")).pack(side="right", padx=10)
        else:
            self.start_pdf_thread(scan_id)

    def start_pdf_thread(self, scan_id: int) -> None:
        if self.pdf_button and self.pdf_button.winfo_exists():
            self.pdf_button.configure(state="disabled", text="⏳ Generando PDF...")
        if self.history_pdf_button and self.history_pdf_button.winfo_exists():
            self.history_pdf_button.configure(state="disabled", text="⏳...")

        pdf_thread = threading.Thread(target=self._run_pdf_generation, args=(scan_id,), daemon=True)
        pdf_thread.start()

    def _run_pdf_generation(self, scan_id: int) -> None:
        try:
            ai_summary = self.ai_summary_cache.get(scan_id)
            output_path = self.pdf_generator.generate_pdf(scan_id, ai_summary)
            self.after(0, lambda: self.show_message(f"✅ PDF generado: {Path(output_path).name}", "Éxito"))
            self.after(0, lambda: self.open_reports_folder(Path(output_path).parent))
        except Exception as e:
            err_msg = str(e)
            print(f"ERROR PDF: {err_msg}")
            traceback.print_exc()
            self.after(0, lambda: self.show_message(f"❌ Error PDF: {err_msg}", "Error"))
        finally:
            self.after(0, self._reset_pdf_buttons)

    def _reset_pdf_buttons(self) -> None:
        if self.pdf_button and self.pdf_button.winfo_exists():
            self.pdf_button.configure(state="normal", text="📄 Exportar PDF Profesional")
        if self.history_pdf_button and self.history_pdf_button.winfo_exists():
            self.history_pdf_button.configure(state="normal", text="📄 PDF")

    def show_scan(self) -> None:
        self._select_nav_button("scan")
        scan_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_BG)
        scan_frame.grid_columnconfigure(0, weight=1)
        scan_frame.grid_rowconfigure(2, weight=1)

        # Hero centrado
        hero = ctk.CTkFrame(scan_frame, fg_color=COLOR_BG)
        hero.grid(row=0, column=0, pady=(40, 10), sticky="n")
        title_row = ctk.CTkFrame(hero, fg_color=COLOR_BG)
        title_row.pack()
        ctk.CTkLabel(title_row, text="VULN", font=ctk.CTkFont(size=42, weight="bold", family="Consolas"),
                     text_color=COLOR_TEXT).pack(side="left")
        ctk.CTkLabel(title_row, text=" <SEEKER/>", font=ctk.CTkFont(size=42, weight="bold", family="Consolas"),
                     text_color=COLOR_ACCENT).pack(side="left")
        ctk.CTkLabel(hero, text="Advanced Vulnerability Scanner", text_color=COLOR_MUTED,
                     font=ctk.CTkFont(size=16)).pack(pady=(8, 18))

        # Formulario centrado
        form_frame = ctk.CTkFrame(scan_frame, fg_color=COLOR_SURFACE, corner_radius=16,
                                  border_width=1, border_color=COLOR_BORDER)
        form_frame.grid(row=1, column=0, padx=40, pady=(0, 20), sticky="n")
        form_frame.grid_columnconfigure(0, weight=1)
        self.url_entry = ctk.CTkEntry(form_frame, placeholder_text="https://target.com",
                                      font=ctk.CTkFont(size=16, family="Consolas"),
                                      height=48, width=520,
                                      fg_color=COLOR_BG, border_color=COLOR_BORDER,
                                      text_color=COLOR_TEXT, placeholder_text_color=COLOR_MUTED)
        self.url_entry.grid(row=0, column=0, padx=20, pady=(20, 12), sticky="ew")

        self.crawl_var = ctk.BooleanVar()
        self.crawl_checkbox = ctk.CTkCheckBox(form_frame, text="🕷️ Activar Crawler (Descubrimiento Automático)",
                                              variable=self.crawl_var, font=ctk.CTkFont(size=14),
                                              fg_color=COLOR_ACCENT, hover_color="#00c968",
                                              text_color=COLOR_TEXT, border_color=COLOR_BORDER)
        self.crawl_checkbox.grid(row=1, column=0, padx=20, pady=(0, 16), sticky="w")

        self.start_button = ctk.CTkButton(form_frame, text="INITIALIZE SCAN", height=50,
                                          font=ctk.CTkFont(size=18, weight="bold", family="Consolas"),
                                          command=self.start_scan_thread,
                                          corner_radius=12,
                                          fg_color=COLOR_ACCENT, hover_color="#00c968",
                                          text_color="#0D1117")
        self.start_button.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")

        # Terminal inferior
        console_frame = ctk.CTkFrame(scan_frame, fg_color=COLOR_SURFACE, corner_radius=12,
                                     border_width=1, border_color=COLOR_BORDER)
        console_frame.grid(row=2, column=0, padx=24, pady=(0, 24), sticky="nsew")
        console_frame.grid_columnconfigure(0, weight=1)
        console_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(console_frame, text="> Terminal Output", font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=COLOR_MUTED).grid(row=0, column=0, padx=16, pady=(14, 8), sticky="w")
        self.scan_log_textbox = ctk.CTkTextbox(console_frame, height=320, state="disabled",
                                               font=ctk.CTkFont(family="Consolas", size=12),
                                               fg_color="#0b0f14", text_color=COLOR_TEXT,
                                               border_color=COLOR_BORDER)
        self.scan_log_textbox.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.show_frame(scan_frame)

    def start_scan_thread(self) -> None:
        url = self.url_entry.get().strip()
        if not url:
            if self.scan_log_textbox:
                self.scan_log_textbox.configure(state="normal")
                self.scan_log_textbox.insert("end", "[!] Error: Ingrese una URL válida.\n")
                self.scan_log_textbox.configure(state="disabled")
            return
        self.start_button.configure(state="disabled", text="⏳ EJECUTANDO...")
        self.url_entry.configure(state="disabled")
        self.crawl_checkbox.configure(state="disabled")
        self.log_handler = GUILogHandler(self.log_queue)
        logger = logging.getLogger("VulnSeeker")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.addHandler(self.log_handler)
        self.scan_thread = threading.Thread(target=self.run_engine, args=(url, self.crawl_var.get()), daemon=True)
        self.scan_thread.start()

    def run_engine(self, target_url: str, use_crawler: bool) -> None:
        try:
            logger = logging.getLogger("VulnSeeker")
            logger.info(f"🚀 Iniciando escaneo: {target_url}")
            logger.info(f"🕷️ Crawler: {'SÍ' if use_crawler else 'NO'}")

            threads_cfg = int(self.db_manager.get_setting("threads", "10") or 10)
            enable_subs_cfg = (self.db_manager.get_setting("enable_subdomains", "true") or "true").lower() in (
                "true", "1", "yes", "y")
            ua_cfg = self.db_manager.get_setting("user_agent", GlobalConfig.USER_AGENT) or GlobalConfig.USER_AGENT
            config = {
                "threads": threads_cfg,
                "user_agent": ua_cfg,
                "enable_subdomains": enable_subs_cfg
            }

            engine = VulnSeekerEngine(config=config)
            engine.register_module(SQLInjectionScanner())
            engine.register_module(XSSScanner())
            engine.register_module(HeaderAnalyzer())
            engine.register_module(PortScanner())
            engine.register_module(PathFuzzer())
            engine.register_module(WAFDetector())
            engine.register_module(CMSAuditor())
            logger.info(
                f"⚡ Motor de análisis iniciado (5 módulos, {threads_cfg} hilos, Subdomains: {'ON' if enable_subs_cfg else 'OFF'})...")
            results = engine.scan(target_url, crawl=use_crawler)

            logger.info(f"💾 Guardando resultados...")

            technologies = getattr(engine, 'fingerprint_data', "Unknown")
            subdomains = getattr(engine, 'subdomain_data', [])

            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            logger.info(f"📄 JSON: {json_path}")

            scan_id = self.db_manager.save_scan_results(target_url, results, technologies)

            if subdomains:
                self.db_manager.save_subdomains(scan_id, subdomains)
                logger.info(f"🌍 {len(subdomains)} subdominios asociados al scan #{scan_id}")

            logger.info(f"🗄️ SQLite: Scan ID {scan_id}")
            logger.info("✅ ESCANEO COMPLETADO EXITOSAMENTE")
            self.current_scan_id = scan_id
            self.after(0, self._scan_completed_with_redirect)
        except Exception as e:
            logger.error(f"💥 Error en escaneo: {e}")
            self.after(0, self._scan_completed)

    def _scan_completed_with_redirect(self) -> None:
        self.show_results()
        self._scan_completed()

    def _scan_completed(self) -> None:
        try:
            if self.start_button and self.start_button.winfo_exists():
                self.start_button.configure(state="normal", text="🚀 INICIAR ATAQUE")
            if self.url_entry and self.url_entry.winfo_exists():
                self.url_entry.configure(state="normal")
            if self.crawl_checkbox and self.crawl_checkbox.winfo_exists():
                self.crawl_checkbox.configure(state="normal")
        except Exception:
            pass

    def show_history(self) -> None:
        self._select_nav_button("history")

        # Frame principal que ocupa todo el espacio
        history_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_BG)
        # Configuración de rejilla 3x3 para centrado perfecto
        history_frame.grid_columnconfigure(0, weight=1)  # Margen izquierdo
        history_frame.grid_columnconfigure(1, weight=0)  # Contenido (ancho fijo o adaptable)
        history_frame.grid_columnconfigure(2, weight=1)  # Margen derecho
        history_frame.grid_rowconfigure(0, weight=1)  # Margen superior
        history_frame.grid_rowconfigure(1, weight=0)  # Contenido
        history_frame.grid_rowconfigure(2, weight=1)  # Margen inferior

        # Contenedor del contenido (Centrado)
        content_box = ctk.CTkFrame(history_frame, fg_color=COLOR_BG, width=960, corner_radius=0)
        content_box.grid(row=1, column=1, sticky="nsew")  # En el centro

        # Ojo: No usamos grid_propagate(False) aquí para que crezca según necesite,
        # pero como está en el centro, se verá centrado.
        content_box.grid_columnconfigure(0, weight=1)

        # --- Título ---
        ctk.CTkLabel(content_box, text="📋 Historial de Escaneos",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=COLOR_TEXT).grid(row=0, column=0, padx=20, pady=(0, 20), sticky="w")

        # --- Filtros ---
        filter_frame = ctk.CTkFrame(content_box, fg_color=COLOR_PANEL, corner_radius=10,
                                    border_width=1, border_color=COLOR_BORDER)
        filter_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")

        ctk.CTkLabel(filter_frame, text="🎯 Filtrar por Target:", font=ctk.CTkFont(size=14, weight="bold")).pack(
            side="left", padx=(20, 10), pady=15)

        self.target_filter_var = ctk.StringVar(value="Todos")
        targets = self.db_manager.get_unique_targets()
        targets.insert(0, "Todos")
        self.target_filter_menu = ctk.CTkOptionMenu(filter_frame, values=targets, variable=self.target_filter_var,
                                                    command=self._on_target_filter_change, width=300,
                                                    fg_color=COLOR_ACCENT_BLUE, button_color="#2b75cc")
        self.target_filter_menu.pack(side="left", pady=15)

        # --- Tabla ---
        table_container = ctk.CTkFrame(content_box, fg_color=COLOR_BG)
        table_container.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)
        self.history_table_container = table_container
        self._refresh_history_table(table_container)

        # --- Botones Superiores (Carpeta, PDF, IA) ---
        button_frame = ctk.CTkFrame(content_box, fg_color=COLOR_BG)
        button_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)  # Espaciador

        reports_dir = Path(GlobalConfig.REPORTS_DIR)
        ctk.CTkButton(button_frame, text="📂 Abrir Carpeta", height=45, width=140,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=lambda: self.open_reports_folder(reports_dir),
                      corner_radius=10,
                      fg_color=COLOR_PANEL, hover_color="#2d333b",
                      border_width=1, border_color=COLOR_BORDER, text_color=COLOR_TEXT).pack(side="left", padx=(0, 10))

        # Espaciador invisible para empujar los otros a la derecha
        ctk.CTkLabel(button_frame, text="").pack(side="left", expand=True, fill="x")

        self.history_pdf_button = ctk.CTkButton(button_frame, text="📄 PDF", height=45, width=100,
                                                font=ctk.CTkFont(size=14, weight="bold"),
                                                command=lambda: self.prepare_pdf_generation(
                                                    self.selected_history_scan_id), state="disabled",
                                                corner_radius=10,
                                                fg_color=COLOR_ACCENT, hover_color="#00e67a",
                                                text_color=COLOR_BG)
        self.history_pdf_button.pack(side="right", padx=(10, 0))

        self.history_ai_button = ctk.CTkButton(button_frame, text="🤖 IA", height=45, width=100,
                                               font=ctk.CTkFont(size=14, weight="bold"),
                                               command=lambda: self.generate_ai_report(self.selected_history_scan_id),
                                               state="disabled", corner_radius=10,
                                               fg_color="#9D00FF", hover_color="#7A00C4",
                                               text_color=COLOR_TEXT)
        self.history_ai_button.pack(side="right", padx=(10, 0))

        # --- Botones Inferiores (Danger Zone) ---
        danger_frame = ctk.CTkFrame(content_box, fg_color=COLOR_BG)
        danger_frame.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="ew")

        ctk.CTkButton(danger_frame, text="🗑️ Eliminar Seleccionado", height=42, width=170,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_delete_selected,
                      corner_radius=10,
                      fg_color="#f97316", hover_color="#ea580c",
                      text_color=COLOR_BG).pack(side="left", padx=(0, 10))

        ctk.CTkButton(danger_frame, text="☢️ NUKE DB", height=42, width=140,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_nuke_db,
                      corner_radius=10,
                      fg_color=COLOR_DANGER, hover_color="#dc2626",
                      text_color=COLOR_BG).pack(side="left", padx=10)

        ctk.CTkButton(danger_frame, text="📊 Exportar CSV", height=42, width=150,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_export_csv,
                      corner_radius=10,
                      fg_color=COLOR_ACCENT_BLUE, hover_color="#2b75cc",
                      text_color=COLOR_BG).pack(side="right", padx=0)

        self.show_frame(history_frame)

    def _on_target_filter_change(self, selected_target: str) -> None:
        if self.current_frame:
            for child in self.current_frame.winfo_children():
                if child.grid_info()['row'] == 2:
                    self._refresh_history_table(child, selected_target)
                    break

    def handle_delete_selected(self) -> None:
        if not self.selected_history_scan_id:
            self.show_message("ℹ️ Seleccione un scan primero.", "Info")
            return
        confirm = CTkInputDialog(text="Escriba DELETE para confirmar:", title="Confirmar eliminación").get_input()
        if confirm != "DELETE":
            self.show_message("Operación cancelada.", "Cancelado")
            return
        ok = self.db_manager.delete_scan(self.selected_history_scan_id)
        if ok:
            self.show_message("✅ Scan eliminado.", "Éxito")
            self.selected_history_scan_id = None
            if self.history_table_container:
                self._refresh_history_table(self.history_table_container, self.target_filter_var.get())
        else:
            self.show_message("❌ No se pudo eliminar.", "Error")

    def handle_nuke_db(self) -> None:
        first = CTkInputDialog(text="PELIGRO: escriba NUKE para continuar:", title="☢️ NUKE DB").get_input()
        if first != "NUKE":
            self.show_message("Operación cancelada.", "Cancelado")
            return
        second = CTkInputDialog(text="CONFIRME: escriba CONFIRM:", title="☢️ Confirmación final").get_input()
        if second != "CONFIRM":
            self.show_message("Operación cancelada.", "Cancelado")
            return
        ok = self.db_manager.nuke_database()
        if ok:
            self.show_message("☢️ Base limpiada (historial eliminado).", "Éxito")
            self.selected_history_scan_id = None
            if self.history_table_container:
                self._refresh_history_table(self.history_table_container, "Todos")
        else:
            self.show_message("❌ No se pudo limpiar la base.", "Error")

    def handle_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                                            initialfile="vulnseeker_export.csv")
        if not path:
            return
        ok = self.db_manager.export_to_csv(path)
        if ok:
            self.show_message(f"📊 CSV exportado:\n{path}", "Éxito")
        else:
            self.show_message("❌ Error exportando CSV.", "Error")

    def _refresh_history_table(self, table_container: ctk.CTkFrame, target_filter: str = "Todos") -> None:
        for widget in table_container.winfo_children():
            widget.destroy()
        self.history_row_cache = {}
        scans = self.db_manager.get_all_scans() if target_filter == "Todos" else self.db_manager.get_scans_by_target(
            target_filter)
        if not scans:
            ctk.CTkLabel(table_container, text="📭 No hay escaneos registrados aún.", font=ctk.CTkFont(size=18)).grid(
                row=0, column=0, padx=40, pady=40)
            return

        header_frame = ctk.CTkFrame(table_container, fg_color=COLOR_PANEL,
                                    border_width=1, border_color=COLOR_BORDER, corner_radius=8)
        header_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 5))
        headers = ["🆔 ID", "📅 FECHA", "🎯 OBJETIVO", "🔍 HALLAZGOS"]
        for col, header_text in enumerate(headers):
            ctk.CTkLabel(header_frame, text=header_text, font=ctk.CTkFont(size=14, weight="bold")).grid(row=0,
                                                                                                        column=col,
                                                                                                        padx=12,
                                                                                                        pady=12,
                                                                                                        sticky="w")

        scrollable_frame = ctk.CTkScrollableFrame(table_container, height=350)
        scrollable_frame.grid(row=1, column=0, padx=15, pady=(5, 15), sticky="nsew")

        for idx, (scan_id, scan_date, target_url, vuln_count) in enumerate(scans):
            try:
                readable_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00')).strftime("%d-%m-%Y %H:%M")
            except:
                readable_date = scan_date[:16]
            row_color = (COLOR_PANEL, "#1a1a1a") if idx % 2 == 0 else ("#131313", "#1f1f1f")
            row_frame = ctk.CTkFrame(scrollable_frame, fg_color=row_color, height=35, corner_radius=8,
                                     border_width=1, border_color=COLOR_BORDER)
            row_frame.grid(row=idx, column=0, sticky="ew", padx=5, pady=2)
            row_frame.grid_columnconfigure(2, weight=1)
            self.history_row_cache[scan_id] = {"frame": row_frame, "default_color": row_color}

            for col, text in enumerate(
                    [str(scan_id), readable_date, (target_url[:50] + "...") if len(target_url) > 50 else target_url,
                     str(vuln_count)]):
                lbl = ctk.CTkLabel(row_frame, text=text,
                                   font=ctk.CTkFont(size=13, weight="bold" if col in [0, 3] else "normal"),
                                   text_color=COLOR_TEXT)
                lbl.grid(row=0, column=col, padx=12 if col in [0, 3] else 8, pady=8, sticky="e" if col == 3 else "w")
                lbl.bind("<Button-1>", lambda e, sid=scan_id: self._on_history_row_click(sid))
            row_frame.bind("<Button-1>", lambda e, sid=scan_id: self._on_history_row_click(sid))

    def _on_history_row_click(self, scan_id: int) -> None:
        self.selected_history_scan_id = scan_id
        for sid, data in self.history_row_cache.items():
            try:
                data["frame"].configure(fg_color=data["default_color"])
            except:
                pass
        if scan_id in self.history_row_cache:
            try:
                self.history_row_cache[scan_id]["frame"].configure(fg_color=("#123426", "#0f2f22"),
                                                                   border_color=COLOR_ACCENT)
            except:
                pass
        if hasattr(self, 'history_ai_button') and self.history_ai_button.winfo_exists():
            self.history_ai_button.configure(state="normal", fg_color=("#8b5cf6", "#7c3aed"))
        if hasattr(self, 'history_pdf_button') and self.history_pdf_button.winfo_exists():
            self.history_pdf_button.configure(state="normal", fg_color=("#10b981", "#047857"))

    def show_settings(self) -> None:
        self._select_nav_button("settings")

        # Frame Principal (Centrado 3x3)
        settings_frame = ctk.CTkFrame(self.main_container, fg_color=COLOR_BG)
        settings_frame.grid_columnconfigure(0, weight=1)
        settings_frame.grid_columnconfigure(1, weight=0)  # Contenido
        settings_frame.grid_columnconfigure(2, weight=1)
        settings_frame.grid_rowconfigure(0, weight=1)
        settings_frame.grid_rowconfigure(1, weight=0)  # Contenido
        settings_frame.grid_rowconfigure(2, weight=1)

        # Contenido Centrado
        content_box = ctk.CTkFrame(settings_frame, fg_color=COLOR_BG, width=800, corner_radius=0)
        content_box.grid(row=1, column=1, sticky="nsew")
        content_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(content_box, text="⚙️ Configuración del Sistema",
                     font=ctk.CTkFont(size=32, weight="bold"),  # Título un poco más grande
                     text_color=COLOR_TEXT).grid(row=0, column=0, padx=20, pady=(0, 30), sticky="w")

        # Valores actuales
        threads_val = int(self.db_manager.get_setting("threads", "10") or 10)
        enable_subs_val = (self.db_manager.get_setting("enable_subdomains", "true") or "true").lower() in (
            "true", "1", "yes", "y")
        ua_val = self.db_manager.get_setting("user_agent", GlobalConfig.USER_AGENT) or GlobalConfig.USER_AGENT
        groq_val = self.db_manager.get_setting("groq_api_key", "") or (self.db_manager.get_api_key() or "")

        # Formulario
        form = ctk.CTkFrame(content_box, fg_color=COLOR_SURFACE, corner_radius=12,
                            border_width=1, border_color=COLOR_BORDER)
        form.grid(row=1, column=0, padx=20, pady=0, sticky="ew")
        form.grid_columnconfigure(1, weight=1)  # Input column expande

        # --- HILOS ---
        ctk.CTkLabel(form, text="Hilos (1-50):", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0,
                                                                                                padx=20, pady=20,
                                                                                                sticky="w")
        self.threads_slider = ctk.CTkSlider(form, from_=1, to=50, number_of_steps=49, width=300,
                                            progress_color=COLOR_ACCENT, button_color=COLOR_ACCENT,
                                            button_hover_color=COLOR_ACCENT_ALT)
        self.threads_slider.set(threads_val)
        self.threads_slider.grid(row=0, column=1, padx=20, pady=20, sticky="ew")

        # --- SUBDOMINIOS ---
        ctk.CTkLabel(form, text="Activar Subdomain Scanner:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=1,
                                                                                                             column=0,
                                                                                                             padx=20,
                                                                                                             pady=20,
                                                                                                             sticky="w")
        self.subdomains_switch = ctk.CTkSwitch(form, text="", onvalue=True, offvalue=False,
                                               fg_color="#444", progress_color=COLOR_ACCENT,
                                               button_color="white", button_hover_color="gray")
        self.subdomains_switch.select() if enable_subs_val else self.subdomains_switch.deselect()
        self.subdomains_switch.grid(row=1, column=1, padx=20, pady=20, sticky="w")

        # --- USER AGENT ---
        ctk.CTkLabel(form, text="User-Agent:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=2, column=0,
                                                                                              padx=20, pady=20,
                                                                                              sticky="w")
        self.ua_entry = ctk.CTkEntry(form, placeholder_text=GlobalConfig.USER_AGENT, font=ctk.CTkFont(size=14),
                                     fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT,
                                     height=40)
        self.ua_entry.insert(0, ua_val)
        self.ua_entry.grid(row=2, column=1, padx=20, pady=20, sticky="ew")

        # --- GROQ API KEY ---
        ctk.CTkLabel(form, text="API Key de Groq:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=3, column=0,
                                                                                                   padx=20, pady=20,
                                                                                                   sticky="w")
        self.groq_entry = ctk.CTkEntry(form, placeholder_text="sk-...", show="*", font=ctk.CTkFont(size=14),
                                       fg_color=COLOR_BG, border_color=COLOR_BORDER, text_color=COLOR_TEXT,
                                       height=40)
        if groq_val:
            self.groq_entry.insert(0, groq_val)
        self.groq_entry.grid(row=3, column=1, padx=20, pady=20, sticky="ew")

        # --- BOTÓN GUARDAR ---
        save_btn = ctk.CTkButton(form, text="💾 Guardar Cambios", height=45, font=ctk.CTkFont(size=15, weight="bold"),
                                 command=self.save_settings, corner_radius=10,
                                 fg_color=COLOR_ACCENT, hover_color="#00e67a",
                                 text_color=COLOR_BG)
        save_btn.grid(row=4, column=0, columnspan=2, padx=20, pady=(30, 20), sticky="e")

        self.show_frame(settings_frame)

    def save_settings(self) -> None:
        try:
            threads = int(self.threads_slider.get()) if self.threads_slider else 10
            enable_subs = self.subdomains_switch.get() if self.subdomains_switch else True
            ua = self.ua_entry.get().strip() if self.ua_entry else GlobalConfig.USER_AGENT
            groq = self.groq_entry.get().strip() if self.groq_entry else ""

            self.db_manager.set_setting("threads", str(threads))
            self.db_manager.set_setting("enable_subdomains", "true" if enable_subs else "false")
            self.db_manager.set_setting("user_agent", ua or GlobalConfig.USER_AGENT)
            if groq:
                self.db_manager.set_setting("groq_api_key", groq)
                self.db_manager.save_api_key(groq)

            self.show_message("✅ Configuración guardada.", "Éxito")
        except Exception as e:
            self.show_message(f"❌ Error al guardar: {e}", "Error")


def main() -> None:
    app = VulnSeekerApp()
    app.mainloop()


if __name__ == "__main__":
    main()

