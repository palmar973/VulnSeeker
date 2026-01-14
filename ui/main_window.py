#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise - FASE 20: GOLD MASTER UI (FINAL REPAIRED).
- FIX CRÍTICO: Reintegración de métodos PDF faltantes/mal indentados.
- FIX UI: Gráfico de barras ajustado (Copilot) + Layout optimizado.
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

plt.style.use('dark_background')

# Backend imports
from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from modules.header_analyzer import HeaderAnalyzer
from modules.port_scanner import PortScanner
from modules.path_fuzzer import PathFuzzer
from modules.ai_analyst import GroqAIAnalyst
from reports.report_generator import ReportGenerator
from reports.pdf_generator import PDFReportGenerator
from core.config import GlobalConfig
from core.db_manager import DatabaseManager

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
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nswe")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="VulnSeeker\nEnterprise",
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.nav_buttons = {
            "scan": self._create_nav_button("🚀 Nuevo Escaneo", 1, self.show_scan),
            "results": self._create_nav_button("📊 Resultados", 2, self.show_results),
            "history": self._create_nav_button("📋 Historial", 3, self.show_history),
            "settings": self._create_nav_button("⚙️ Configuración", 4, self.show_settings)
        }

        self.main_container = ctk.CTkFrame(self, corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nswe")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    def _create_nav_button(self, text: str, row: int, command) -> ctk.CTkButton:
        btn = ctk.CTkButton(self.sidebar, text=text, font=ctk.CTkFont(size=14, weight="bold"),
                            height=40, anchor="w", command=command,
                            fg_color="transparent", hover_color=("gray80", "gray20"))
        btn.grid(row=row, column=0, padx=20, pady=(0, 10), sticky="ew")
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
            btn.configure(fg_color=("gray90", "gray30") if key == button_key else "transparent")

    def show_results(self) -> None:
        self._select_nav_button("results")
        if not self.current_scan_id:
            self.show_message("ℹ️ Realice un escaneo primero.", "Info")
            self.show_scan()
            return

        results_frame = ctk.CTkFrame(self.main_container)
        ctk.CTkLabel(results_frame, text=f"📊 RESULTADOS SCAN #{self.current_scan_id}",
                     font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, padx=20, pady=(15, 10), sticky="w")

        # 1. KPIs
        kpi_frame = ctk.CTkFrame(results_frame)
        kpi_frame.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")

        scan_stats = self.db_manager.get_scan_stats(self.current_scan_id)
        subdomain_count = self.db_manager.get_subdomain_count(self.current_scan_id)
        target_url = self.db_manager.get_scan_target(self.current_scan_id)

        kpi_configs = [
            ("Vulnerabilidades", scan_stats["total_vulns"], "🐛", "#f0932b"),
            ("Críticas/Alta", scan_stats["critical_high"], "🚨", "#eb4d4b"),
            ("Subdominios", subdomain_count, "🌐", "#4facfe")
        ]

        for idx, (title, value, icon, color) in enumerate(kpi_configs):
            kpi_card = ctk.CTkFrame(kpi_frame, fg_color=color, height=90)
            kpi_card.grid(row=0, column=idx, padx=10, pady=10, sticky="nsew")
            kpi_card.grid_columnconfigure(0, weight=1)
            kpi_card.grid_rowconfigure(1, weight=1)
            ctk.CTkLabel(kpi_card, text=icon, font=ctk.CTkFont(size=30)).grid(row=0, column=0, pady=(10, 5))
            ctk.CTkLabel(kpi_card, text=str(value), font=ctk.CTkFont(size=32, weight="bold")).grid(
                row=1, column=0, pady=(0, 2))
            ctk.CTkLabel(kpi_card, text=title, font=ctk.CTkFont(size=13)).grid(row=2, column=0, pady=(0, 10))

        ctk.CTkLabel(kpi_frame, text=f"🎯 {target_url}", font=ctk.CTkFont(size=14)).grid(
            row=0, column=len(kpi_configs), padx=20, pady=20)

        kpi_frame.grid_columnconfigure((0, 1, 2), weight=1)
        kpi_frame.grid_columnconfigure(3, weight=0)

        # 2. Tech Info & Subdomains Row
        info_row_frame = ctk.CTkFrame(results_frame, fg_color="transparent")
        info_row_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        info_row_frame.grid_columnconfigure(0, weight=1)
        info_row_frame.grid_columnconfigure(1, weight=1)

        # -- Sección Tecnologías --
        tech_info = self.db_manager.get_scan_technologies(self.current_scan_id)
        tech_frame = ctk.CTkFrame(info_row_frame, fg_color=("gray85", "gray17"), height=50)
        tech_frame.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="ew")
        tech_frame.pack_propagate(False)

        ctk.CTkLabel(tech_frame, text="🕵️ Tecnologías:", font=ctk.CTkFont(size=14, weight="bold")
                     ).pack(side="left", padx=(15, 5))
        ctk.CTkLabel(tech_frame, text=tech_info, font=ctk.CTkFont(size=13, family="Consolas"),
                     text_color=("#00ff88")).pack(side="left", padx=5)

        # -- Sección Subdominios --
        if subdomain_count > 0:
            subdomains = self.db_manager.get_subdomains_by_scan(self.current_scan_id)
            sub_scroll = ctk.CTkScrollableFrame(info_row_frame, height=50, fg_color=("gray85", "gray17"),
                                                orientation="vertical")
            sub_scroll.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="ew")

            ctk.CTkLabel(sub_scroll, text=f"🌐 Subdominios ({subdomain_count})",
                         font=ctk.CTkFont(size=12, weight="bold"), text_color="#4facfe").pack(anchor="w")

            for sub in subdomains:
                ctk.CTkLabel(sub_scroll, text=f"• {sub}", font=ctk.CTkFont(size=12, family="Consolas"),
                             anchor="w").pack(anchor="w", padx=10)
        else:
            empty_frame = ctk.CTkFrame(info_row_frame, fg_color=("gray85", "gray17"), height=50)
            empty_frame.grid(row=0, column=1, padx=(10, 0), pady=0, sticky="ew")
            empty_frame.pack_propagate(False)
            ctk.CTkLabel(empty_frame, text="🌐 Sin subdominios", text_color="gray50").pack(expand=True)

        # 3. Gráficos
        charts_frame = ctk.CTkFrame(results_frame)
        charts_frame.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="nsew")
        charts_frame.grid_columnconfigure((0, 1), weight=1)
        results_frame.grid_rowconfigure(3, weight=1)

        # -- Pie Chart --
        pie_frame = ctk.CTkFrame(charts_frame)
        pie_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(pie_frame, text="Distribución por Severidad",
                     font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, pady=(5, 5))
        self._create_pie_chart(pie_frame, self.current_scan_id)

        # -- Bar Chart --
        bar_frame = ctk.CTkFrame(charts_frame)
        bar_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(bar_frame, text="Top Vulnerabilidades", font=ctk.CTkFont(size=16, weight="bold")
                     ).grid(row=0, column=0, pady=(5, 5))
        self._create_bar_chart(bar_frame, self.current_scan_id)

        # 4. Botones
        buttons_frame = ctk.CTkFrame(results_frame)
        buttons_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        buttons_frame.grid_columnconfigure(1, weight=1)

        self.ai_button = ctk.CTkButton(buttons_frame, text="🤖 Generar Informe IA (Llama 3)", height=40,
                                       font=ctk.CTkFont(size=15, weight="bold"),
                                       command=lambda: self.generate_ai_report(self.current_scan_id),
                                       fg_color=("#8b5cf6", "#7c3aed"), hover_color=("#7c3aed", "#6d28d9"))
        self.ai_button.pack(side="left", padx=10, pady=10)

        self.pdf_button = ctk.CTkButton(buttons_frame, text="📄 Exportar PDF Profesional", height=40,
                                        font=ctk.CTkFont(size=15, weight="bold"),
                                        command=lambda: self.prepare_pdf_generation(self.current_scan_id),
                                        fg_color=("#10b981", "#047857"), hover_color=("#059669", "#047857"))
        self.pdf_button.pack(side="right", padx=10, pady=10)

        results_frame.grid_columnconfigure(0, weight=1)
        self.show_frame(results_frame)

    def _create_pie_chart(self, parent_frame: ctk.CTkFrame, scan_id: int) -> None:
        severity_data = self.db_manager.get_severity_distribution_by_scan(scan_id)
        if not severity_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos para graficar", font=ctk.CTkFont(size=14)).grid(row=1,
                                                                                                         column=0,
                                                                                                         pady=40)
            return
        labels = [row[0] for row in severity_data]
        sizes = [row[1] for row in severity_data]
        color_map = {'INFO': '#999999', 'LOW': '#ffff99', 'MEDIUM': '#ffcc99', 'HIGH': '#ff6666', 'CRITICAL': '#ff3333'}
        colors = [color_map.get(l, '#cccccc') for l in labels]

        fig = Figure(figsize=(6, 3.2), facecolor='#2b2b2b')
        fig.subplots_adjust(left=0.0, right=0.7, bottom=0.1, top=0.9)
        ax = fig.add_subplot(111)

        wedges, texts, autotexts = ax.pie(sizes, labels=None, colors=colors, autopct='%1.1f%%', startangle=90,
                                          pctdistance=0.8)

        ax.set_facecolor('#2b2b2b')
        for autotext in autotexts:
            autotext.set_color('black')
            autotext.set_fontsize(9)

        ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1, 0.5), facecolor='#2b2b2b',
                  labelcolor='white', ncol=1)

        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().grid(row=1, column=0, pady=5)

    def _create_bar_chart(self, parent_frame: ctk.CTkFrame, scan_id: int) -> None:
        vuln_data = self.db_manager.get_top_vulns_by_scan(scan_id, 5)
        if not vuln_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos para graficar", font=ctk.CTkFont(size=14)).grid(row=1,
                                                                                                         column=0,
                                                                                                         pady=40)
            return
        names = [row[0][:15] + "..." if len(row[0]) > 15 else row[0] for row in vuln_data]
        counts = [row[1] for row in vuln_data]

        # FIX COPILOT: Ajuste de dimensiones y márgenes
        fig = Figure(figsize=(6.6, 3.2), facecolor='#2b2b2b')
        fig.subplots_adjust(left=0.12, right=0.99, bottom=0.42, top=0.9)
        ax = fig.add_subplot(111)

        bars = ax.bar(names, counts, color=['#4facfe', '#00f2fe', '#fa709a', '#febefe', '#ffecd2'])
        ax.set_facecolor('#2b2b2b')
        ax.margins(x=0.08)

        if counts:
            ax.set_ylim(0, max(counts) * 1.25)

        ax.tick_params(axis='x', colors='white', rotation=25, labelsize=9)
        ax.tick_params(axis='y', colors='white', labelsize=9)
        ax.set_title("Top 5", color='white', fontsize=11)

        y_limit = ax.get_ylim()[1]
        offset = y_limit * 0.02

        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width() / 2., count + offset,
                    f'{count}',
                    ha='center', va='bottom', color='white', fontsize=9,
                    clip_on=False, zorder=10)

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
        scan_frame = ctk.CTkFrame(self.main_container)
        ctk.CTkLabel(scan_frame, text="🚀 NUEVO ESCANEO", font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0,
                                                                                                        padx=20,
                                                                                                        pady=(30, 20))

        form_frame = ctk.CTkFrame(scan_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")
        form_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(form_frame, text="🎯 URL Objetivo:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0,
                                                                                                        padx=(20, 10),
                                                                                                        pady=20,
                                                                                                        sticky="w")
        self.url_entry = ctk.CTkEntry(form_frame, placeholder_text="https://ejemplo.com", font=ctk.CTkFont(size=14),
                                      height=40)
        self.url_entry.grid(row=0, column=1, padx=(0, 20), pady=20, sticky="ew")
        self.crawl_var = ctk.BooleanVar()
        self.crawl_checkbox = ctk.CTkCheckBox(form_frame, text="🕷️ Activar Crawler (Descubrimiento Automático)",
                                              variable=self.crawl_var, font=ctk.CTkFont(size=14))
        self.crawl_checkbox.grid(row=1, column=0, columnspan=2, padx=20, pady=(10, 20), sticky="w")

        self.start_button = ctk.CTkButton(form_frame, text="🚀 INICIAR ATAQUE", height=45,
                                          font=ctk.CTkFont(size=18, weight="bold"), command=self.start_scan_thread,
                                          fg_color=("gray70", "gray30"), hover_color=("red", "darkred"))
        self.start_button.grid(row=2, column=0, columnspan=2, padx=20, pady=20)

        console_frame = ctk.CTkFrame(scan_frame)
        console_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        console_frame.grid_columnconfigure(0, weight=1)
        console_frame.grid_rowconfigure(0, weight=1)
        scan_frame.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(console_frame, text="📋 Consola de Salida:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0,
                                                                                                                column=0,
                                                                                                                padx=20,
                                                                                                                pady=(
                                                                                                                    20,
                                                                                                                    10))
        self.scan_log_textbox = ctk.CTkTextbox(console_frame, height=300, state="disabled",
                                               font=ctk.CTkFont(family="Consolas", size=12))
        self.scan_log_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
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
            logger.info(f"⚡ Motor de análisis iniciado (5 módulos, {threads_cfg} hilos, Subdomains: {'ON' if enable_subs_cfg else 'OFF'})...")
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
        history_frame = ctk.CTkFrame(self.main_container)
        history_frame.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(history_frame, text="📋 Historial de Escaneos", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(30, 20))

        filter_frame = ctk.CTkFrame(history_frame)
        filter_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")
        ctk.CTkLabel(filter_frame, text="🎯 Filtrar por Target:", font=ctk.CTkFont(size=14, weight="bold")).pack(
            side="left", padx=(20, 10), pady=15)
        self.target_filter_var = ctk.StringVar(value="Todos")
        targets = self.db_manager.get_unique_targets()
        targets.insert(0, "Todos")
        self.target_filter_menu = ctk.CTkOptionMenu(filter_frame, values=targets, variable=self.target_filter_var,
                                                    command=self._on_target_filter_change, width=400)
        self.target_filter_menu.pack(side="left", pady=15)

        table_container = ctk.CTkFrame(history_frame)
        table_container.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)
        table_container.grid_rowconfigure(0, weight=1)
        self.history_table_container = table_container
        self._refresh_history_table(table_container)

        button_frame = ctk.CTkFrame(history_frame)
        button_frame.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)

        reports_dir = Path(GlobalConfig.REPORTS_DIR)
        ctk.CTkButton(button_frame, text="📂 Abrir Carpeta", height=45, width=120,
                      font=ctk.CTkFont(size=14, weight="bold"), command=lambda: self.open_reports_folder(reports_dir),
                      fg_color=("gray70", "gray25"), hover_color=("orange", "darkorange")).pack(side="left", padx=10,
                                                                                                pady=10)

        self.history_pdf_button = ctk.CTkButton(button_frame, text="📄 PDF", height=45, width=100,
                                                font=ctk.CTkFont(size=14, weight="bold"),
                                                command=lambda: self.prepare_pdf_generation(
                                                    self.selected_history_scan_id), state="disabled",
                                                fg_color=("#10b981", "#047857"), hover_color=("#059669", "#047857"))
        self.history_pdf_button.pack(side="right", padx=(5, 10), pady=10)

        self.history_ai_button = ctk.CTkButton(button_frame, text="🤖 IA", height=45, width=100,
                                               font=ctk.CTkFont(size=14, weight="bold"),
                                               command=lambda: self.generate_ai_report(self.selected_history_scan_id),
                                               state="disabled", fg_color=("#8b5cf6", "#7c3aed"),
                                               hover_color=("#7c3aed", "#6d28d9"))
        self.history_ai_button.pack(side="right", padx=(10, 5), pady=10)

        danger_frame = ctk.CTkFrame(history_frame, fg_color="transparent")
        danger_frame.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="ew")
        danger_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkButton(danger_frame, text="🗑️ Eliminar Seleccionado", height=42, width=170,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_delete_selected,
                      fg_color=("#f97316", "#c2410c"), hover_color=("#ea580c", "#9a3412")).pack(side="left", padx=10,
                                                                                              pady=8)
        ctk.CTkButton(danger_frame, text="☢️ NUKE DB", height=42, width=140,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_nuke_db,
                      fg_color=("#ef4444", "#b91c1c"), hover_color=("#dc2626", "#991b1b")).pack(side="left", padx=10,
                                                                                              pady=8)
        ctk.CTkButton(danger_frame, text="📊 Exportar CSV", height=42, width=150,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self.handle_export_csv,
                      fg_color=("#3b82f6", "#1d4ed8"), hover_color=("#2563eb", "#1e40af")).pack(side="right",
                                                                                               padx=10, pady=8)

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

        header_frame = ctk.CTkFrame(table_container, fg_color=("gray70", "gray25"))
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
            row_color = ("gray85", "gray20") if idx % 2 == 0 else ("gray95", "gray30")
            row_frame = ctk.CTkFrame(scrollable_frame, fg_color=row_color, height=35)
            row_frame.grid(row=idx, column=0, sticky="ew", padx=5, pady=2)
            row_frame.grid_columnconfigure(2, weight=1)
            self.history_row_cache[scan_id] = {"frame": row_frame, "default_color": row_color}

            for col, text in enumerate(
                    [str(scan_id), readable_date, (target_url[:50] + "...") if len(target_url) > 50 else target_url,
                     str(vuln_count)]):
                lbl = ctk.CTkLabel(row_frame, text=text,
                                   font=ctk.CTkFont(size=13, weight="bold" if col in [0, 3] else "normal"))
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
                self.history_row_cache[scan_id]["frame"].configure(fg_color=("#10b981", "#047857"))
            except:
                pass
        if hasattr(self, 'history_ai_button') and self.history_ai_button.winfo_exists():
            self.history_ai_button.configure(state="normal", fg_color=("#8b5cf6", "#7c3aed"))
        if hasattr(self, 'history_pdf_button') and self.history_pdf_button.winfo_exists():
            self.history_pdf_button.configure(state="normal", fg_color=("#10b981", "#047857"))

    def show_settings(self) -> None:
        self._select_nav_button("settings")
        settings_frame = ctk.CTkFrame(self.main_container)
        settings_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(settings_frame, text="⚙️ Configuración del Sistema",
                     font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0, padx=20, pady=(30, 10),
                                                                    sticky="w")

        # Valores actuales
        threads_val = int(self.db_manager.get_setting("threads", "10") or 10)
        enable_subs_val = (self.db_manager.get_setting("enable_subdomains", "true") or "true").lower() in (
            "true", "1", "yes", "y")
        ua_val = self.db_manager.get_setting("user_agent", GlobalConfig.USER_AGENT) or GlobalConfig.USER_AGENT
        groq_val = self.db_manager.get_setting("groq_api_key", "") or (self.db_manager.get_api_key() or "")

        form = ctk.CTkFrame(settings_frame)
        form.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Hilos (1-50):", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0,
                                                                                                padx=10, pady=15,
                                                                                                sticky="w")
        self.threads_slider = ctk.CTkSlider(form, from_=1, to=50, number_of_steps=49, width=320)
        self.threads_slider.set(threads_val)
        self.threads_slider.grid(row=0, column=1, padx=10, pady=15, sticky="ew")

        ctk.CTkLabel(form, text="Activar Subdomain Scanner:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=1,
                                                                                                            column=0,
                                                                                                            padx=10,
                                                                                                            pady=15,
                                                                                                            sticky="w")
        self.subdomains_switch = ctk.CTkSwitch(form, text="", onvalue=True, offvalue=False)
        self.subdomains_switch.select() if enable_subs_val else self.subdomains_switch.deselect()
        self.subdomains_switch.grid(row=1, column=1, padx=10, pady=15, sticky="w")

        ctk.CTkLabel(form, text="User-Agent:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=2, column=0,
                                                                                               padx=10, pady=15,
                                                                                               sticky="w")
        self.ua_entry = ctk.CTkEntry(form, placeholder_text=GlobalConfig.USER_AGENT, font=ctk.CTkFont(size=14))
        self.ua_entry.insert(0, ua_val)
        self.ua_entry.grid(row=2, column=1, padx=10, pady=15, sticky="ew")

        ctk.CTkLabel(form, text="API Key de Groq:", font=ctk.CTkFont(size=15, weight="bold")).grid(row=3, column=0,
                                                                                                   padx=10, pady=15,
                                                                                                   sticky="w")
        self.groq_entry = ctk.CTkEntry(form, placeholder_text="sk-...", show="*", font=ctk.CTkFont(size=14))
        if groq_val:
            self.groq_entry.insert(0, groq_val)
        self.groq_entry.grid(row=3, column=1, padx=10, pady=15, sticky="ew")

        save_btn = ctk.CTkButton(form, text="💾 Guardar", height=40, font=ctk.CTkFont(size=15, weight="bold"),
                                 command=self.save_settings, fg_color=("#10b981", "#047857"),
                                 hover_color=("#059669", "#047857"))
        save_btn.grid(row=4, column=0, columnspan=2, padx=10, pady=(20, 10), sticky="e")

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

