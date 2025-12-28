#!/usr/bin/env python3.14
"""
Ventana principal de VulnSeeker Enterprise - FASE 14: Llama 3.3 70B INTEGRADO.
🤖 IA Ejecutiva + 5 Módulos + Queue Anti-Freeze + Gráficos Rotados.
FIX 1: Eliminado parámetro inválido 'show_seperator' en CTkInputDialog.
FIX 2: Corrección de Scope en manejo de errores de Threading (NameError 'e').
"""

import customtkinter as ctk
from customtkinter import CTkInputDialog  # Para API Key
import logging
import threading
import sys
import os
import queue
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
import matplotlib

matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

plt.style.use('dark_background')

# Backend imports - FASE 14: + AI Analyst
from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from modules.header_analyzer import HeaderAnalyzer
from modules.port_scanner import PortScanner
from modules.path_fuzzer import PathFuzzer
from modules.ai_analyst import GroqAIAnalyst  # ← FASE 14 NUEVO
from reports.report_generator import ReportGenerator
from core.config import GlobalConfig
from core.db_manager import DatabaseManager
from core.models import Vulnerability

# Configuración global de CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class GUILogHandler(logging.Handler):
    """Handler optimizado con Queue (anti-freeze para 10k+ logs)."""

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
    """Aplicación Enterprise con IA Ejecutiva Llama 3.3 70B."""

    def __init__(self) -> None:
        super().__init__()
        self.title("VulnSeeker Enterprise")
        self.geometry("1100x680")
        self.minsize(900, 500)
        self.resizable(True, True)

        # Sistema de logs buffered (anti-freeze)
        self.log_queue = queue.Queue()
        self.log_update_interval_ms = 100

        # Estado de la app
        self.current_frame: ctk.CTkFrame | None = None
        self.scan_thread: Optional[threading.Thread] = None
        self.ai_thread: Optional[threading.Thread] = None
        self.log_handler: Optional[GUILogHandler] = None
        self.scan_log_textbox: Optional[ctk.CTkTextbox] = None
        self.url_entry: Optional[ctk.CTkEntry] = None
        self.start_button: Optional[ctk.CTkButton] = None
        self.crawl_checkbox: Optional[ctk.CTkCheckBox] = None
        self.ai_button: Optional[ctk.CTkButton] = None  # ← FASE 14
        self.nav_buttons: dict = {}

        # Singletons
        self.db_manager = DatabaseManager()
        self.ai_analyst = GroqAIAnalyst()

        Path("ui/assets").mkdir(exist_ok=True)
        self._build_interface()

        # Loop de logs
        self.after(self.log_update_interval_ms, self._process_log_queue)

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

        self.logo_label = ctk.CTkLabel(
            self.sidebar, text="VulnSeeker\nEnterprise",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.nav_buttons = {
            "dashboard": self._create_nav_button("🏠 Dashboard", 1, self.show_dashboard),
            "scan": self._create_nav_button("🔍 Nuevo Escaneo", 2, self.show_scan),
            "history": self._create_nav_button("📊 Historial", 3, self.show_history)
        }

        self.main_container = ctk.CTkFrame(self, corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nswe")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.show_dashboard()

    def _create_nav_button(self, text: str, row: int, command) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self.sidebar, text=text, font=ctk.CTkFont(size=14, weight="bold"),
            height=40, anchor="w", command=command,
            fg_color="transparent", hover_color=("gray80", "gray20")
        )
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

    # Dashboard y gráficos (sin cambios - funcionan perfecto)
    def show_dashboard(self) -> None:
        self._select_nav_button("dashboard")
        dashboard_frame = ctk.CTkFrame(self.main_container)

        title_label = ctk.CTkLabel(
            dashboard_frame, text="🚀 CENTRO DE CONTROL - ANALÍTICA DE SEGURIDAD",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        kpi_frame = ctk.CTkFrame(dashboard_frame)
        kpi_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")

        kpi_data = self.db_manager.get_kpis()
        kpi_configs = [
            ("Total Escaneos", kpi_data["total_scans"], "🧾", "#4facfe"),
            ("Total Vulnerabilidades", kpi_data["total_vulns"], "🐛", "#f0932b"),
            ("Críticas/Alta", kpi_data["critical_high"], "🚨", "#eb4d4b")
        ]

        for idx, (title, value, icon, color) in enumerate(kpi_configs):
            kpi_card = ctk.CTkFrame(kpi_frame, fg_color=color, height=100)
            kpi_card.grid(row=0, column=idx, padx=10, pady=10, sticky="nsew")
            kpi_card.grid_columnconfigure(0, weight=1)
            kpi_card.grid_rowconfigure(1, weight=1)

            ctk.CTkLabel(kpi_card, text=icon, font=ctk.CTkFont(size=30)).grid(row=0, column=0, pady=(15, 5))
            ctk.CTkLabel(kpi_card, text=str(value), font=ctk.CTkFont(size=32, weight="bold")).grid(row=1, column=0,
                                                                                                   pady=(0, 10))
            ctk.CTkLabel(kpi_card, text=title, font=ctk.CTkFont(size=14)).grid(row=2, column=0, pady=(0, 15))

        kpi_frame.grid_columnconfigure((0, 1, 2), weight=1)

        charts_frame = ctk.CTkFrame(dashboard_frame)
        charts_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        charts_frame.grid_columnconfigure(1, weight=1)
        charts_frame.grid_rowconfigure(0, weight=1)
        dashboard_frame.grid_rowconfigure(2, weight=1)

        pie_frame = ctk.CTkFrame(charts_frame)
        pie_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        pie_frame.grid_columnconfigure(0, weight=1)
        pie_frame.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(pie_frame, text="Distribución por Severidad", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0,
                                                                                                                  column=0,
                                                                                                                  pady=(
                                                                                                                      10,
                                                                                                                      5))
        self._create_pie_chart(pie_frame)

        bar_frame = ctk.CTkFrame(charts_frame)
        bar_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        bar_frame.grid_columnconfigure(0, weight=1)
        bar_frame.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(bar_frame, text="Top 5 Vulnerabilidades", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0,
                                                                                                              column=0,
                                                                                                              pady=(10,
                                                                                                                    5))
        self._create_bar_chart(bar_frame)

        self.show_frame(dashboard_frame)

    def _create_pie_chart(self, parent_frame: ctk.CTkFrame) -> None:
        severity_data = self.db_manager.get_severity_distribution()
        if not severity_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos suficientes para graficar", font=ctk.CTkFont(size=14)).grid(
                row=1, column=0, pady=40)
            return

        labels = [row[0] for row in severity_data]
        sizes = [row[1] for row in severity_data]
        colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ffd700']

        fig = Figure(figsize=(5, 4), facecolor='#2b2b2b')
        ax = fig.add_subplot(111)
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax.set_facecolor('#2b2b2b')

        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().grid(row=1, column=0, pady=10)

    def _create_bar_chart(self, parent_frame: ctk.CTkFrame) -> None:
        vuln_data = self.db_manager.get_top_vulnerabilities(5)
        if not vuln_data:
            ctk.CTkLabel(parent_frame, text="📊 Sin datos suficientes para graficar", font=ctk.CTkFont(size=14)).grid(
                row=1, column=0, pady=40)
            return

        names = [row[0][:15] + "..." if len(row[0]) > 15 else row[0] for row in vuln_data]
        counts = [row[1] for row in vuln_data]

        fig = Figure(figsize=(5, 4), facecolor='#2b2b2b')
        fig.subplots_adjust(bottom=0.25)

        ax = fig.add_subplot(111)
        bars = ax.bar(names, counts, color=['#4facfe', '#00f2fe', '#fa709a', '#febefe', '#ffecd2'])
        ax.set_facecolor('#2b2b2b')

        ax.tick_params(axis='x', colors='white', rotation=30, labelsize=9)
        ax.tick_params(axis='y', colors='white')
        ax.set_title("Top 5", color='white', fontsize=12)

        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height + 0.1, f'{count}', ha='center', va='bottom',
                    color='white', fontsize=10)

        canvas = FigureCanvasTkAgg(fig, parent_frame)
        canvas.draw()
        canvas.get_tk_widget().grid(row=1, column=0, pady=10)

    def show_scan(self) -> None:
        self._select_nav_button("scan")
        scan_frame = ctk.CTkFrame(self.main_container)

        ctk.CTkLabel(scan_frame, text="🔍 Nuevo Escaneo", font=ctk.CTkFont(size=28, weight="bold")).grid(row=0, column=0,
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

        self.start_button = ctk.CTkButton(
            form_frame, text="🚀 INICIAR ATAQUE", height=45,
            font=ctk.CTkFont(size=18, weight="bold"),
            command=self.start_scan_thread,
            fg_color=("gray70", "gray30"), hover_color=("red", "darkred")
        )
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

    def show_history(self) -> None:
        """FASE 14: + Botón IA Violeta para Informes Ejecutivos."""
        self._select_nav_button("history")
        history_frame = ctk.CTkFrame(self.main_container)

        title_label = ctk.CTkLabel(history_frame, text="📊 Historial de Escaneos",
                                   font=ctk.CTkFont(size=28, weight="bold"))
        title_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        scans: List[Tuple[int, str, str, int]] = self.db_manager.get_all_scans()

        table_container = ctk.CTkFrame(history_frame)
        table_container.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)
        table_container.grid_rowconfigure(0, weight=1)
        history_frame.grid_rowconfigure(1, weight=1)

        if not scans:
            empty_label = ctk.CTkLabel(table_container, text="📭 No hay escaneos registrados aún.",
                                       font=ctk.CTkFont(size=18))
            empty_label.grid(row=0, column=0, padx=40, pady=40)
        else:
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
                row_frame = ctk.CTkFrame(scrollable_frame, fg_color=row_color)
                row_frame.grid(row=idx, column=0, sticky="ew", padx=5, pady=2)

                ctk.CTkLabel(row_frame, text=str(scan_id), font=ctk.CTkFont(size=13, weight="bold")).grid(row=0,
                                                                                                          column=0,
                                                                                                          padx=12,
                                                                                                          pady=10,
                                                                                                          sticky="w")
                ctk.CTkLabel(row_frame, text=readable_date, font=ctk.CTkFont(size=13)).grid(row=0, column=1, padx=8,
                                                                                            pady=10, sticky="w")
                ctk.CTkLabel(row_frame, text=(target_url[:50] + "...") if len(target_url) > 50 else target_url,
                             font=ctk.CTkFont(size=13)).grid(row=0, column=2, padx=8, pady=10, sticky="w")
                ctk.CTkLabel(row_frame, text=str(vuln_count), font=ctk.CTkFont(size=13, weight="bold")).grid(row=0,
                                                                                                             column=3,
                                                                                                             padx=12,
                                                                                                             pady=10,
                                                                                                             sticky="ew")

        # FASE 14: BOTONES INFERIORES
        button_frame = ctk.CTkFrame(table_container)
        button_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="ew")
        button_frame.grid_columnconfigure((0, 1), weight=1)

        # Botón Reportes (existente)
        reports_dir = Path(GlobalConfig.REPORTS_DIR)
        open_reports_btn = ctk.CTkButton(
            button_frame, text="📂 Abrir Carpeta de Reportes", height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=lambda: self.open_reports_folder(reports_dir),
            fg_color=("gray70", "gray25"), hover_color=("orange", "darkorange")
        )
        open_reports_btn.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # FASE 14: BOTÓN IA VIOLETA ✨
        self.ai_button = ctk.CTkButton(
            button_frame, text="🤖 Generar Informe IA (Llama 3)", height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.generate_ai_report,
            fg_color=("#8b5cf6", "#7c3aed"),  # Violeta Groq
            hover_color=("#7c3aed", "#6d28d9")
        )
        self.ai_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.show_frame(history_frame)

    def generate_ai_report(self) -> None:
        """FASE 14: Llama 3.3 70B - Informe Ejecutivo en Thread."""
        scans = self.db_manager.get_all_scans()
        if not scans:
            self.show_message("ℹ️ No hay escaneos para analizar.", "Info")
            return

        # FIX: CTkInputDialog no tiene 'show_seperator'. Eliminado.
        dialog = CTkInputDialog(text="Ingrese su Groq Cloud API Key:", title="🤖 Llama 3.3 70B")
        api_key = dialog.get_input()

        if not api_key or api_key.strip() == "":
            self.show_message("❌ API Key requerida para análisis IA.", "Error")
            return

        # Thread para no congelar UI
        self.ai_button.configure(state="disabled", text="⏳ Llama 3.3 Pensando...")
        self.ai_thread = threading.Thread(target=self._run_ai_analysis, args=(api_key, scans[0][0]), daemon=True)
        self.ai_thread.start()

    def _run_ai_analysis(self, api_key: str, scan_id: int) -> None:
        """Ejecuta IA en background y abre ventana resultado."""
        try:
            # Obtener vulnerabilidades del scan
            vulns = self.db_manager.get_vulnerabilities_by_scan(scan_id)
            target_url = self.db_manager.get_scan_target(scan_id)

            # Generar informe
            report = self.ai_analyst.generate_security_report(api_key, vulns, target_url)

            # Mostrar en UI principal
            self.after(0, lambda: self.show_ai_report_window(report, scan_id))

        except Exception as e:
            # FIX CRÍTICO: Capturar 'e' en una variable local string antes de pasarlo a la lambda
            # para evitar 'NameError: variable e is not defined' por el cierre del scope.
            error_msg = str(e)
            print(f"[DEBUG UI] Error en hilo IA: {error_msg}")  # Log en consola negra también
            self.after(0, lambda: self.show_message(f"Error IA: {error_msg}", "Error"))
        finally:
            self.after(0, lambda: self.ai_button.configure(state="normal", text="🤖 Generar Informe IA (Llama 3)"))

    def show_ai_report_window(self, report: str, scan_id: int) -> None:
        """Ventana popup 800x600 con informe ejecutivo."""
        window = ctk.CTkToplevel(self)
        window.title(f"🤖 Informe IA Ejecutivo - Scan #{scan_id}")
        window.geometry("900x700")
        window.resizable(True, True)
        window.grab_set()  # Modal

        # Header
        header_frame = ctk.CTkFrame(window)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(header_frame, text="📄 INFORME EJECUTIVO - Llama 3.3 70B",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=15)
        ctk.CTkLabel(header_frame, text="Análisis CISO automatizado para Directiva",
                     font=ctk.CTkFont(size=14)).pack()

        # Textbox scrollable
        textbox = ctk.CTkTextbox(window, font=ctk.CTkFont(family="Consolas", size=13), height=550)
        textbox.pack(fill="both", expand=True, padx=20, pady=10)
        textbox.insert("0.0", report)
        textbox.configure(state="disabled")

        # Copy/Save buttons
        btn_frame = ctk.CTkFrame(window)
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))

        def copy_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append(report)
            self.update()

        ctk.CTkButton(btn_frame, text="📋 Copiar al Portapapeles",
                      command=copy_to_clipboard, fg_color="green").pack(side="left", padx=10, pady=10)

        ctk.CTkButton(btn_frame, text="💾 Guardar como TXT",
                      command=lambda: self.save_report(report, f"informe_ia_scan_{scan_id}.txt"),
                      fg_color="#4facfe").pack(side="right", padx=10, pady=10)

    def save_report(self, report: str, filename: str) -> None:
        """Guarda informe IA como TXT."""
        filepath = Path("reports") / filename
        filepath.parent.mkdir(exist_ok=True)
        try:
            filepath.write_text(report, encoding="utf-8")
            self.show_message(f"✅ Guardado: {filepath}", "Success")
        except Exception as e:
            self.show_message(f"❌ Error guardando: {e}", "Error")

    def show_message(self, message: str, title: str) -> None:
        """Notificación simple."""
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

            engine = VulnSeekerEngine()
            engine.register_module(SQLInjectionScanner())
            engine.register_module(XSSScanner())
            engine.register_module(HeaderAnalyzer())
            engine.register_module(PortScanner())
            engine.register_module(PathFuzzer())

            logger.info("⚡ Motor de análisis iniciado (5 módulos activos)...")
            results = engine.scan(target_url, crawl=use_crawler)

            logger.info(f"💾 Guardando {len(results)} resultados...")

            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            logger.info(f"📄 JSON: {json_path}")

            scan_id = self.db_manager.save_scan_results(target_url, results)
            logger.info(f"🗄️  SQLite: Scan ID {scan_id}")

            logger.info("✅ ESCANEO COMPLETADO EXITOSAMENTE")

        except Exception as e:
            logger.error(f"💥 Error en escaneo: {e}")
        finally:
            self.after(0, self._scan_completed)

    def _scan_completed(self) -> None:
        self.start_button.configure(state="normal", text="🚀 INICIAR ATAQUE")
        self.url_entry.configure(state="normal")
        self.crawl_checkbox.configure(state="normal")


def main() -> None:
    app = VulnSeekerApp()
    app.mainloop()


if __name__ == "__main__":
    main()