#!/usr/bin/env python3.14
"""
Ventana principal de VulnSeeker Enterprise - FASE 9: Motor threading + Logs en vivo.
Aquí decidí usar GUILogHandler para capturar logs del engine en tiempo real sin bloquear UI.
El threading está blindado contra race conditions con locks internos.
"""

import customtkinter as ctk
import logging
import threading
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Backend imports
from core.engine import VulnSeekerEngine
from modules.sqli_module import SQLInjectionScanner
from modules.xss_module import XSSScanner
from reports.report_generator import ReportGenerator
from core.config import GlobalConfig
from core.db_manager import DatabaseManager

# Configuración global de CustomTkinter (tema oscuro)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class GUILogHandler(logging.Handler):
    """Handler personalizado que redirige logs a CTkTextbox en hilo seguro."""

    def __init__(self, textbox: ctk.CTkTextbox) -> None:
        super().__init__()
        self.textbox = textbox
        self.lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        """Escribe log en textbox desde cualquier hilo."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = self.format(record)
        log_line = f"[{timestamp}] {message}\n"

        def update_textbox():
            with self.lock:
                self.textbox.configure(state="normal")
                self.textbox.insert("end", log_line)
                self.textbox.see("end")
                self.textbox.configure(state="disabled")

        # Schedule en main thread (Tkinter requirement)
        self.textbox.after(0, update_textbox)


class VulnSeekerApp(ctk.CTk):
    """Aplicación principal con threading para escaneos no-bloqueantes."""

    def __init__(self) -> None:
        super().__init__()
        self.title("VulnSeeker Enterprise")
        self.geometry("1100x680")
        self.minsize(900, 500)
        self.resizable(True, True)

        # Estado de la app
        self.current_frame: ctk.CTkFrame | None = None
        self.scan_thread: Optional[threading.Thread] = None
        self.log_handler: Optional[GUILogHandler] = None
        self.scan_log_textbox: Optional[ctk.CTkTextbox] = None

        Path("ui/assets").mkdir(exist_ok=True)
        self._build_interface()

    def _build_interface(self) -> None:
        """Layout principal: Sidebar + Contenedor."""
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nswe")

        self.logo_label = ctk.CTkLabel(
            self.sidebar, text="VulnSeeker\nEnterprise",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Botones navegación
        self.nav_buttons = {
            "dashboard": self._create_nav_button("🏠 Dashboard", 1, self.show_dashboard),
            "scan": self._create_nav_button("🔍 Nuevo Escaneo", 2, self.show_scan),
            "history": self._create_nav_button("📊 Historial", 3, self.show_history)
        }

        # Main container
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

    def show_dashboard(self) -> None:
        self._select_nav_button("dashboard")
        frame = ctk.CTkFrame(self.main_container)
        ctk.CTkLabel(frame, text="📊 Dashboard", font=ctk.CTkFont(size=28, weight="bold")
                     ).grid(row=0, column=0, padx=20, pady=(30, 20))
        ctk.CTkLabel(frame, text="¡Bienvenido!\nPróximamente: estadísticas históricas.",
                     font=ctk.CTkFont(size=16)).grid(row=1, column=0, padx=20, pady=20)
        self.show_frame(frame)

    def show_scan(self) -> None:
        """Pestaña Nuevo Escaneo - FUNCIONAL con threading."""
        self._select_nav_button("scan")

        # Frame principal
        scan_frame = ctk.CTkFrame(self.main_container)

        # Título
        ctk.CTkLabel(scan_frame, text="🔍 Nuevo Escaneo",
                     font=ctk.CTkFont(size=28, weight="bold")
                     ).grid(row=0, column=0, padx=20, pady=(30, 20))

        # === FORMULARIO DE ENTRADA ===
        form_frame = ctk.CTkFrame(scan_frame)
        form_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="ew")
        form_frame.grid_columnconfigure(1, weight=1)

        # URL Input
        ctk.CTkLabel(form_frame, text="🎯 URL Objetivo:",
                     font=ctk.CTkFont(size=16, weight="bold")
                     ).grid(row=0, column=0, padx=(20, 10), pady=20, sticky="w")

        self.url_entry = ctk.CTkEntry(
            form_frame, placeholder_text="https://ejemplo.com",
            font=ctk.CTkFont(size=14), height=40
        )
        self.url_entry.grid(row=0, column=1, padx=(0, 20), pady=20, sticky="ew")

        # Crawler Checkbox
        self.crawl_var = ctk.BooleanVar()
        self.crawl_checkbox = ctk.CTkCheckBox(
            form_frame, text="🕷️ Activar Crawler (Descubrimiento Automático)",
            variable=self.crawl_var, font=ctk.CTkFont(size=14)
        )
        self.crawl_checkbox.grid(row=1, column=0, columnspan=2, padx=20, pady=(10, 20), sticky="w")

        # Botón Iniciar
        self.start_button = ctk.CTkButton(
            form_frame, text="🚀 INICIAR ATAQUE", height=45,
            font=ctk.CTkFont(size=18, weight="bold"),
            command=self.start_scan_thread,
            fg_color=("gray70", "gray30"), hover_color=("red", "darkred")
        )
        self.start_button.grid(row=2, column=0, columnspan=2, padx=20, pady=20)

        # === CONSOLA DE LOGS ===
        console_frame = ctk.CTkFrame(scan_frame)
        console_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        console_frame.grid_columnconfigure(0, weight=1)
        console_frame.grid_rowconfigure(0, weight=1)
        scan_frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(console_frame, text="📋 Consola de Salida:",
                     font=ctk.CTkFont(size=16, weight="bold")
                     ).grid(row=0, column=0, padx=20, pady=(20, 10))

        self.scan_log_textbox = ctk.CTkTextbox(
            console_frame, height=300, state="disabled",
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.scan_log_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        self.show_frame(scan_frame)

    def show_history(self) -> None:
        self._select_nav_button("history")
        frame = ctk.CTkFrame(self.main_container)
        ctk.CTkLabel(frame, text="📊 Historial", font=ctk.CTkFont(size=28, weight="bold")
                     ).grid(row=0, column=0, padx=20, pady=(30, 20))
        ctk.CTkLabel(frame, text="Próximamente: conexión SQLite con tabla histórica.",
                     font=ctk.CTkFont(size=16)).grid(row=1, column=0, padx=20, pady=20)
        self.show_frame(frame)

    def start_scan_thread(self) -> None:
        """Inicia escaneo en hilo secundario."""
        url = self.url_entry.get().strip()
        if not url:
            self.scan_log_textbox.configure(state="normal")
            self.scan_log_textbox.insert("end", "[!] Error: Ingrese una URL válida.\n")
            self.scan_log_textbox.see("end")
            self.scan_log_textbox.configure(state="disabled")
            return

        # UI Feedback
        self.start_button.configure(state="disabled", text="⏳ EJECUTANDO...")
        self.url_entry.configure(state="disabled")
        self.crawl_checkbox.configure(state="disabled")

        # Configurar logger para GUI
        self.log_handler = GUILogHandler(self.scan_log_textbox)
        logger = logging.getLogger("VulnSeeker")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()  # Limpiar handlers previos
        logger.addHandler(self.log_handler)

        # Iniciar thread
        self.scan_thread = threading.Thread(
            target=self.run_engine, args=(url, self.crawl_var.get()),
            daemon=True
        )
        self.scan_thread.start()

    def run_engine(self, target_url: str, use_crawler: bool) -> None:
        """Ejecuta el motor en background thread."""
        try:
            logger = logging.getLogger("VulnSeeker")
            logger.info(f"🚀 Iniciando escaneo: {target_url}")
            logger.info(f"🕷️ Crawler: {'SÍ' if use_crawler else 'NO'}")

            # Inicializar engine
            engine = VulnSeekerEngine()
            engine.register_module(SQLInjectionScanner())
            engine.register_module(XSSScanner())

            # Ejecutar scan
            logger.info("⚡ Motor de análisis iniciado...")
            results = engine.scan(target_url, crawl=use_crawler)

            # Persistencia dual
            logger.info(f"💾 Guardando {len(results)} resultados...")

            # JSON
            reporter = ReportGenerator(output_dir=GlobalConfig.REPORTS_DIR)
            json_path = reporter.export_json(results, target_url)
            logger.info(f"📄 JSON: {json_path}")

            # SQLite
            db = DatabaseManager()
            scan_id = db.save_scan_results(target_url, results)
            logger.info(f"🗄️  SQLite: Scan ID {scan_id}")

            logger.info("✅ ESCANEO COMPLETADO EXITOSAMENTE")

        except Exception as e:
            logger.error(f"💥 Error en escaneo: {e}")
        finally:
            # Reactivar UI desde main thread
            self.after(0, self._scan_completed)

    def _scan_completed(self) -> None:
        """Callback post-escaneo (UI thread)."""
        self.start_button.configure(state="normal", text="🚀 INICIAR ATAQUE")
        self.url_entry.configure(state="normal")
        self.crawl_checkbox.configure(state="normal")


def main() -> None:
    app = VulnSeekerApp()
    app.mainloop()


if __name__ == "__main__":
    main()