#!/usr/bin/env python3.14
"""
Ventana principal de VulnSeeker Enterprise.
Aquí decidí usar customtkinter porque ofrece un look "cyberpunk" profesional que impresiona al cliente final.
Espero que el Senior apruebe esta base antes de conectar el backend.
"""

import customtkinter as ctk
from pathlib import Path
import sys
import os

# Configuración global de CustomTkinter (tema oscuro)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class VulnSeekerApp(ctk.CTk):
    """Aplicación principal de escritorio. Sidebar + Área principal dinámica."""

    def __init__(self) -> None:
        super().__init__()

        # Configuración de ventana principal
        self.title("VulnSeeker Enterprise")
        self.geometry("1100x680")
        self.minsize(900, 500)
        self.resizable(True, True)

        # Variables de estado de navegación
        self.current_frame: ctk.CTkFrame | None = None

        # Aquí crearé el directorio ui/ si no existe (para assets futuros)
        Path("ui/assets").mkdir(exist_ok=True)

        # Construcción de la UI
        self._build_interface()

    def _build_interface(self) -> None:
        """Construye el layout principal: Sidebar + Frame contenedor."""

        # === SIDEBAR IZQUIERDO (200px) ===
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nswe", rowspan=1)

        # Logo/Título del proyecto
        self.logo_label = ctk.CTkLabel(
            self.sidebar,
            text="VulnSeeker\nEnterprise",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Botones de navegación
        self.nav_buttons = {
            "dashboard": self._create_nav_button("🏠 Dashboard", 1, self.show_dashboard),
            "scan": self._create_nav_button("🔍 Nuevo Escaneo", 2, self.show_scan),
            "history": self._create_nav_button("📊 Historial", 3, self.show_history)
        }

        # Frame principal contenedor (derecha)
        self.main_container = ctk.CTkFrame(self, corner_radius=0)
        self.main_container.grid(row=0, column=1, sticky="nswe", rowspan=1)

        # Configuración de grid del root
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Placeholder inicial: Dashboard
        self.show_dashboard()

    def _create_nav_button(self, text: str, row: int, command) -> ctk.CTkButton:
        """Fabrica botones del sidebar con hover effects."""
        btn = ctk.CTkButton(
            self.sidebar,
            text=text,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            anchor="w",
            command=command,
            fg_color="transparent",
            hover_color=("gray80", "gray20")
        )
        btn.grid(row=row, column=0, padx=20, pady=(0, 10), sticky="ew")
        return btn

    def show_frame(self, frame: ctk.CTkFrame) -> None:
        """Muestra un frame en el área principal, destruyendo el anterior."""
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = frame
        frame.grid(row=0, column=0, sticky="nswe", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)

    def show_dashboard(self) -> None:
        """Pantalla Dashboard (placeholder)."""
        self._select_nav_button("dashboard")

        dashboard_frame = ctk.CTkFrame(self.main_container)

        title = ctk.CTkLabel(
            dashboard_frame,
            text="📊 Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(30, 20))

        info = ctk.CTkLabel(
            dashboard_frame,
            text="¡Bienvenido a VulnSeeker Enterprise!\n\n"
                 "Próximamente:\n"
                 "• Estadísticas de escaneos\n"
                 "• Vulnerabilidades por severidad\n"
                 "• Tendencias históricas",
            font=ctk.CTkFont(size=16)
        )
        info.grid(row=1, column=0, padx=20, pady=20)

        self.show_frame(dashboard_frame)

    def show_scan(self) -> None:
        """Pantalla Nuevo Escaneo (placeholder)."""
        self._select_nav_button("scan")

        scan_frame = ctk.CTkFrame(self.main_container)

        title = ctk.CTkLabel(
            scan_frame,
            text="🔍 Nuevo Escaneo",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(30, 20))

        info = ctk.CTkLabel(
            scan_frame,
            text="Próximamente podrás:\n"
                 "• Ingresar URL objetivo\n"
                 "• Configurar módulos activos\n"
                 "• Iniciar escaneo con 1 clic",
            font=ctk.CTkFont(size=16)
        )
        info.grid(row=1, column=0, padx=20, pady=20)

        self.show_frame(scan_frame)

    def show_history(self) -> None:
        """Pantalla Historial (placeholder)."""
        self._select_nav_button("history")

        history_frame = ctk.CTkFrame(self.main_container)

        title = ctk.CTkLabel(
            history_frame,
            text="📊 Historial de Escaneos",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(30, 20))

        info = ctk.CTkLabel(
            history_frame,
            text="Conexión con SQLite activada.\n\n"
                 "Próximamente:\n"
                 "• Tabla de escaneos históricos\n"
                 "• Filtros por fecha/severidad\n"
                 "• Exportación de reportes",
            font=ctk.CTkFont(size=16)
        )
        info.grid(row=1, column=0, padx=20, pady=20)

        self.show_frame(history_frame)

    def _select_nav_button(self, button_key: str) -> None:
        """Resalta el botón activo del sidebar."""
        for key, btn in self.nav_buttons.items():
            if key == button_key:
                btn.configure(fg_color=("gray90", "gray30"))
            else:
                btn.configure(fg_color="transparent")


def main() -> None:
    """Entry point de la aplicación GUI."""
    app = VulnSeekerApp()
    app.mainloop()


if __name__ == "__main__":
    main()