#!/usr/bin/env python3.14
"""
Lanzador oficial de la Interfaz Gráfica (GUI) de VulnSeeker.
Este script asegura que todos los módulos (core, modules, ui) sean visibles.
"""
import sys
import os

# Truco de Senior:
# Añadimos explícitamente el directorio actual al Path de Python
# para evitar el error "ModuleNotFoundError: No module named 'core'"
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Ahora sí podemos importar la ventana de forma segura
from ui.main_window import main

if __name__ == "__main__":
    print(f"[*] Iniciando VulnSeeker GUI desde: {current_dir}")
    main()