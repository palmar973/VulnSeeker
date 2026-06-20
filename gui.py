#!/usr/bin/env python3.14
"""Arranque GUI asegurando core/modules/ui en sys.path."""
import sys
import os

# Añade la raíz al sys.path para evitar ModuleNotFoundError con core
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from ui.main_window import main

if __name__ == "__main__":
    print(f"[*] Iniciando VulnSeeker GUI desde: {current_dir}")
    main()
