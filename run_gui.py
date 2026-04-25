#!/usr/bin/env python3
"""
GHOSTLINK GUI Launcher — run from GhostLink project root.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from PySide6.QtWidgets import QApplication
from ghostlink.gui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()