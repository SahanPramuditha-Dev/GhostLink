import sys
import os
import ctypes
import io
import re
import html as html_mod
import csv
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from PySide6.QtWidgets import (
    QMainWindow,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QComboBox,
    QSpinBox,
    QLineEdit,
    QCheckBox,
    QTextEdit,
    QProgressBar,
    QGroupBox,
    QFormLayout,
    QMessageBox,
    QFileDialog,
    QGridLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFrame,
    QSplitter,
    QScrollArea,
    QApplication,
    QDialog,
    QMenu,
    QGraphicsOpacityEffect,
)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QTextCursor

from ghostlink.engine.profiles import PROFILES
from ghostlink.core.constants import (
    DEFAULT_MINLEN,
    DEFAULT_MAXLEN,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
)

from .workers import ScanWorker, AttackWorker, ReconWorker
from PySide6.QtGui import QIcon
from ghostlink.network.scanner import WiFiScanner


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GHOSTLINK")
        self.resize(1240, 840)
        self.setMinimumSize(1080, 720)
        self.setFont(QFont("Segoe UI", 10))
        self.setWindowIcon(QIcon("ghostlink.ico"))

        self.scan_results = []
        self.config = {
            "ssid": None,
            "interface": None,
            "charset": "0123456789",
            "minlen": DEFAULT_MINLEN,
            "maxlen": DEFAULT_MAXLEN,
            "threads": DEFAULT_THREADS,
            "timeout": DEFAULT_TIMEOUT,
            "wordlist": None,
            "skip_cached": True,
        }

        self.attack_worker = None
        self.total_combinations = 0
        self._scan_auto_timer = QTimer(self)
        self._scan_auto_timer.timeout.connect(self._on_auto_rescan_tick)
        self._scan_auto_enabled = False
        self._last_selected_bssid = ""
        self._scan_seen_at = {}
        self._scan_new_bssids = set()
        self._scan_cycle = 0
        self._scan_prev_by_bssid = {}
        self._pulse_new_on = False
        self._scan_hint_shown = False
        self._scan_density_mode = "comfortable"
        self._scan_compare_enabled = True
        self._scan_column_visibility = {
            1: True, 4: True, 5: True, 6: True, 7: True, 8: True
        }
        self._scan_pulse_timer = QTimer(self)
        self._scan_pulse_timer.timeout.connect(self._tick_new_pulse)
        self._scan_pulse_timer.start(700)
        self._recon_records: list[dict] = []
        self._recon_filter_mode = "all"
        self._recon_collapse_sections = False

        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self.create_chrome_bar())

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(False)
        self.tabs.setElideMode(Qt.ElideRight)
        shell_layout.addWidget(self.tabs)

        self.setCentralWidget(shell)

        self.create_scan_tab()
        self.create_attack_tab()
        self.create_progress_tab()
        self.create_recon_tab()

        self.apply_theme()
        self.statusBar().showMessage("System ready")

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Chrome bar
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def create_chrome_bar(self) -> QWidget:
        bar = QFrame()
        bar.setProperty("role", "chrome")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(8)

        dot_red    = QLabel("o"); dot_red.setProperty("role", "dot_red")
        dot_yellow = QLabel("o"); dot_yellow.setProperty("role", "dot_yellow")
        dot_green  = QLabel("o"); dot_green.setProperty("role", "dot_green")
        title      = QLabel("G H O S T L I N K"); title.setProperty("role", "chrome_title")
        version    = QLabel("Wi-Fi Security Framework // v2.1.0"); version.setProperty("role", "chrome_meta")

        layout.addWidget(dot_red); layout.addWidget(dot_yellow); layout.addWidget(dot_green)
        layout.addSpacing(10); layout.addWidget(title); layout.addStretch(); layout.addWidget(version)
        return bar

    def make_tab_header(self, title: str, subtitle: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 2); layout.setSpacing(2)
        t = QLabel(title);    t.setProperty("role", "title")
        s = QLabel(subtitle); s.setProperty("role", "subtitle")
        layout.addWidget(t); layout.addWidget(s)
        return container

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Theme
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def apply_theme(self):
        self.setStyleSheet("""
        QWidget {
            color: #d5ecff;
            font-family: 'Segoe UI', 'Trebuchet MS', sans-serif;
            font-size: 10pt;
        }
        QMainWindow { background-color: #030d1b; }
        QFrame[role="chrome"] { background: #020a16; border-bottom: 1px solid #12375f; }
        QLabel[role="dot_red"]    { color: #ff4b4b; font-size: 12pt; }
        QLabel[role="dot_yellow"] { color: #ffc531; font-size: 12pt; }
        QLabel[role="dot_green"]  { color: #2fe67a; font-size: 12pt; }
        QLabel[role="chrome_title"] { color: #00b8ff; font-weight: 700; letter-spacing: 3px; }
        QLabel[role="chrome_meta"]  { color: #2f79b4; font-size: 9pt; }
        QStatusBar { background: #020a16; border-top: 1px solid #12375f; color: #2f79b4; }
        QTabWidget::pane {
            background: #010b18; border: 1px solid #12375f; border-top: none;
            border-bottom-left-radius: 10px; border-bottom-right-radius: 10px; padding: 12px;
        }
        QTabBar::tab {
            background: #061426; color: #f5fbff; border: 1px solid #36506e;
            border-top-left-radius: 10px; border-top-right-radius: 10px;
            padding: 10px 18px; margin-right: 4px; font-weight: 800; letter-spacing: 1px;
        }
        QTabBar::tab:selected { background: #091b33; border-color: #5e7ea2; }
        QTabBar::tab:hover    { background: #0b213f; }
        QLabel[role="title"]    { font-size: 21px; font-weight: 800; color: #f6fcff; }
        QLabel[role="subtitle"] { color: #3c8ad0; font-size: 10pt; }
        QLabel[role="meta"]     { color: #5e89b3; font-size: 9pt; }
        QLabel[role="pill"] {
            background: #061a30; border: 1px solid #0078bf; border-radius: 9px;
            color: #dff2ff; font-weight: 700; padding: 9px 12px;
        }
        QLabel[role="target_left"]  { color: #00c5ff; font-size: 10pt; font-weight: 700; }
        QLabel[role="target_right"] { color: #f6fcff;  font-size: 10pt; font-weight: 600; }
        QFrame[role="target_strip"] { background: #061a30; border: 1px solid #00a9ee; border-radius: 9px; }
        QLabel[role="metric"] {
            background: #081a2f; border: 1px solid #1e4f7f; border-radius: 9px;
            color: #e8f6ff; font-weight: 700; padding: 10px 12px;
        }
        QGroupBox {
            color: #f4fbff; background: #031224; border: 1px solid #1b456f;
            border-radius: 9px; margin-top: 12px; padding-top: 12px; font-weight: 700;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
        QTableWidget, QTextEdit {
            background: #071930; border: 1px solid #1f4d79; border-radius: 8px;
            color: #ebf8ff; gridline-color: #10365a;
            selection-background-color: #0e3358; selection-color: #ffffff;
        }
        QHeaderView::section {
            background: #0c2542; color: #4b95d5; border: none;
            border-bottom: 1px solid #1a4671; padding: 8px; font-weight: 700; letter-spacing: 1px;
        }
        QTableWidget[role="scan_table"] {
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #071b33, stop:1 #041428);
            border: 1px solid #1f5887;
            border-radius: 10px;
            gridline-color: #113b61;
            alternate-background-color: #081d36;
            selection-background-color: #123e68;
            selection-color: #f6fcff;
            padding: 2px;
        }
        QTableWidget[role="scan_table"]::item {
            border-bottom: 1px solid #0f3759;
            padding: 8px 8px;
        }
        QTableWidget[role="scan_table"]::item:selected {
            border-left: 3px solid #39b4ff;
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #123e68, stop:1 #1f5f95);
        }
        QTableWidget[role="scan_table"] QHeaderView::section {
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0d2f55, stop:1 #0a2340);
            color: #72bbff;
            border: none;
            border-bottom: 1px solid #2b6a9c;
            padding: 12px 10px;
            font-weight: 800;
            letter-spacing: 2px;
        }
        QLineEdit, QSpinBox, QComboBox {
            background: #081a30; border: 1px solid #255785; border-radius: 8px;
            color: #eff8ff; padding: 6px 36px 6px 10px; min-height: 20px;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus,
        QTextEdit:focus, QTableWidget:focus { border: 1px solid #00b8ff; }
        QComboBox {
            selection-background-color: #11406a;
            selection-color: #f8fdff;
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 30px;
            border-left: 1px solid #1b4f7b;
            background: #0b223c;
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
        }
        QComboBox::down-arrow {
            width: 0px;
            height: 0px;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 7px solid #8fd2ff;
            margin-top: 2px;
        }
        QComboBox::down-arrow:on { margin-top: 4px; }
        QComboBox QAbstractItemView {
            background: #07182c;
            border: 1px solid #2a6da1;
            border-radius: 10px;
            outline: 0;
            padding: 6px;
            color: #e7f4ff;
            selection-background-color: #0f3a64;
            selection-color: #ffffff;
        }
        QComboBox QAbstractItemView::item {
            min-height: 32px;
            padding: 7px 10px;
            border-radius: 7px;
            margin: 1px 0;
        }
        QComboBox QAbstractItemView::item:hover {
            background: #0d3154;
            color: #f6fcff;
        }
        QComboBox QAbstractItemView::item:selected {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0f3d68, stop:1 #13507f);
            border: 1px solid #3b93d2;
        }
        QCheckBox { spacing: 8px; color: #d7ebff; }
        QCheckBox::indicator {
            width: 16px; height: 16px; border-radius: 4px;
            border: 1px solid #2b6297; background: #07192f;
        }
        QCheckBox::indicator:checked { background: #0094de; border: 1px solid #56c7ff; }
        QPushButton {
            background: #061326; border: 1px solid #4a5f79; color: #f7fcff;
            border-radius: 9px; padding: 10px 16px; font-weight: 800;
            letter-spacing: 1px; min-height: 22px;
        }
        QPushButton:hover   { background: #0b2341; border: 1px solid #6587ad; }
        QPushButton:pressed { padding-top: 11px; }
        QPushButton[variant="secondary"] { background: #061326; border: 1px solid #4a5f79; }
        QPushButton[variant="danger"]    { background: #3d1119; border: 1px solid #8b3a4c; }
        QPushButton[variant="danger"]:hover { background: #5a1825; }
        QPushButton[variant="success"]   { background: #08331f; border: 1px solid #1f9b68; }
        QPushButton[variant="critical"]  { background: #3d2312; border: 1px solid #a3663e; }
        QPushButton:disabled { background: #1c2a3b; border: 1px solid #354a62; color: #6f8ca9; }
        QProgressBar {
            background: #09182c; border: 1px solid #245987; border-radius: 8px;
            text-align: center; color: #f5fbff; min-height: 22px; font-weight: 700;
        }
        QProgressBar::chunk {
            border-radius: 7px;
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00b8ff, stop:1 #09de9a);
        }
        QSplitter::handle {
            background: #0f2d4a;
        }
        QSplitter::handle:horizontal {
            width: 6px;
            background: #0f2d4a;
            border-left: 1px solid #1a4671;
            border-right: 1px solid #1a4671;
        }
        QSplitter::handle:vertical {
            height: 6px;
            background: #0f2d4a;
            border-top: 1px solid #1a4671;
            border-bottom: 1px solid #1a4671;
        }
        QSplitter::handle:hover {
            background: #1a4671;
        }
        QScrollArea { border: none; background: transparent; }
        QScrollBar:vertical {
            background: #061426; width: 8px; border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #1e4d79; border-radius: 4px; min-height: 24px;
        }
        QScrollBar::handle:vertical:hover { background: #2a6aaa; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QFrame[role="recon_running"] {
            background: #030f1f;
            border: 1px solid rgba(0, 184, 255, 0.25);
            border-left: 3px solid #00b8ff;
            border-radius: 8px;
        }
        QFrame[role="recon_sidebar"] {
            background: #031224;
            border: 1px solid #1b456f;
            border-radius: 9px;
        }
        QFrame[role="recon_output_frame"] {
            background: #071930;
            border: 1px solid #1f4d79;
            border-radius: 8px;
        }
        QFrame[role="recon_summary"] {
            background: #04111f;
            border: 1px solid #0f2d47;
            border-radius: 7px;
        }
        QLabel[role="summary_card"] {
            background: #061b30;
            border: 1px solid #1e4d79;
            border-radius: 6px;
            color: #d9eeff;
            font-family: 'Consolas', monospace;
            font-size: 8.5pt;
            font-weight: 700;
            padding: 7px 10px;
        }
        QPushButton[role="mod_btn"] {
            background: #061826;
            border: 1px solid #1e4260;
            border-radius: 7px;
            color: #a8ccea;
            font-size: 9pt;
            font-weight: 700;
            letter-spacing: 0.5px;
            padding: 7px 10px;
            text-align: left;
        }
        QPushButton[role="mod_btn"]:hover {
            background: #0b2748;
            border-color: #3a7ab8;
            color: #d5ecff;
        }
        QPushButton[role="mod_btn"]:pressed {
            background: #0d2f56;
        }
        QPushButton[role="run_all_btn"] {
            background: #2a1608;
            border: 1px solid #7a4020;
            border-radius: 7px;
            color: #f0a060;
            font-size: 9pt;
            font-weight: 800;
            letter-spacing: 1px;
            padding: 9px 10px;
        }
        QPushButton[role="run_all_btn"]:hover {
            background: #3d2010;
            border-color: #c06030;
            color: #ffc080;
        }
        QPushButton[role="toolbar_btn"] {
            background: #061222;
            border: 1px solid #1e3d5e;
            border-radius: 6px;
            color: #8ab8d8;
            font-size: 8pt;
            font-weight: 800;
            letter-spacing: 0.5px;
            padding: 4px 10px;
            min-height: 0;
        }
        QPushButton[role="toolbar_btn"]:hover {
            background: #0b2040;
            border-color: #3a6a9a;
            color: #c0ddf0;
        }
        QPushButton[role="scan_filter"] {
            background: #061326;
            border: 1px solid #3a5572;
            border-radius: 10px;
            color: #e6f4ff;
            font-size: 9pt;
            font-weight: 800;
            letter-spacing: 1px;
            padding: 8px 16px;
            min-height: 22px;
        }
        QPushButton[role="scan_filter"]:hover {
            background: #0b2341;
            border-color: #5f86ad;
        }
        QPushButton[role="scan_filter"]:checked {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0c3c65, stop:1 #11619a);
            border: 1px solid #5ec0ff;
            color: #ffffff;
        }
        QPushButton[role="scan_filter"]:checked:hover {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0e4a79, stop:1 #1678be);
            border: 1px solid #7cd0ff;
        }
        QPushButton[role="clear_btn"] {
            background: #1e0a0a;
            border: 1px solid #5a2020;
            border-radius: 6px;
            color: #c06060;
            font-size: 8pt;
            font-weight: 800;
            letter-spacing: 0.5px;
            padding: 4px 10px;
            min-height: 0;
        }
        QPushButton[role="clear_btn"]:hover {
            background: #2e1010;
            border-color: #8a3030;
            color: #e08080;
        }
        """)

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Tab 1 Ã¢â‚¬â€ Scan
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def create_scan_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, "SCAN & SELECT")
        layout = QVBoxLayout(tab); layout.setContentsMargins(14, 14, 14, 14); layout.setSpacing(12)
        layout.addWidget(self.make_tab_header("Target Discovery", "Scan nearby Wi-Fi networks and select a target to attack."))

        summary = QHBoxLayout(); summary.setSpacing(10)
        self.scan_total_label = QLabel("Total: 0"); self.scan_total_label.setProperty("role", "metric"); summary.addWidget(self.scan_total_label)
        self.scan_open_label = QLabel("Open: 0"); self.scan_open_label.setProperty("role", "metric"); summary.addWidget(self.scan_open_label)
        self.scan_secure_label = QLabel("WPA2/WPA3: 0"); self.scan_secure_label.setProperty("role", "metric"); summary.addWidget(self.scan_secure_label)
        self.scan_strong_label = QLabel("Strong (>70%): 0"); self.scan_strong_label.setProperty("role", "metric"); summary.addWidget(self.scan_strong_label)
        summary.addStretch()
        layout.addLayout(summary)

        row = QHBoxLayout(); row.setSpacing(10)
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(190)
        row.addWidget(self.interface_combo)
        self.refresh_iface_btn = QPushButton("REFRESH IFACES")
        self.refresh_iface_btn.setProperty("variant", "secondary")
        self.refresh_iface_btn.clicked.connect(self.refresh_interfaces)
        row.addWidget(self.refresh_iface_btn)
        self.iface_health_label = QLabel("Interface: unknown")
        self.iface_health_label.setProperty("role", "meta")
        row.addWidget(self.iface_health_label)
        self.scan_btn = QPushButton("SCAN NETWORKS"); self.scan_btn.clicked.connect(self.start_scan); row.addWidget(self.scan_btn)
        self.scan_btn.setProperty("variant", "success")
        self.debug_btn = QPushButton("DEBUG SCANNER"); self.debug_btn.setProperty("variant", "secondary"); self.debug_btn.clicked.connect(self.debug_scanner); row.addWidget(self.debug_btn)
        self.auto_rescan_check = QCheckBox("Auto-rescan")
        self.auto_rescan_check.toggled.connect(self.toggle_auto_rescan)
        row.addWidget(self.auto_rescan_check)
        self.auto_rescan_interval = QSpinBox()
        self.auto_rescan_interval.setRange(5, 300)
        self.auto_rescan_interval.setValue(20)
        self.auto_rescan_interval.setSuffix(" s")
        self.auto_rescan_interval.valueChanged.connect(self.update_auto_rescan_interval)
        row.addWidget(self.auto_rescan_interval)
        self.density_combo = QComboBox()
        self.density_combo.addItem("Comfortable", "comfortable")
        self.density_combo.addItem("Compact", "compact")
        self.density_combo.currentIndexChanged.connect(self.update_scan_density)
        row.addWidget(self.density_combo)
        self.compare_check = QCheckBox("Compare scans")
        self.compare_check.setChecked(True)
        self.compare_check.toggled.connect(self.toggle_compare_scans)
        row.addWidget(self.compare_check)
        self.last_scan_label = QLabel("Last scan: never"); self.last_scan_label.setProperty("role", "meta"); row.addWidget(self.last_scan_label)
        row.addStretch(); layout.addLayout(row)

        filter_row = QHBoxLayout(); filter_row.setSpacing(8)
        self.scan_search_edit = QLineEdit()
        self.scan_search_edit.setPlaceholderText("Search SSID / BSSID...")
        self.scan_search_edit.textChanged.connect(self.apply_scan_filters)
        filter_row.addWidget(self.scan_search_edit, 1)
        self.scan_filter_buttons = {}
        for key, label in [
            ("all", "ALL"),
            ("strong", "STRONG"),
            ("open", "OPEN"),
            ("secure", "WPA2/WPA3"),
            ("band5", "5 GHZ"),
        ]:
            btn = QPushButton(label)
            btn.setProperty("role", "scan_filter")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, k=key: self.set_scan_filter(k))
            self.scan_filter_buttons[key] = btn
            filter_row.addWidget(btn)
        self.scan_filter_buttons["all"].setChecked(True)
        self.filter_preset_combo = QComboBox()
        self.filter_preset_combo.addItem("Preset: Custom", "custom")
        self.filter_preset_combo.addItem("Preset: Audit mode", "audit")
        self.filter_preset_combo.addItem("Preset: Open only", "open_only")
        self.filter_preset_combo.addItem("Preset: 5GHz strong", "5g_strong")
        self.filter_preset_combo.currentIndexChanged.connect(self.apply_filter_preset)
        filter_row.addWidget(self.filter_preset_combo)
        self.columns_btn = QPushButton("COLUMNS")
        self.columns_btn.setProperty("variant", "secondary")
        self.columns_btn.clicked.connect(self.open_column_menu)
        filter_row.addWidget(self.columns_btn)
        self.show_hidden_check = QCheckBox("Show hidden")
        self.show_hidden_check.toggled.connect(self.apply_scan_filters)
        filter_row.addWidget(self.show_hidden_check)
        layout.addLayout(filter_row)

        table_shell = QHBoxLayout()
        table_shell.setSpacing(10)
        self.scan_table = QTableWidget(0, 9)
        self.scan_table.setProperty("role", "scan_table")
        self.scan_table.setHorizontalHeaderLabels(["SSID", "STATUS", "SIGNAL", "SECURITY", "RISK", "BAND", "CHANNEL", "CONGESTION", "BSSID / VENDOR"])
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setShowGrid(True); self.scan_table.setAlternatingRowColors(True)
        self.scan_table.setWordWrap(False)
        self.scan_table.verticalHeader().setDefaultSectionSize(52)
        self.scan_table.setSortingEnabled(True)
        self.scan_table.horizontalHeader().setStretchLastSection(False)
        self.scan_table.horizontalHeader().setMinimumSectionSize(70)
        self.scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)
        self.scan_table.setColumnWidth(1, 165)
        self.scan_table.setColumnWidth(2, 155)
        self.scan_table.setColumnWidth(3, 175)
        self.scan_table.setColumnWidth(4, 110)
        self.scan_table.setColumnWidth(5, 95)
        self.scan_table.setColumnWidth(6, 80)
        self.scan_table.setColumnWidth(7, 130)
        self.scan_table.itemSelectionChanged.connect(self._sync_scan_selection_state)
        self.scan_table.itemDoubleClicked.connect(self.on_scan_row_double_clicked)
        self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self.open_scan_context_menu)
        self.scan_table.setMinimumHeight(260)
        table_shell.addWidget(self.scan_table, 4)

        self.scan_side_panel = QFrame()
        self.scan_side_panel.setProperty("role", "recon_summary")
        self.scan_side_panel.setMinimumWidth(250)
        side_l = QVBoxLayout(self.scan_side_panel)
        side_l.setContentsMargins(10, 10, 10, 10)
        side_l.setSpacing(8)
        t = QLabel("Selected Network")
        t.setProperty("role", "meta")
        side_l.addWidget(t)
        self.sel_ssid = QLabel("SSID: -"); self.sel_ssid.setProperty("role", "summary_card"); side_l.addWidget(self.sel_ssid)
        self.sel_bssid = QLabel("BSSID: -"); self.sel_bssid.setProperty("role", "summary_card"); side_l.addWidget(self.sel_bssid)
        self.sel_vendor = QLabel("Vendor: -"); self.sel_vendor.setProperty("role", "summary_card"); side_l.addWidget(self.sel_vendor)
        self.sel_risk = QLabel("Risk: -"); self.sel_risk.setProperty("role", "summary_card"); side_l.addWidget(self.sel_risk)
        self.sel_channel = QLabel("Channel: -"); self.sel_channel.setProperty("role", "summary_card"); side_l.addWidget(self.sel_channel)
        self.sel_seen = QLabel("Last seen: -"); self.sel_seen.setProperty("role", "summary_card"); side_l.addWidget(self.sel_seen)
        side_actions = QHBoxLayout()
        self.side_set_target_btn = QPushButton("SET TARGET")
        self.side_set_target_btn.setProperty("variant", "success")
        self.side_set_target_btn.clicked.connect(self.select_target)
        self.side_copy_bssid_btn = QPushButton("COPY BSSID")
        self.side_copy_bssid_btn.setProperty("variant", "secondary")
        self.side_copy_bssid_btn.clicked.connect(self.copy_selected_bssid)
        side_actions.addWidget(self.side_set_target_btn)
        side_actions.addWidget(self.side_copy_bssid_btn)
        side_l.addLayout(side_actions)
        side_l.addStretch()
        table_shell.addWidget(self.scan_side_panel, 1)
        layout.addLayout(table_shell)

        self.scan_footer_stats = QLabel("Delta: +0 / -0 / ~0")
        self.scan_footer_stats.setProperty("role", "meta")
        layout.addWidget(self.scan_footer_stats)

        self.empty_state_frame = QFrame()
        self.empty_state_frame.setProperty("role", "recon_summary")
        ef = QVBoxLayout(self.empty_state_frame)
        ef.setContentsMargins(18, 14, 18, 14)
        ef.setSpacing(8)
        empty_title = QLabel("No Networks Visible")
        empty_title.setStyleSheet("font-size:14px; font-weight:800; color:#e8f6ff;")
        empty_text = QLabel("1) Run as Administrator\n2) Ensure Wi-Fi adapter is enabled\n3) Choose correct interface")
        empty_text.setProperty("role", "meta")
        self.empty_retry_btn = QPushButton("RETRY SCAN")
        self.empty_retry_btn.setProperty("variant", "success")
        self.empty_retry_btn.clicked.connect(self.start_scan)
        ef.addWidget(empty_title)
        ef.addWidget(empty_text)
        ef.addWidget(self.empty_retry_btn, 0, Qt.AlignLeft)
        self.empty_state_frame.hide()
        layout.addWidget(self.empty_state_frame)

        ar = QHBoxLayout(); ar.setSpacing(10)
        self.select_btn = QPushButton("SET AS TARGET"); self.select_btn.setProperty("variant", "success")
        self.select_btn.clicked.connect(self.select_target); self.select_btn.setEnabled(False)
        self.rescan_btn = QPushButton("RESCAN"); self.rescan_btn.setProperty("variant", "secondary"); self.rescan_btn.clicked.connect(self.start_scan)
        self.export_scan_btn = QPushButton("EXPORT CSV"); self.export_scan_btn.setProperty("variant", "secondary"); self.export_scan_btn.clicked.connect(self.export_scan_csv)
        self.export_scan_json_btn = QPushButton("EXPORT JSON"); self.export_scan_json_btn.setProperty("variant", "secondary"); self.export_scan_json_btn.clicked.connect(self.export_scan_json)
        self.copy_scan_btn = QPushButton("COPY TABLE"); self.copy_scan_btn.setProperty("variant", "secondary"); self.copy_scan_btn.clicked.connect(self.copy_scan_results)
        ar.addWidget(self.select_btn)
        ar.addWidget(self.rescan_btn)
        ar.addWidget(self.export_scan_btn)
        ar.addWidget(self.export_scan_json_btn)
        ar.addWidget(self.copy_scan_btn)
        ar.addStretch()
        self.scan_selection_label = QLabel("Selected: none"); self.scan_selection_label.setProperty("role", "meta")
        ar.addWidget(self.scan_selection_label)
        layout.addLayout(ar)

        strip = QFrame(); strip.setProperty("role", "target_strip")
        sl = QHBoxLayout(strip); sl.setContentsMargins(12, 10, 12, 10)
        self.target_state_left  = QLabel("o   TARGET LOCKED"); self.target_state_left.setProperty("role", "target_left")
        self.target_state_right = QLabel("None");              self.target_state_right.setProperty("role", "target_right")
        sl.addWidget(self.target_state_left); sl.addStretch(); sl.addWidget(self.target_state_right)
        layout.addWidget(strip)
        self.active_scan_filter = "all"
        self.filtered_scan_results = []
        self.refresh_interfaces()
        self._maybe_show_scan_hints()
        self._sync_scan_selection_state()

    def _set_scan_placeholder(self, text: str):
        self.scan_table.setRowCount(1)
        for c, v in enumerate([text, "", "", "", "", "", "", "", ""]):
            item = QTableWidgetItem(v)
            item.setTextAlignment(Qt.AlignCenter if c else (Qt.AlignVCenter | Qt.AlignLeft))
            self.scan_table.setItem(0, c, item)
        self.select_btn.setEnabled(False)
        self.scan_selection_label.setText("Selected: none")

    def _security_item(self, security: str) -> QTableWidgetItem:
        sec = security.upper()
        if "WPA3" in sec:
            label, rank = "WPA3", 4
        elif "WPA2" in sec:
            label, rank = "WPA2", 3
        elif "OPEN" in sec:
            label, rank = "OPEN", 1
        else:
            label, rank = (sec or "UNKNOWN"), 2
        item = QTableWidgetItem(label)
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, rank)
        return item

    def _security_cell_widget(self, security: str) -> QWidget:
        sec = (security or "Unknown").upper()
        if "WPA3" in sec:
            text, icon, fg, border, bg = "WPA3 SECURE", "LOCK", "#53e2ff", "#2aa7d4", "#0e2c3b"
        elif "WPA2" in sec:
            text, icon, fg, border, bg = "WPA2 SECURE", "LOCK", "#52ffb1", "#25b874", "#0f3326"
        elif "OPEN" in sec:
            text, icon, fg, border, bg = "OPEN RISK", "WARN", "#ffd486", "#d08a2a", "#3a2b14"
        else:
            text, icon, fg, border, bg = sec, "INFO", "#c0d7ea", "#4d6b88", "#152434"

        chip = QLabel(f"{icon}  {text}")
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(
            "QLabel {"
            f"color:{fg};"
            f"background:{bg};"
            f"border:1px solid {border};"
            "border-radius:8px;"
            "padding:5px 10px;"
            "font-size:8.5pt;"
            "font-weight:800;"
            "letter-spacing:0.6px;"
            "}"
        )
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(10, 4, 10, 4)
        lay.addWidget(chip)
        return holder

    def _chip_widget(self, text: str, fg: str, border: str, bg: str) -> QWidget:
        chip = QLabel(text)
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(
            "QLabel {"
            f"color:{fg};"
            f"background:{bg};"
            f"border:1px solid {border};"
            "border-radius:8px;"
            "padding:4px 8px;"
            "font-size:8pt;"
            "font-weight:800;"
            "letter-spacing:0.5px;"
            "}"
        )
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.addWidget(chip)
        return holder

    def _status_cell_widget(self, status: str) -> QWidget:
        up = (status or "").upper()
        if up.startswith("NEW"):
            if self._pulse_new_on:
                return self._chip_widget(status, "#b7fff1", "#54d8bf", "#185347")
            return self._chip_widget(status, "#85ffe7", "#2eae97", "#113730")
        return self._chip_widget(status, "#b9d5eb", "#4f6f8b", "#142536")

    def _risk_cell_widget(self, risk: str) -> QWidget:
        r = (risk or "").upper()
        if r == "HIGH":
            return self._chip_widget("HIGH", "#ffb4bf", "#b44a61", "#3f1b25")
        if r == "MED":
            return self._chip_widget("MED", "#ffd58e", "#b57b22", "#3f2e15")
        return self._chip_widget("LOW", "#a6ffd0", "#3c9a6a", "#123325")

    def _congestion_cell_widget(self, congestion: str) -> QWidget:
        c = (congestion or "").upper()
        if c == "CROWDED":
            return self._chip_widget("CROWDED", "#ffb7c1", "#b94f67", "#401d27")
        if c == "BUSY":
            return self._chip_widget("BUSY", "#ffd99d", "#bc8330", "#423117")
        return self._chip_widget("CLEAR", "#aef4ff", "#3a8ea0", "#13313a")

    def _signal_cell_widget(self, signal: int) -> QWidget:
        signal = max(0, min(100, int(signal)))

        if signal >= 75:
            left, right, txt = "#31ff84", "#09de9a", "#7dffc2"
        elif signal >= 45:
            left, right, txt = "#ffd34d", "#ffb347", "#ffe49a"
        else:
            left, right, txt = "#ff7373", "#ff4f6d", "#ffb3bf"

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(10, 0, 10, 0)
        root_layout.setSpacing(8)

        track = QFrame()
        track.setFixedHeight(14)
        track.setMinimumWidth(120)
        track.setMaximumWidth(120)
        track.setStyleSheet(
            "QFrame {"
            "background:#0a1d32;"
            "border:1px solid #1b4d78;"
            "border-radius:7px;"
            "}"
        )

        fill = QFrame(track)
        fill_width = max(8, int((signal / 100) * 118))
        fill.setGeometry(1, 1, fill_width, 12)
        fill.setStyleSheet(
            "QFrame {"
            f"background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {left}, stop:1 {right});"
            "border-radius:6px;"
            "}"
        )

        pct = QLabel(f"{signal}%")
        pct.setStyleSheet(
            "QLabel {"
            f"color:{txt};"
            "font-weight:800;"
            "font-size:10pt;"
            "letter-spacing:0.6px;"
            "}"
        )
        pct.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)

        root_layout.addWidget(track)
        root_layout.addWidget(pct)
        root_layout.addStretch()
        return root

    def _signal_item(self, signal: int) -> QTableWidgetItem:
        signal = max(0, min(100, int(signal)))
        item = QTableWidgetItem(f"{signal:03d}%")
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, signal)
        if signal >= 75:
            item.setForeground(Qt.green)
        elif signal >= 45:
            item.setForeground(Qt.yellow)
        else:
            item.setForeground(Qt.red)
        return item

    def _signal_cell_widget(self, signal: int) -> QWidget:
        signal = max(0, min(100, int(signal)))
        if signal >= 80:
            tone = ("#2dff98", "#00d97a", "#113a2d", "EXCELLENT")
        elif signal >= 60:
            tone = ("#5cd8ff", "#17b1ff", "#0f3044", "STRONG")
        elif signal >= 40:
            tone = ("#ffd86b", "#ffb445", "#3d2e14", "FAIR")
        else:
            tone = ("#ff9a9a", "#ff5f7a", "#44202a", "WEAK")
        left, right, chip_bg, tier = tone

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(10, 4, 10, 4)
        root_layout.setSpacing(8)

        pct = QLabel(f"{signal:02d}%")
        pct.setStyleSheet(
            "QLabel {"
            f"color:{left};"
            "font-weight:900;"
            "font-size:10pt;"
            "letter-spacing:0.7px;"
            "}"
        )
        chip = QLabel(tier)
        chip.setStyleSheet(
            "QLabel {"
            f"background:{chip_bg};"
            f"border:1px solid {right};"
            "border-radius:7px;"
            f"color:{left};"
            "font-size:6.8pt;"
            "font-weight:800;"
            "padding:1px 8px;"
            "letter-spacing:0.6px;"
            "}"
        )
        chip.setMinimumWidth(74)
        chip.setAlignment(Qt.AlignCenter)
        root.setToolTip(
            "Signal quality guide:\n"
            "80-100: excellent stability\n"
            "60-79: strong and reliable\n"
            "40-59: fair/intermittent\n"
            "0-39: weak"
        )
        root_layout.addWidget(pct)
        root_layout.addWidget(chip)
        root_layout.addStretch()
        return root

    def _tick_new_pulse(self):
        self._pulse_new_on = not self._pulse_new_on
        if self.filtered_scan_results:
            self._render_scan_table(self.filtered_scan_results)

    def _animate_scan_refresh(self):
        effect = QGraphicsOpacityEffect(self.scan_table.viewport())
        self.scan_table.viewport().setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(220)
        anim.setStartValue(0.25)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start()
        self._scan_refresh_anim = anim

    def _maybe_show_scan_hints(self):
        if self._scan_hint_shown:
            return
        self._scan_hint_shown = True
        QMessageBox.information(
            self,
            "Scan Tips",
            "Tips:\n- Double-click row to set target.\n- Right-click a row for quick actions.\n- Press Ctrl+F to focus search.",
        )

    def toggle_compare_scans(self, enabled: bool):
        self._scan_compare_enabled = bool(enabled)
        self.apply_scan_filters()

    def update_scan_density(self):
        mode = self.density_combo.currentData()
        self._scan_density_mode = mode or "comfortable"
        self.scan_table.verticalHeader().setDefaultSectionSize(44 if self._scan_density_mode == "compact" else 52)
        self._render_scan_table(self.filtered_scan_results)

    def apply_filter_preset(self):
        preset = self.filter_preset_combo.currentData()
        if preset == "audit":
            self.show_hidden_check.setChecked(True)
            self.set_scan_filter("all")
        elif preset == "open_only":
            self.show_hidden_check.setChecked(True)
            self.set_scan_filter("open")
        elif preset == "5g_strong":
            self.show_hidden_check.setChecked(False)
            self.set_scan_filter("band5")
            self.scan_search_edit.setText("")
        elif preset == "custom":
            return
        self.apply_scan_filters()

    def open_column_menu(self):
        menu = QMenu(self)
        col_map = {
            1: "Status",
            4: "Risk",
            5: "Band",
            6: "Channel",
            7: "Congestion",
            8: "BSSID/Vendor",
        }
        for col, label in col_map.items():
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(not self.scan_table.isColumnHidden(col))
            action.toggled.connect(lambda checked, c=col: self.scan_table.setColumnHidden(c, not checked))
        menu.exec(self.columns_btn.mapToGlobal(self.columns_btn.rect().bottomLeft()))

    def copy_selected_bssid(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if not net:
            return
        QApplication.clipboard().setText(net.bssid or "")
        self.statusBar().showMessage("BSSID copied to clipboard")

    def _channel_to_band(self, channel: int) -> str:
        if channel >= 36:
            return "5 GHz"
        if 1 <= channel <= 14:
            return "2.4 GHz"
        return "Unknown"

    def _vendor_from_bssid(self, bssid: str) -> str:
        oui = (bssid or "").upper().replace("-", ":")
        if len(oui) < 8:
            return "Unknown"
        prefix = oui[:8]
        vendors = {
            "00:1A:11": "Cisco",
            "00:26:5A": "Apple",
            "3C:84:6A": "TP-Link",
            "D8:0D:17": "Huawei",
            "F4:F2:6D": "Samsung",
            "FC:FB:FB": "Google",
            "B8:27:EB": "Raspberry Pi",
            "9C:3D:CF": "Xiaomi",
        }
        return vendors.get(prefix, "Unknown")

    def _risk_label(self, signal: int, security: str) -> str:
        sec = (security or "").upper()
        score = 0
        if "OPEN" in sec:
            score += 2
        elif "WPA2" in sec:
            score += 1
        if signal >= 70:
            score += 1
        if score >= 3:
            return "HIGH"
        if score == 2:
            return "MED"
        return "LOW"

    def _status_label(self, net) -> str:
        bssid = (net.bssid or "").strip().lower()
        if self._scan_compare_enabled and bssid and bssid in self._scan_prev_by_bssid:
            prev_signal = int(self._scan_prev_by_bssid[bssid].get("signal", int(net.signal or 0)))
            delta = int(net.signal or 0) - prev_signal
            if abs(delta) >= 3:
                sign = "+" if delta > 0 else ""
                return f"Seen {sign}{delta}%"
        if bssid in self._scan_new_bssids:
            return "NEW now"
        ts = self._scan_seen_at.get(bssid)
        if not ts:
            return "Seen now"
        return f"Seen {ts.strftime('%H:%M:%S')}"

    def _congestion_map(self, networks):
        counts = {}
        for net in networks:
            ch = int(net.channel or 0)
            if ch <= 0:
                continue
            counts[ch] = counts.get(ch, 0) + 1
        labels = {}
        for ch, c in counts.items():
            if c >= 4:
                labels[ch] = "Crowded"
            elif c >= 2:
                labels[ch] = "Busy"
            else:
                labels[ch] = "Clear"
        return labels

    def set_scan_filter(self, filter_key: str):
        self.active_scan_filter = filter_key
        for key, btn in self.scan_filter_buttons.items():
            btn.setChecked(key == filter_key)
        self.apply_scan_filters()

    def apply_scan_filters(self):
        query = self.scan_search_edit.text().strip().lower() if hasattr(self, "scan_search_edit") else ""
        filtered = []
        for net in self.scan_results:
            sec = (net.security or "").upper()
            band = self._channel_to_band(int(net.channel or 0))
            if self.active_scan_filter == "strong" and int(net.signal or 0) <= 70:
                continue
            if self.active_scan_filter == "open" and "OPEN" not in sec:
                continue
            if self.active_scan_filter == "secure" and ("WPA2" not in sec and "WPA3" not in sec):
                continue
            if self.active_scan_filter == "band5" and band != "5 GHz":
                continue
            ssid_l = (net.ssid or "").lower()
            bssid_l = (net.bssid or "").lower()
            if not self.show_hidden_check.isChecked() and (net.hidden or not (net.ssid or "").strip()):
                continue
            if query and query not in ssid_l and query not in bssid_l:
                continue
            filtered.append(net)
        self.filtered_scan_results = filtered
        self._render_scan_table(filtered)
        self._sync_scan_selection_state()

    def _render_scan_table(self, networks):
        self.scan_table.setSortingEnabled(False)
        self.scan_table.setRowCount(0)
        if not networks:
            self._set_scan_placeholder("No networks match current filters.")
            self.empty_state_frame.show()
            self.scan_table.setSortingEnabled(True)
            return
        self.empty_state_frame.hide()
        congestion = self._congestion_map(networks)
        self.scan_table.setRowCount(len(networks))
        for row, net in enumerate(networks):
            ssid = net.ssid or "<hidden>"
            ssid_item = QTableWidgetItem(ssid)
            ssid_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if net.hidden or ssid == "<hidden>":
                ssid_item.setForeground(Qt.yellow)
            self.scan_table.setItem(row, 0, ssid_item)
            status_text = self._status_label(net)
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 1, status_item)
            self.scan_table.setCellWidget(row, 1, self._status_cell_widget(status_text))
            self.scan_table.setItem(row, 2, self._signal_item(net.signal))
            self.scan_table.setCellWidget(row, 2, self._signal_cell_widget(net.signal))
            self.scan_table.setItem(row, 3, self._security_item(net.security))
            self.scan_table.setCellWidget(row, 3, self._security_cell_widget(net.security))
            risk = self._risk_label(int(net.signal or 0), net.security or "")
            risk_item = QTableWidgetItem(risk)
            risk_item.setTextAlignment(Qt.AlignCenter)
            risk_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 4, risk_item)
            self.scan_table.setCellWidget(row, 4, self._risk_cell_widget(risk))
            band_item = QTableWidgetItem(self._channel_to_band(int(net.channel or 0)))
            band_item.setTextAlignment(Qt.AlignCenter)
            self.scan_table.setItem(row, 5, band_item)
            ch_item = QTableWidgetItem(str(int(net.channel or 0)))
            ch_item.setTextAlignment(Qt.AlignCenter)
            self.scan_table.setItem(row, 6, ch_item)
            congest_text = congestion.get(int(net.channel or 0), "-")
            congest_item = QTableWidgetItem(congest_text)
            congest_item.setTextAlignment(Qt.AlignCenter)
            congest_item.setForeground(Qt.transparent)
            self.scan_table.setItem(row, 7, congest_item)
            self.scan_table.setCellWidget(row, 7, self._congestion_cell_widget(congest_text))
            vendor = self._vendor_from_bssid(net.bssid or "")
            bssid_item = QTableWidgetItem(f"{net.bssid or '-'}  |  {vendor}")
            bssid_item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.scan_table.setItem(row, 8, bssid_item)
        self.scan_table.sortItems(2, Qt.DescendingOrder)
        self.scan_table.setSortingEnabled(True)
        self._animate_scan_refresh()

    def _sync_scan_selection_state(self):
        row = self.scan_table.currentRow() if hasattr(self, "scan_table") else -1
        net = self._network_from_row(row)
        valid = net is not None
        self.select_btn.setEnabled(valid)
        if not valid:
            self.scan_selection_label.setText("Selected: none")
            self.sel_ssid.setText("SSID: -")
            self.sel_bssid.setText("BSSID: -")
            self.sel_vendor.setText("Vendor: -")
            self.sel_risk.setText("Risk: -")
            self.sel_channel.setText("Channel: -")
            self.sel_seen.setText("Last seen: -")
            return
        self.scan_selection_label.setText(f"Selected: {net.ssid or '<hidden>'} ({net.signal}%)")
        self._last_selected_bssid = (net.bssid or "").strip().lower()
        self.sel_ssid.setText(f"SSID: {net.ssid or '<hidden>'}")
        self.sel_bssid.setText(f"BSSID: {net.bssid or '-'}")
        self.sel_vendor.setText(f"Vendor: {self._vendor_from_bssid(net.bssid or '')}")
        self.sel_risk.setText(f"Risk: {self._risk_label(int(net.signal or 0), net.security or '')}")
        self.sel_channel.setText(f"Channel: {int(net.channel or 0)} ({self._channel_to_band(int(net.channel or 0))})")
        seen = self._scan_seen_at.get((net.bssid or "").strip().lower())
        self.sel_seen.setText(f"Last seen: {seen.strftime('%H:%M:%S') if seen else '-'}")

    def _update_scan_summary(self, networks):
        total = len(networks)
        open_count = sum(1 for n in networks if "OPEN" in (n.security or "").upper())
        secure_count = sum(1 for n in networks if ("WPA2" in (n.security or "").upper() or "WPA3" in (n.security or "").upper()))
        strong_count = sum(1 for n in networks if int(n.signal or 0) > 70)
        self.scan_total_label.setText(f"Total: {total}")
        self.scan_open_label.setText(f"Open: {open_count}")
        self.scan_secure_label.setText(f"WPA2/WPA3: {secure_count}")
        self.scan_strong_label.setText(f"Strong (>70%): {strong_count}")

    def on_scan_row_double_clicked(self, *_args):
        if self.select_btn.isEnabled():
            self.select_target()
            self.tabs.setCurrentIndex(1)

    def _network_from_row(self, row: int):
        if row < 0:
            return None
        bssid_item = self.scan_table.item(row, 8)
        if not bssid_item:
            return None
        bssid = (bssid_item.text() or "").split("|", 1)[0].strip().lower()
        if not bssid or bssid == "-":
            ssid_item = self.scan_table.item(row, 0)
            ssid = (ssid_item.text() if ssid_item else "").strip()
            for net in self.filtered_scan_results:
                if (net.ssid or "<hidden>") == ssid:
                    return net
            return None
        for net in self.filtered_scan_results:
            if (net.bssid or "").strip().lower() == bssid:
                return net
        return None

    def _restore_scan_selection(self):
        target = (self.config.get("target_bssid") or self._last_selected_bssid or "").strip().lower()
        if not target:
            return
        for row in range(self.scan_table.rowCount()):
            item = self.scan_table.item(row, 8)
            if item and item.text().split("|", 1)[0].strip().lower() == target:
                self.scan_table.selectRow(row)
                self.scan_table.scrollToItem(item)
                break

    def open_scan_context_menu(self, pos):
        row = self.scan_table.rowAt(pos.y())
        if row < 0:
            return
        self.scan_table.selectRow(row)
        net = self._network_from_row(row)
        if not net:
            return
        menu = QMenu(self)
        set_target_action = menu.addAction("Set as Target")
        menu.addSeparator()
        copy_ssid_action = menu.addAction("Copy SSID")
        copy_bssid_action = menu.addAction("Copy BSSID")
        copy_row_action = menu.addAction("Copy Row")
        chosen = menu.exec(self.scan_table.viewport().mapToGlobal(pos))
        if chosen == set_target_action:
            self.select_target()
        elif chosen == copy_ssid_action:
            QApplication.clipboard().setText(net.ssid or "<hidden>")
            self.statusBar().showMessage("SSID copied to clipboard")
        elif chosen == copy_bssid_action:
            QApplication.clipboard().setText(net.bssid or "")
            self.statusBar().showMessage("BSSID copied to clipboard")
        elif chosen == copy_row_action:
            row_text = f"{net.ssid or '<hidden>'}, {net.signal}%, {net.security}, {self._channel_to_band(int(net.channel or 0))}, ch {int(net.channel or 0)}, {net.bssid or ''}"
            QApplication.clipboard().setText(row_text)
            self.statusBar().showMessage("Row copied to clipboard")

    def toggle_auto_rescan(self, enabled: bool):
        self._scan_auto_enabled = bool(enabled)
        if enabled:
            self.update_auto_rescan_interval()
            self.statusBar().showMessage("Auto-rescan enabled")
        else:
            self._scan_auto_timer.stop()
            self.statusBar().showMessage("Auto-rescan disabled")

    def update_auto_rescan_interval(self):
        if not self._scan_auto_enabled:
            return
        self._scan_auto_timer.start(int(self.auto_rescan_interval.value()) * 1000)

    def _on_auto_rescan_tick(self):
        if self.scan_btn.isEnabled():
            self.start_scan()

    def refresh_interfaces(self):
        current = self.interface_combo.currentText().strip() if hasattr(self, "interface_combo") else ""
        if not hasattr(self, "interface_combo"):
            return
        self.interface_combo.clear()
        self.interface_combo.addItem("Auto (default)", "")
        ifaces = WiFiScanner.list_interfaces()
        for iface in ifaces:
            self.interface_combo.addItem(iface, iface)
        if ifaces:
            self.iface_health_label.setText("Interface: ready")
        else:
            self.iface_health_label.setText("Interface: no adapter detected")
        if current:
            idx = self.interface_combo.findText(current)
            if idx >= 0:
                self.interface_combo.setCurrentIndex(idx)

    def start_scan(self):
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Administrator Required",
                "GHOSTLINK must be run as Administrator to scan Wi-Fi networks.\n\n"
                "Please restart the application as Administrator.\n(Right-click -> Run as administrator)")
            self.iface_health_label.setText("Interface: admin required")
            return
        self.statusBar().showMessage("Scanning for Wi-Fi networks...")
        self.last_scan_label.setText("Last scan: scanning...")
        self.scan_btn.setEnabled(False); self.scan_table.setRowCount(0); self._set_scan_placeholder("Scanning...")
        selected_iface = self.interface_combo.currentData() if hasattr(self, "interface_combo") else None
        selected_iface = selected_iface or None
        self.worker = ScanWorker(selected_iface); self.worker.finished.connect(self.on_scan_finished); self.worker.error.connect(self.on_scan_error); self.worker.start()

    def on_scan_finished(self, networks):
        self._scan_cycle += 1
        previous_bssids = set(self._scan_seen_at.keys())
        self._scan_prev_by_bssid = {
            (n.bssid or "").strip().lower(): {"signal": int(n.signal or 0), "security": n.security or ""}
            for n in self.scan_results
            if (n.bssid or "").strip()
        }
        current_bssids = set([(n.bssid or "").strip().lower() for n in networks if (n.bssid or "").strip()])
        self._scan_new_bssids = current_bssids.difference(previous_bssids)
        disappeared = previous_bssids.difference(current_bssids)
        changed = 0
        for n in networks:
            b = (n.bssid or "").strip().lower()
            if not b or b not in self._scan_prev_by_bssid:
                continue
            if abs(int(n.signal or 0) - int(self._scan_prev_by_bssid[b].get("signal", int(n.signal or 0)))) >= 3:
                changed += 1
        self.scan_footer_stats.setText(f"Delta: +{len(self._scan_new_bssids)} / -{len(disappeared)} / ~{changed}")
        now = datetime.now()
        for bssid in current_bssids:
            self._scan_seen_at[bssid] = now
        self.scan_results = sorted(networks, key=lambda n: int(n.signal or 0), reverse=True)
        self._update_scan_summary(self.scan_results)
        if self.scan_results:
            self.apply_scan_filters()
            self._restore_scan_selection()
            self.statusBar().showMessage(f"Scan complete: {len(self.scan_results)} network(s) found")
            self.iface_health_label.setText("Interface: ready")
        else:
            self.filtered_scan_results = []
            self._set_scan_placeholder("No networks found. Hints: turn Wi-Fi on, choose correct adapter, then click RESCAN.")
            self.statusBar().showMessage("Scan complete: no networks found")
            self.iface_health_label.setText("Interface: no networks")
        self.last_scan_label.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        self.scan_btn.setEnabled(True)

    def on_scan_error(self, message):
        self.scan_btn.setEnabled(True); self.scan_table.setRowCount(0)
        self._set_scan_placeholder("Scan failed. Hints: Run as Admin, ensure adapter is enabled, then retry scan.")
        self.statusBar().showMessage("Scan failed")
        self.last_scan_label.setText("Last scan: failed")
        self.iface_health_label.setText("Interface: scan error")
        QMessageBox.critical(self, "Scan Error", message)

    def select_target(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if net is not None:
            ssid = net.ssid or "<hidden>"
            self.config["ssid"] = ssid; self.config["interface"] = net.interface
            self.config["target_bssid"] = net.bssid or ""
            self.attack_target_label.setText(f"SSID: {ssid}")
            self.target_state_right.setText(f"{ssid} - {net.security}")
            self.statusBar().showMessage(f"Target selected: {ssid}")

    def export_scan_csv(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results",
            "ghostlink_scan_results.csv",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["SSID", "Status", "Signal", "Security", "Risk", "Band", "Channel", "Congestion", "BSSID", "Vendor", "Interface"])
            congestion = self._congestion_map(self.filtered_scan_results)
            for net in self.filtered_scan_results:
                writer.writerow([
                    net.ssid or "<hidden>",
                    self._status_label(net),
                    int(net.signal or 0),
                    net.security or "Unknown",
                    self._risk_label(int(net.signal or 0), net.security or ""),
                    self._channel_to_band(int(net.channel or 0)),
                    int(net.channel or 0),
                    congestion.get(int(net.channel or 0), "-"),
                    net.bssid or "",
                    self._vendor_from_bssid(net.bssid or ""),
                    net.interface or "",
                ])
        self.statusBar().showMessage(f"Scan CSV exported: {path}")

    def export_scan_json(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Scan Results (JSON)",
            "ghostlink_scan_results.json",
            "JSON files (*.json);;All files (*.*)",
        )
        if not path:
            return
        data = []
        for net in self.filtered_scan_results:
            data.append({
                "ssid": net.ssid or "<hidden>",
                "bssid": net.bssid or "",
                "signal": int(net.signal or 0),
                "security": net.security or "Unknown",
                "risk": self._risk_label(int(net.signal or 0), net.security or ""),
                "band": self._channel_to_band(int(net.channel or 0)),
                "channel": int(net.channel or 0),
                "congestion": self._congestion_map(self.filtered_scan_results).get(int(net.channel or 0), "-"),
                "vendor": self._vendor_from_bssid(net.bssid or ""),
                "status": self._status_label(net),
                "interface": net.interface or "",
            })
        Path(path).write_text(__import__("json").dumps(data, indent=2), encoding="utf-8")
        self.statusBar().showMessage(f"Scan JSON exported: {path}")

    def copy_scan_results(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Copy Scan", "No scan results to copy.")
            return
        lines = ["SSID\tStatus\tSignal\tSecurity\tRisk\tBand\tChannel\tCongestion\tBSSID\tVendor"]
        congestion = self._congestion_map(self.filtered_scan_results)
        for net in self.filtered_scan_results:
            lines.append("\t".join([
                net.ssid or "<hidden>",
                self._status_label(net),
                f"{int(net.signal or 0)}%",
                net.security or "Unknown",
                self._risk_label(int(net.signal or 0), net.security or ""),
                self._channel_to_band(int(net.channel or 0)),
                str(int(net.channel or 0)),
                congestion.get(int(net.channel or 0), "-"),
                net.bssid or "",
                self._vendor_from_bssid(net.bssid or ""),
            ]))
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage("Scan table copied to clipboard")

    def debug_scanner(self):
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin: QMessageBox.critical(self, "Admin Required", "Run as Administrator."); return
        from ghostlink.network.scanner import WiFiScanner
        import traceback
        try:
            networks = WiFiScanner.scan()
            if networks:
                info = "\n".join(f"{n.ssid:<25} {n.signal}%  {n.security}" for n in networks)
                QMessageBox.information(self, "Scanner Diagnostics", f"Found {len(networks)} networks:\n\n{info}")
            else:
                QMessageBox.warning(self, "Scanner Diagnostics", "Scanner returned an empty list.\n\nTry running 'netsh wlan show networks mode=Bssid' manually.")
        except Exception as e:
            QMessageBox.critical(self, "Scanner Error", f"{e}\n\n{traceback.format_exc()}")

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Tab 2 Ã¢â‚¬â€ Attack Config
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def create_attack_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, "ATTACK CONFIG")
        layout = QVBoxLayout(tab); layout.setContentsMargins(14, 14, 14, 14); layout.setSpacing(12)
        layout.addWidget(self.make_tab_header("Attack Configuration", "Define search strategy, performance limits, and optional wordlist source."))

        self.attack_target_label = QLabel("SSID: Not selected"); self.attack_target_label.setProperty("role", "pill")
        layout.addWidget(self.attack_target_label)

        grid = QGridLayout(); grid.setHorizontalSpacing(12); grid.setVerticalSpacing(8)

        pg = QGroupBox("Search Strategy"); pf = QFormLayout(pg)
        pf.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter); pf.setFormAlignment(Qt.AlignLeft | Qt.AlignTop); pf.setSpacing(10)
        self.profile_combo = QComboBox()
        for pid, prof in PROFILES.items(): self.profile_combo.addItem(f"{prof.icon} {prof.name}", pid)
        self.profile_combo.setMaxVisibleItems(9)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed); pf.addRow("Profile:", self.profile_combo)
        self.charset_edit = QLineEdit(self.config["charset"]); self.charset_edit.setPlaceholderText("Characters to brute force"); pf.addRow("Charset:", self.charset_edit)
        self.minlen_spin = QSpinBox(); self.minlen_spin.setRange(1, 12); self.minlen_spin.setValue(self.config["minlen"]); pf.addRow("Min Length:", self.minlen_spin)
        self.maxlen_spin = QSpinBox(); self.maxlen_spin.setRange(1, 12); self.maxlen_spin.setValue(self.config["maxlen"]); pf.addRow("Max Length:", self.maxlen_spin)

        eg = QGroupBox("Execution Limits"); ef = QFormLayout(eg)
        ef.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter); ef.setFormAlignment(Qt.AlignLeft | Qt.AlignTop); ef.setSpacing(10)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1, 8);  self.threads_spin.setValue(self.config["threads"]); ef.addRow("Threads:", self.threads_spin)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3, 30); self.timeout_spin.setValue(self.config["timeout"]); ef.addRow("Timeout (s):", self.timeout_spin)

        wg = QGroupBox("Wordlist Source"); wl = QVBoxLayout(wg); wl.setSpacing(10)
        self.wordlist_edit = QTextEdit()
        self.wordlist_edit.setPlaceholderText("Paste/type passwords here (one per line), or paste a full wordlist file path.")
        self.wordlist_edit.setFixedHeight(88)
        self.wordlist_edit.textChanged.connect(self.update_wordlist_mode_hint)
        wl.addWidget(self.wordlist_edit)
        self.wordlist_mode_hint = QLabel("Mode: none")
        self.wordlist_mode_hint.setProperty("role", "meta")
        wl.addWidget(self.wordlist_mode_hint)
        wb = QHBoxLayout(); wb.setSpacing(8)
        self.browse_btn   = QPushButton("BROWSE"); self.browse_btn.setProperty("variant", "secondary");   self.browse_btn.clicked.connect(self.browse_wordlist);               wb.addWidget(self.browse_btn)
        self.template_btn = QPushButton("TEMPLATE"); self.template_btn.setProperty("variant", "secondary"); self.template_btn.clicked.connect(self.download_wordlist_template); wb.addWidget(self.template_btn)
        self.clear_wl_btn = QPushButton("CLEAR");  self.clear_wl_btn.setProperty("variant", "secondary"); self.clear_wl_btn.clicked.connect(lambda: self.wordlist_edit.clear()); wb.addWidget(self.clear_wl_btn)
        wb.addStretch(); wl.addLayout(wb)
        self.update_wordlist_mode_hint()

        xg = QGroupBox("Execution"); xl = QVBoxLayout(xg); xl.setSpacing(10)
        self.cache_check = QCheckBox("Include previously cached passwords"); self.cache_check.setChecked(not self.config["skip_cached"]); xl.addWidget(self.cache_check)
        pl = QLabel("Start will switch to Progress and begin worker execution."); pl.setProperty("role", "meta"); xl.addWidget(pl)
        self.start_attack_btn = QPushButton("START ATTACK"); self.start_attack_btn.setProperty("variant", "critical"); self.start_attack_btn.clicked.connect(self.start_attack); xl.addWidget(self.start_attack_btn)

        grid.addWidget(pg, 0, 0); grid.addWidget(wg, 0, 1); grid.addWidget(eg, 1, 0); grid.addWidget(xg, 1, 1)
        grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)
        layout.addLayout(grid); layout.addStretch()

    def on_profile_changed(self):
        pid = self.profile_combo.currentData()
        if pid and pid in PROFILES: self.charset_edit.setText(PROFILES[pid].charset)

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text files (*.txt *.lst *.dic);;All files (*.*)")
        if path:
            self.wordlist_edit.setPlainText(path)

    def download_wordlist_template(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Wordlist Template",
            "ghostlink_wordlist_template.txt",
            "Text files (*.txt);;All files (*.*)",
        )
        if not path:
            return
        sample_words = [
            "# GHOSTLINK Wordlist Template",
            "# One candidate password per line.",
            "# Remove comment lines before running if you want.",
            "password123",
            "welcome123",
            "letmein2026",
            "qwerty123",
            "admin@123",
            "wifi@home",
            "company2026",
            "summer2026!",
        ]
        Path(path).write_text("\n".join(sample_words) + "\n", encoding="utf-8")
        self.statusBar().showMessage(f"Template saved: {path}")

    def update_wordlist_mode_hint(self):
        wl_raw = self.wordlist_edit.toPlainText().strip()
        if not wl_raw:
            self.wordlist_mode_hint.setText("Mode: none (optional)")
            return
        if "\n" not in wl_raw and Path(wl_raw).exists():
            self.wordlist_mode_hint.setText("Mode: file path detected")
            return
        inline_count = len([w for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")])
        self.wordlist_mode_hint.setText(f"Mode: inline list detected ({inline_count} candidates)")

    def update_config_from_gui(self):
        self.config["charset"]     = self.charset_edit.text()
        self.config["minlen"]      = self.minlen_spin.value()
        self.config["maxlen"]      = self.maxlen_spin.value()
        self.config["threads"]     = self.threads_spin.value()
        self.config["timeout"]     = self.timeout_spin.value()
        wl_raw = self.wordlist_edit.toPlainText().strip()
        self.config["wordlist"] = None
        self.config["wordlist_inline"] = None
        if wl_raw:
            if "\n" not in wl_raw and Path(wl_raw).exists():
                self.config["wordlist"] = Path(wl_raw)
            else:
                inline_words = [w.strip() for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")]
                self.config["wordlist_inline"] = inline_words if inline_words else None
        self.config["skip_cached"] = not self.cache_check.isChecked()

    def start_attack(self):
        if not self.config.get("ssid"):
            QMessageBox.warning(self, "No Target", "Please scan and select a target first."); return
        self.update_config_from_gui(); self.tabs.setCurrentIndex(2)
        self.progress_text.clear(); self.progress_text.append("Starting attack...\n")
        self.progress_bar.setValue(0); self.progress_percent_label.setText("Progress: 0%")
        self.speed_label.setText("Speed: 0 pwd/s"); self.attempts_label.setText("Attempts: 0"); self.current_pwd_label.setText("Current: -")
        self.attack_worker = AttackWorker(self.config)
        self.attack_worker.attack_started.connect(self.on_attack_started)
        self.attack_worker.progress_update.connect(self.on_progress_update)
        self.attack_worker.finished.connect(self.on_attack_finished)
        self.attack_worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.attack_worker.start()
        self.start_attack_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.statusBar().showMessage(f"Attack running against {self.config['ssid']}")

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Tab 3 Ã¢â‚¬â€ Progress
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def create_progress_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, "PROGRESS")
        layout = QVBoxLayout(tab); layout.setContentsMargins(14, 14, 14, 14); layout.setSpacing(12)
        layout.addWidget(self.make_tab_header("Live Telemetry", "Track candidate processing rate, attempts, and active password candidate."))

        mg = QGridLayout(); mg.setHorizontalSpacing(10); mg.setVerticalSpacing(10)
        self.progress_percent_label = QLabel("Progress: 0%"); self.progress_percent_label.setProperty("role", "metric"); mg.addWidget(self.progress_percent_label, 0, 0)
        self.speed_label            = QLabel("Speed: 0 pwd/s"); self.speed_label.setProperty("role", "metric");           mg.addWidget(self.speed_label, 0, 1)
        self.attempts_label         = QLabel("Attempts: 0");    self.attempts_label.setProperty("role", "metric");        mg.addWidget(self.attempts_label, 1, 0)
        self.current_pwd_label      = QLabel("Current: -");     self.current_pwd_label.setProperty("role", "metric");     mg.addWidget(self.current_pwd_label, 1, 1)
        layout.addLayout(mg)

        pbg = QGroupBox("Progress"); pbl = QVBoxLayout(pbg)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 100); self.progress_bar.setValue(0); self.progress_bar.setFormat("%p%")
        pbl.addWidget(self.progress_bar); layout.addWidget(pbg)

        lg = QGroupBox("Execution Log"); ll = QVBoxLayout(lg)
        self.progress_text = QTextEdit(); self.progress_text.setReadOnly(True); self.progress_text.setFont(QFont("Consolas", 10))
        ll.addWidget(self.progress_text); layout.addWidget(lg, 1)

        ctrl = QHBoxLayout(); ctrl.addStretch()
        self.stop_btn = QPushButton("STOP"); self.stop_btn.setProperty("variant", "danger"); self.stop_btn.clicked.connect(self.stop_attack); self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.stop_btn); layout.addLayout(ctrl)

    def on_attack_started(self, total):
        self.total_combinations = total
        if total > 0: self.progress_text.append(f"Search space: {total:,} passwords\n")

    def on_progress_update(self, current_password, attempts, speed):
        self.attempts_label.setText(f"Attempts: {attempts}")
        self.speed_label.setText(f"Speed: {speed:.1f} pwd/s")
        self.current_pwd_label.setText(f"Current: {current_password[:38] if current_password else '-'}")
        if attempts % 50 == 0:
            self.progress_text.append(f"Attempt {attempts}: {current_password[:25]:<25} @ {speed:.1f}/s")
        if self.total_combinations > 0:
            pct = min(int((attempts / self.total_combinations) * 100), 100)
            self.progress_bar.setValue(pct); self.progress_percent_label.setText(f"Progress: {pct}%")

    def stop_attack(self):
        if self.attack_worker:
            self.attack_worker.stop(); self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopping attack worker...")

    def on_attack_finished(self, password, attempts, elapsed, verified):
        self.start_attack_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        was_stopped = bool(self.attack_worker and self.attack_worker.stop_requested)
        if password:
            self.progress_bar.setValue(100); self.progress_percent_label.setText("Progress: 100%")
        else:
            self.progress_percent_label.setText(f"Progress: {self.progress_bar.value()}%")
        if password and verified:
            self.show_compromised_dialog(password, attempts, elapsed)
            self.statusBar().showMessage("Attack complete: password verified")
        elif was_stopped:
            QMessageBox.information(self, "Attack Stopped", "Attack was stopped by user.")
            self.statusBar().showMessage("Attack stopped by user")
        else:
            QMessageBox.information(self, "Attack Complete", "Password not found within search space.")
            self.statusBar().showMessage("Attack complete: password not found")

    def show_compromised_dialog(self, password: str, attempts: int, elapsed: float) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Target Compromised")
        dlg.setModal(True)
        dlg.setMinimumWidth(430)
        dlg.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0a192d, stop:1 #060f1f);
                border: 1px solid #1d5c8f;
                border-radius: 14px;
            }
            QFrame[role="top_band"] {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00b8ff, stop:1 #09de9a);
                border-top-left-radius: 14px;
                border-top-right-radius: 14px;
                min-height: 6px;
                max-height: 6px;
            }
            QLabel[role="tag"] {
                color: #8ecfff;
                font-size: 9pt;
                font-weight: 700;
                letter-spacing: 1px;
            }
            QLabel[role="headline"] {
                color: #f4fbff;
                font-size: 19px;
                font-weight: 900;
            }
            QLabel[role="badge"] {
                background: qradialgradient(cx:0.5, cy:0.45, radius:0.9, fx:0.48, fy:0.4, stop:0 #5ad3ff, stop:1 #0075d3);
                border: 1px solid #3ad0ff;
                border-radius: 28px;
                color: #ffffff;
                font-size: 28px;
                font-weight: 700;
                min-width: 56px;
                max-width: 56px;
                min-height: 56px;
                max-height: 56px;
                qproperty-alignment: AlignCenter;
            }
            QFrame[role="card"] {
                background: #07152b;
                border: 1px solid #1f507d;
                border-radius: 10px;
            }
            QLabel[role="key"] {
                color: #57b7ff;
                font-size: 9pt;
                font-weight: 700;
            }
            QLabel[role="value"] {
                color: #f2f9ff;
                font-size: 10.5pt;
                font-weight: 700;
            }
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #008dd8, stop:1 #00c9ff);
                color: #01182b;
                border: none;
                border-radius: 10px;
                min-height: 38px;
                padding: 0 20px;
                font-size: 10pt;
                font-weight: 900;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00a0f2, stop:1 #26dcff);
            }
            QPushButton:pressed {
                background: #0083c8;
            }
        """)

        root = QVBoxLayout(dlg)
        root.setContentsMargins(0, 0, 0, 14)
        root.setSpacing(0)

        top_band = QFrame()
        top_band.setProperty("role", "top_band")
        root.addWidget(top_band)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(18, 14, 18, 0)
        body_layout.setSpacing(12)
        root.addWidget(body)

        tag = QLabel("VERIFIED ACCESS")
        tag.setProperty("role", "tag")
        body_layout.addWidget(tag)

        heading_row = QHBoxLayout()
        heading_row.setContentsMargins(0, 0, 0, 0)
        heading_row.setSpacing(12)
        badge = QLabel("i")
        badge.setProperty("role", "badge")
        heading_row.addWidget(badge, 0, Qt.AlignTop)

        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 2, 0, 0)
        title_col.setSpacing(3)
        headline = QLabel("Password Found")
        headline.setProperty("role", "headline")
        subtitle = QLabel("Target compromised successfully.")
        subtitle.setStyleSheet("color:#8ab0cf; font-size:10pt;")
        title_col.addWidget(headline)
        title_col.addWidget(subtitle)
        heading_row.addLayout(title_col, 1)
        body_layout.addLayout(heading_row)

        card = QFrame()
        card.setProperty("role", "card")
        card_layout = QGridLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setHorizontalSpacing(14)
        card_layout.setVerticalSpacing(8)
        details = [
            ("SSID", str(self.config.get("ssid") or "-")),
            ("Password", str(password)),
            ("Attempts", f"{attempts:,}"),
            ("Time", f"{elapsed:.1f}s"),
        ]
        for row, (key, value) in enumerate(details):
            key_lbl = QLabel(key.upper())
            key_lbl.setProperty("role", "key")
            val_lbl = QLabel(value)
            val_lbl.setProperty("role", "value")
            val_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            card_layout.addWidget(key_lbl, row, 0)
            card_layout.addWidget(val_lbl, row, 1)
        body_layout.addWidget(card)

        button_row = QHBoxLayout()
        button_row.addStretch()
        ok_btn = QPushButton("CONTINUE")
        ok_btn.clicked.connect(dlg.accept)
        button_row.addWidget(ok_btn)
        body_layout.addLayout(button_row)

        dlg.exec()

    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    # Tab 4 Ã¢â‚¬â€ Recon  (REDESIGNED)
    # Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    #
    # Layout: horizontal QSplitter
    #   LEFT  Ã¢â‚¬â€ narrow sidebar  (190 px, not resizable by user)
    #             Ã¢â‚¬Â¢ title + subtitle
    #             Ã¢â‚¬Â¢ 9 module buttons (vertical stack, compact)
    #             Ã¢â‚¬Â¢ RUN ALL button
    #             Ã¢â‚¬Â¢ spacer
    #             Ã¢â‚¬Â¢ running-indicator strip (vertical, compact)
    #   RIGHT Ã¢â‚¬â€ main output area  (stretches to fill remaining width)
    #             Ã¢â‚¬Â¢ toolbar row  (filter pills + action buttons + checkboxes)
    #             Ã¢â‚¬Â¢ recon_output QTextEdit  Ã¢â€ Â given stretch=1, fills everything
    #
    # This removes the "Structured Recon Data" table that was eating vertical
    # space and leaving only ~2 lines for the actual output.  The rich HTML
    # rendered by _render_recon_output already contains all structured data
    # beautifully, so the table was purely redundant.

    def create_recon_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "RECON")

        # Root layout Ã¢â‚¬â€ no padding; the splitter fills the whole pane
        root = QHBoxLayout(tab)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Ã¢â€â‚¬Ã¢â€â‚¬ Horizontal splitter Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter)

        # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
        # LEFT SIDEBAR
        # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
        sidebar_outer = QWidget()
        sidebar_outer.setProperty("role", "recon_sidebar")
        sidebar_outer.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar_outer)
        sidebar_layout.setContentsMargins(12, 14, 8, 14)
        sidebar_layout.setSpacing(0)

        # Header
        title_lbl = QLabel("Recon")
        title_lbl.setStyleSheet(
            "color:#f6fcff; font-size:16px; font-weight:800; letter-spacing:1px;"
        )
        sub_lbl = QLabel("Network intelligence")
        sub_lbl.setStyleSheet("color:#3c8ad0; font-size:8.5pt;")
        sidebar_layout.addWidget(title_lbl)
        sidebar_layout.addWidget(sub_lbl)
        sidebar_layout.addSpacing(14)

        # Section label
        mod_section = QLabel("MODULES")
        mod_section.setStyleSheet(
            "color:#1e5a8a; font-size:7pt; font-weight:900; letter-spacing:2px;"
        )
        sidebar_layout.addWidget(mod_section)
        sidebar_layout.addSpacing(6)

        # Module buttons Ã¢â‚¬â€ vertical stack, compact
        modules = [
            ("1 Full Recon",          "full"),
            ("2 My Device",           "my_device"),
            ("3 Infrastructure",      "infrastructure"),
            ("4 Wireless Analysis",   "wireless"),
            ("5 Internet Identity",   "internet"),
            ("6 Performance",         "performance"),
            ("7 Resources & Sharing", "resources"),
            ("8 Security Insights",   "security"),
            ("9 Traffic Analysis",    "traffic"),
        ]
        self._mod_buttons = {}
        for label, mid in modules:
            btn = QPushButton(label)
            btn.setProperty("role", "mod_btn")
            btn.setFixedHeight(30)
            btn.clicked.connect(lambda checked, m=mid: self._run_recon_module(m))
            sidebar_layout.addWidget(btn)
            sidebar_layout.addSpacing(3)
            self._mod_buttons[mid] = btn

        sidebar_layout.addSpacing(8)

        # Run All
        run_all_btn = QPushButton(">  RUN ALL MODULES")
        run_all_btn.setProperty("role", "run_all_btn")
        run_all_btn.setFixedHeight(34)
        run_all_btn.clicked.connect(lambda: self._run_recon_module("all"))
        sidebar_layout.addWidget(run_all_btn)

        sidebar_layout.addStretch()

        # Ã¢â€â‚¬Ã¢â€â‚¬ Running indicator (inside sidebar, bottom) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        self.recon_status_strip = QFrame()
        self.recon_status_strip.setProperty("role", "recon_running")
        self.recon_status_strip.setVisible(False)
        self.recon_status_strip.setFixedHeight(52)

        ss_layout = QVBoxLayout(self.recon_status_strip)
        ss_layout.setContentsMargins(10, 6, 10, 6)
        ss_layout.setSpacing(4)

        ss_top = QHBoxLayout()
        ss_top.setSpacing(6)
        self.recon_spinner_label = QLabel("Ã¢â€”Â")
        self.recon_spinner_label.setStyleSheet(
            "color:#00b8ff; font-size:12pt; font-weight:900;"
        )
        self._spinner_frames = ["Ã¢â€”Â", "Ã¢â€”â€œ", "Ã¢â€”â€˜", "Ã¢â€”â€™"]
        self._spinner_idx = 0

        self.recon_running_label = QLabel("RunningÃ¢â‚¬Â¦")
        self.recon_running_label.setStyleSheet(
            "color:#a0d4ff; font-size:8pt; font-weight:700; letter-spacing:0.5px;"
        )
        ss_top.addWidget(self.recon_spinner_label)
        ss_top.addWidget(self.recon_running_label)
        ss_top.addStretch()
        ss_layout.addLayout(ss_top)

        self.recon_pulse_bar = QProgressBar()
        self.recon_pulse_bar.setRange(0, 0)
        self.recon_pulse_bar.setFixedHeight(4)
        self.recon_pulse_bar.setTextVisible(False)
        self.recon_pulse_bar.setStyleSheet("""
            QProgressBar { background:#071930; border:none; border-radius:2px; }
            QProgressBar::chunk {
                border-radius:2px;
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #00b8ff, stop:1 #09de9a);
            }
        """)
        ss_layout.addWidget(self.recon_pulse_bar)
        sidebar_layout.addWidget(self.recon_status_strip)

        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(120)
        self._spinner_timer.timeout.connect(self._tick_spinner)

        splitter.addWidget(sidebar_outer)

        # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
        # RIGHT OUTPUT PANEL
        # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(8, 14, 14, 14)
        right_layout.setSpacing(8)

        # Ã¢â€â‚¬Ã¢â€â‚¬ Toolbar Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        toolbar_frame = QFrame()
        toolbar_frame.setStyleSheet(
            "QFrame { background:#04111f; border:1px solid #0f2d47; border-radius:7px; }"
        )
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(8, 5, 8, 5)
        toolbar_layout.setSpacing(5)

        # Filter pills
        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_all   = self._make_filter_pill("All",     active=True)
        self._recon_pill_info  = self._make_filter_pill("Info 0")
        self._recon_pill_data  = self._make_filter_pill("Data 0")
        self._recon_pill_warn  = self._make_filter_pill("Warn 0")
        self._recon_pill_error = self._make_filter_pill("Error 0")
        for pill in (self._recon_pill_all, self._recon_pill_info,
                     self._recon_pill_data, self._recon_pill_warn, self._recon_pill_error):
            toolbar_layout.addWidget(pill)

        toolbar_layout.addStretch()

        # Action buttons
        copy_btn = QPushButton("COPY")
        copy_btn.setProperty("role", "toolbar_btn")
        copy_btn.setFixedHeight(26)
        copy_btn.clicked.connect(self._recon_copy_log)
        toolbar_layout.addWidget(copy_btn)

        csv_btn = QPushButton("CSV")
        csv_btn.setProperty("role", "toolbar_btn")
        csv_btn.setFixedHeight(26)
        csv_btn.clicked.connect(self._recon_export_csv)
        toolbar_layout.addWidget(csv_btn)

        json_btn = QPushButton("JSON")
        json_btn.setProperty("role", "toolbar_btn")
        json_btn.setFixedHeight(26)
        json_btn.clicked.connect(self._recon_export_json)
        toolbar_layout.addWidget(json_btn)

        clear_btn = QPushButton("CLEAR")
        clear_btn.setProperty("role", "clear_btn")
        clear_btn.setFixedHeight(26)
        clear_btn.clicked.connect(self._recon_clear)
        toolbar_layout.addWidget(clear_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("color:#1a3d5e;")
        toolbar_layout.addWidget(sep)

        self._autoscroll_check = QCheckBox("Auto-scroll")
        self._autoscroll_check.setChecked(True)
        self._autoscroll_check.setStyleSheet("font-size:8.5pt; color:#7aaac8;")
        toolbar_layout.addWidget(self._autoscroll_check)

        self._severity_combo = QComboBox()
        self._severity_combo.addItems([
            "All",
            "Alerts (Warn + Error)",
            "Info",
            "Data",
            "Warn",
            "Error",
        ])
        self._severity_combo.setFixedHeight(24)
        self._severity_combo.currentIndexChanged.connect(self._on_recon_view_changed)
        toolbar_layout.addWidget(self._severity_combo)

        self._collapse_sections_check = QCheckBox("Collapse sections")
        self._collapse_sections_check.setChecked(False)
        self._collapse_sections_check.setStyleSheet("font-size:8.5pt; color:#7aaac8;")
        self._collapse_sections_check.toggled.connect(self._on_recon_view_changed)
        toolbar_layout.addWidget(self._collapse_sections_check)

        right_layout.addWidget(toolbar_frame)

        # Ã¢â€â‚¬Ã¢â€â‚¬ Summary strip Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        summary_frame = QFrame()
        summary_frame.setProperty("role", "recon_summary")
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(8, 6, 8, 6)
        summary_layout.setSpacing(6)
        self._summary_sections = QLabel("Sections 0")
        self._summary_sections.setProperty("role", "summary_card")
        self._summary_entries = QLabel("Entries 0")
        self._summary_entries.setProperty("role", "summary_card")
        self._summary_alerts = QLabel("Alerts 0")
        self._summary_alerts.setProperty("role", "summary_card")
        self._summary_view = QLabel("View ALL")
        self._summary_view.setProperty("role", "summary_card")
        summary_layout.addWidget(self._summary_sections)
        summary_layout.addWidget(self._summary_entries)
        summary_layout.addWidget(self._summary_alerts)
        summary_layout.addWidget(self._summary_view)
        summary_layout.addStretch()
        right_layout.addWidget(summary_frame)

        # Ã¢â€â‚¬Ã¢â€â‚¬ Recon output Ã¢â‚¬â€ THE HERO WIDGET Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        # Wrap in a styled frame so it has the dark border
        output_frame = QFrame()
        output_frame.setProperty("role", "recon_output_frame")
        output_frame_layout = QVBoxLayout(output_frame)
        output_frame_layout.setContentsMargins(0, 0, 0, 0)
        output_frame_layout.setSpacing(0)

        self.recon_output = QTextEdit()
        self.recon_output.setReadOnly(True)
        self.recon_output.setFont(QFont("Consolas", 10))
        # Remove the default border since the frame provides it
        self.recon_output.setStyleSheet("""
            QTextEdit {
                background: #060f1c;
                border: none;
                border-radius: 8px;
                color: #ebf8ff;
                padding: 6px 8px;
                line-height: 1.45;
                selection-background-color: #0e3358;
                selection-color: #ffffff;
            }
        """)
        output_frame_layout.addWidget(self.recon_output)

        # stretch=1 Ã¢â€ â€™ this consumes ALL remaining vertical space
        right_layout.addWidget(output_frame, 1)

        splitter.addWidget(right_widget)

        # Fix sidebar width, let right panel expand
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        self._update_recon_summary()

    # Ã¢â€â‚¬Ã¢â€â‚¬ Filter pill helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def _make_filter_pill(self, text: str, active: bool = False) -> QLabel:
        pill = QLabel(text)
        pill.setFixedHeight(22)
        base = (
            "border-radius:4px; padding:2px 9px; font-size:7.5pt; font-weight:800;"
            "font-family:'Consolas',monospace; letter-spacing:0.5px;"
        )
        if active:
            pill.setStyleSheet(base + "background:#0d2d4a; border:1px solid #00b8ff; color:#00e5ff;")
        else:
            pill.setStyleSheet(base + "background:#061426; border:1px solid #1e4d79; color:#4b95d5;")
        return pill

    # Ã¢â€â‚¬Ã¢â€â‚¬ Toolbar action slots Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def _recon_copy_log(self):
        QApplication.clipboard().setText(self.recon_output.toPlainText())
        self.statusBar().showMessage("Log copied to clipboard")

    def _recon_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "recon_data.csv", "CSV Files (*.csv)")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Tag", "Kind", "Label", "Value", "Content"])
            rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()} for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
            for row in rows:
                writer.writerow([
                    row.get("tag", ""),
                    row.get("kind", ""),
                    row.get("label", ""),
                    row.get("value", ""),
                    row.get("content", ""),
                ])
        self.statusBar().showMessage(f"CSV exported Ã¢â€ â€™ {path}")

    def _recon_export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "recon_data.json", "JSON Files (*.json)")
        if not path:
            return
        import json
        rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()} for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        self.statusBar().showMessage(f"JSON exported Ã¢â€ â€™ {path}")

    def _recon_clear(self):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self.statusBar().showMessage("Recon output cleared")
        self._recon_records = []
        self._update_recon_summary()

    def _reset_recon_metrics(self):
        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_info.setText("Info 0")
        self._recon_pill_data.setText("Data 0")
        self._recon_pill_warn.setText("Warn 0")
        self._recon_pill_error.setText("Error 0")

    def _on_recon_view_changed(self):
        combo_text = self._severity_combo.currentText().lower()
        if "alerts" in combo_text:
            self._recon_filter_mode = "alerts"
        elif "info" in combo_text:
            self._recon_filter_mode = "info"
        elif "data" in combo_text:
            self._recon_filter_mode = "data"
        elif "warn" in combo_text:
            self._recon_filter_mode = "warn"
        elif "error" in combo_text:
            self._recon_filter_mode = "error"
        else:
            self._recon_filter_mode = "all"
        self._recon_collapse_sections = self._collapse_sections_check.isChecked()
        self._refresh_recon_view()

    def _passes_recon_filter(self, rec: dict) -> bool:
        mode = self._recon_filter_mode
        if mode == "all":
            return True

        kind = rec.get("kind", "")
        tag = str(rec.get("tag", "")).upper()

        if kind in ("section",):
            return True
        if kind in ("divider", "table_header", "table_row", "kv", "meter"):
            return mode == "all"

        if mode == "alerts":
            return tag in ("WARN", "ERROR")
        return tag == mode.upper()

    def _update_recon_summary(self):
        sections = sum(1 for r in self._recon_records if r.get("kind") == "section")
        entries = sum(1 for r in self._recon_records if r.get("kind") not in ("section", "divider"))
        alerts = sum(1 for r in self._recon_records if str(r.get("tag", "")).upper() in ("WARN", "ERROR"))
        view = self._recon_filter_mode.upper() if self._recon_filter_mode != "alerts" else "ALERTS"
        if self._recon_collapse_sections:
            view += " + COLLAPSED"
        self._summary_sections.setText(f"Sections {sections}")
        self._summary_entries.setText(f"Entries {entries}")
        self._summary_alerts.setText(f"Alerts {alerts}")
        self._summary_view.setText(f"View {view}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Spinner helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def _tick_spinner(self):
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
        self.recon_spinner_label.setText(self._spinner_frames[self._spinner_idx])

    def _set_recon_running(self, module_name: str):
        label = module_name.upper().replace("_", " ")
        self.recon_running_label.setText(f"{label}Ã¢â‚¬Â¦")
        self.recon_status_strip.setVisible(True)
        self._spinner_timer.start()
        # Visually highlight the active button
        for mid, btn in self._mod_buttons.items():
            if mid == module_name:
                btn.setStyleSheet(
                    "QPushButton[role='mod_btn'] {"
                    "background:#0d2f56; border:1px solid #00b8ff; color:#00e5ff;}"
                )
            else:
                btn.setStyleSheet("")

    def _set_recon_idle(self):
        self._spinner_timer.stop()
        self.recon_status_strip.setVisible(False)
        # Reset all button styles
        for btn in self._mod_buttons.values():
            btn.setStyleSheet("")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Module dispatch Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

    def _run_recon_module(self, module_id: str):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self._recon_records = []
        self._update_recon_summary()
        self._set_recon_running(module_id)
        self.statusBar().showMessage(f"Running recon module: {module_id}")

        import ghostlink.network.recon as recon_mod
        func_map = {
            "full":           lambda: recon_mod.print_recon_result(recon_mod.full_network_recon()),
            "my_device":      recon_mod.scan_my_device,
            "infrastructure": recon_mod.scan_infrastructure,
            "wireless":       recon_mod.scan_wireless,
            "internet":       recon_mod.scan_internet_identity,
            "performance":    recon_mod.scan_performance,
            "resources":      recon_mod.scan_resources,
            "security":       recon_mod.scan_security,
            "traffic":        recon_mod.scan_traffic,
            "all":            self._run_all_modules,
        }
        func = func_map.get(module_id)
        if not func:
            self._set_recon_idle()
            self._append_recon_card("ERROR", f"Unknown module: {module_id}", "#ff5f6d")
            return

        self.worker = ReconWorker(func)
        self.worker.output.connect(self._render_recon_output)
        self.worker.finished.connect(self._on_recon_module_done)
        self.worker.error.connect(
            lambda e: (self._set_recon_idle(), self._append_recon_card("ERROR", str(e), "#ff5f6d"))
        )
        self.worker.start()

    def _on_recon_module_done(self):
        self._set_recon_idle()
        self.statusBar().showMessage("Recon module complete")
        self._append_recon_card("DONE", "Module finished successfully.", "#22c55e")

    def _run_all_modules(self):
        import ghostlink.network.recon as recon_mod
        for m in [
            recon_mod.scan_my_device, recon_mod.scan_infrastructure, recon_mod.scan_wireless,
            recon_mod.scan_internet_identity, recon_mod.scan_performance, recon_mod.scan_resources,
            recon_mod.scan_security, recon_mod.scan_traffic,
        ]:
            m()

    def run_recon(self):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self._recon_records = []
        self._update_recon_summary()
        self._append_recon_card("INFO", "Running full reconnaissance (may take 30-120s)...", "#38bdf8")
        self.statusBar().showMessage("Recon running...")
        self.worker = ReconWorker()
        self.worker.output.connect(self._render_recon_output)
        self.worker.finished.connect(lambda: self.statusBar().showMessage("Recon complete"))
        self.worker.error.connect(lambda e: self._append_recon_card("ERROR", str(e), "#ff5f6d"))
        self.worker.start()

    def on_recon_error(self, message):
        self._set_recon_idle()
        self._append_recon_card("ERROR", message, "#ff5f6d")
        self.statusBar().showMessage("Recon failed")
        QMessageBox.critical(self, "Recon Error", message)

    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
    # Recon rendering Ã¢â‚¬â€ fully finetuned v3
    # Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â

    # Per-tag config: (card-bg, left-accent, badge-text, badge-bg)
    _TAG_CFG: dict[str, tuple[str, str, str, str]] = {
        "DATA":  ("#061e10", "#22c55e", "#22c55e", "#0a2e18"),
        "INFO":  ("#051a28", "#38bdf8", "#38bdf8", "#062233"),
        "WARN":  ("#1e1505", "#f59e0b", "#f59e0b", "#2a1c06"),
        "ERROR": ("#1e0509", "#ff5f6d", "#ff5f6d", "#2a070c"),
        "LOG":   ("#06111e", "#1e4d7a", "#4a8ab5", "#071525"),
    }

    @staticmethod
    def _hl_addresses(safe: str) -> str:
        safe = re.sub(
            r"(\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)",
            r"<span style='color:#c084fc;font-weight:700;'>\1</span>",
            safe,
        )
        safe = re.sub(
            r"(\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d+)?\b)",
            r"<span style='color:#67e8f9;font-weight:600;'>\1</span>",
            safe,
        )
        safe = re.sub(
            r"(\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b)",
            r"<span style='color:#2dd4bf;font-weight:700;'>\1</span>",
            safe,
        )
        safe = re.sub(
            r"(?<![=#\w\-])(\b\d+\b)(?![;%\w\-])",
            r"<span style='color:#fbbf24;'>\1</span>",
            safe,
        )
        return safe

    def _strip_ansi(self, text: str) -> str:
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\uFFFD?\[[0-9;]*m", "", text)
        replacements = {
            "ÃƒÂ¢Ã…â€œÃ¢â‚¬Å“": "Ã¢Å“â€œ",
            "ÃƒÂ¢Ã…â€œÃ¢â‚¬â€": "Ã¢Å“â€”",
            "ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢": "Ã¢â€ â€™",
            "ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢": "Ã¢â‚¬Â¢",
            "ÃƒÂ¢Ã…Â¡Ã‚Â ": "Ã¢Å¡Â ",
            "ÃƒÂ¢Ã¢â‚¬Â¢Ã‚Â": "Ã¢â€¢Â",
            "ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬": "Ã¢â€â‚¬",
            "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â": "Ã¢â‚¬â€",
        }
        for wrong, correct in replacements.items():
            text = text.replace(wrong, correct)
        return text.replace("\r", "")

    def _split_into_lines(self, raw: str) -> list[str]:
        raw = re.sub(r"\b(LOG|DATA|INFO|WARN|ERROR)(None|null|n/a|-)\b", r"\1 \2", raw, flags=re.IGNORECASE)
        text = re.sub(
            r"(?<!\n)(?<!\A)\b(LOG|DATA|INFO|WARN|ERROR)\b",
            r"\n\1",
            raw,
        )
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    _SECTION_KW = [
        "route table", "ipv4", "ipv6", "persistent routes", "active routes",
        "active tcp", "active udp", "connections", "system identity",
        "network interfaces", "dns servers", "internet identity", "my device",
        "infrastructure", "performance", "resources", "security",
        "traffic analysis", "recon result", "wireless", "ghostlink",
    ]

    @staticmethod
    def _is_meter_line(line: str) -> bool:
        compact = line.strip()
        if len(compact) < 8:
            return False
        return bool(re.fullmatch(r"[#=\[\]\(\)\|/\\+\-_.:;%\sÃ¢â€“Ë†Ã¢â€“â€œÃ¢â€“â€™Ã¢â€“â€˜Ã¢â€“ÂÃ¢â€“â€šÃ¢â€“Æ’Ã¢â€“â€žÃ¢â€“â€¦Ã¢â€“â€ Ã¢â€“â€¡]+", compact))

    def _classify_line(self, line: str) -> tuple[str, str]:
        if line.strip().lower() in ("none", "null", "n/a", "-"):
            return "LOG", "Ã¢â‚¬â€"

        m = re.match(r"^(LOG|DATA|INFO|WARN|ERROR)\s*(.*)", line, re.IGNORECASE)
        if m:
            tag  = m.group(1).upper()
            body = m.group(2).strip()
            if not body or body.lower() in ("none", "null", "n/a", "-"):
                return tag, "Ã¢â‚¬â€"
            return tag, body

        status_prefix = re.match(r"^[\[\(]?(Ã¢Å“â€œ|Ã¢Å“â€”|Ã¢Å¡Â |Ã¢â€ â€™)\]?\s*(.*)$", line)
        if status_prefix and status_prefix.group(2).strip():
            sym = status_prefix.group(1)
            msg = status_prefix.group(2).strip()
            if sym == "Ã¢Å“â€œ":
                return "DATA", msg
            if sym == "Ã¢Å“â€”":
                return "ERROR", msg
            if sym == "Ã¢Å¡Â ":
                return "WARN", msg
            return "INFO", msg

        if len(line) >= 6 and re.fullmatch(r"[=\-_.\s]{6,}", line):
            return "DIVIDER", line

        if self._is_meter_line(line):
            return "METER", line.strip()

        kv_colon = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-().]{2,36}):\s+(.+)$", line)
        if kv_colon:
            return "KV", f"{kv_colon.group(1).strip()}\t{kv_colon.group(2).strip()}"

        kv_spaced = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-().]{2,36})\s{2,}(.+)$", line)
        if kv_spaced and len(re.split(r"\s{2,}|\t+", kv_spaced.group(2).strip())) <= 2:
            return "KV", f"{kv_spaced.group(1).strip()}\t{kv_spaced.group(2).strip()}"

        # Handle uppercase "label value" lines with single spaces (e.g. "IPV4 ADDRESS 192.168.1.3/24")
        kv_upper = re.match(r"^([A-Z][A-Z0-9 _/\-]{3,36})\s+(.+)$", line)
        if kv_upper:
            label = kv_upper.group(1).strip()
            value = kv_upper.group(2).strip()
            if (
                len(label.split()) >= 2
                and re.search(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{3,}|yes|no|on-link|preferred|unknown", value, re.IGNORECASE)
                and not re.fullmatch(r"[A-Z0-9 _/\-]{4,}", value)
            ):
                return "KV", f"{label}\t{value}"

        if re.match(r"^(measuring|checking|running|querying|detecting|capturing|scanning|probing)\b", line, re.IGNORECASE):
            return "INFO", line

        low = line.lower()
        is_section_pattern = any(re.search(p, line, re.IGNORECASE) for p in [
            r"^\[\d+\]", r"^={3,}", r"Ã¢â€â‚¬{4,}", r"^#+\s",
        ])
        is_section_keyword = (
            len(line) <= 64
            and any(kw in low for kw in self._SECTION_KW)
            and not line.rstrip().endswith(".")
        )
        is_subheader = bool(re.match(r"^[A-Za-z][A-Za-z0-9 _/\-().]{2,80}:$", line))

        if is_section_pattern or is_section_keyword or is_subheader:
            return "SECTION", line

        if "\t" in line or re.search(r" {3,}", line):
            return "TABLE", line

        return "LOG", line

    def _divider_html(self) -> str:
        return (
            "<div style='"
            "height:1px;"
            "margin:8px 2px;"
            "background:#0f2d4a;"
            "'></div>"
        )

    @staticmethod
    def _hl_semantic(safe: str) -> str:
        # Positive state
        safe = re.sub(
            r"\b(enabled|on|active|responsive|connected|listening|established|secure|good|excellent)\b",
            r"<span style='color:#22c55e;font-weight:700;'>\1</span>",
            safe,
            flags=re.IGNORECASE,
        )
        # Warning / weak state
        safe = re.sub(
            r"\b(warn|warning|degraded|unknown|limited|congested)\b",
            r"<span style='color:#f59e0b;font-weight:700;'>\1</span>",
            safe,
            flags=re.IGNORECASE,
        )
        # Negative / failure state
        safe = re.sub(
            r"\b(error|failed|disabled|off|blocked|critical|vulnerable|open network)\b",
            r"<span style='color:#ff6b7a;font-weight:700;'>\1</span>",
            safe,
            flags=re.IGNORECASE,
        )
        return safe

    def _section_html(self, body: str) -> str:
        display = html_mod.escape(body).rstrip(":")
        is_major = bool(re.match(r"^\[\d+\]", body.strip())) or "ghostlink" in body.lower()
        if is_major:
            margin = "16px 0 6px 0"
            pad = "10px 16px"
            bg = "qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0a2442, stop:1 #09192d)"
            border = "1px solid #245489"
            left = "5px solid #60a5fa"
            size = "9.5pt"
        else:
            margin = "10px 0 4px 0"
            pad = "7px 12px"
            bg = "#081a2f"
            border = "1px solid #17395f"
            left = "3px solid #2e88d8"
            size = "9pt"
        return (
            "<div style='"
            f"margin:{margin};"
            f"padding:{pad};"
            f"background:{bg};"
            f"border:{border};"
            f"border-left:{left};"
            "border-radius:7px;"
            "'>"
            "<span style='"
            "color:#dbeafe;"
            "font-family:Consolas,monospace;"
            f"font-size:{size};"
            "font-weight:800;"
            "letter-spacing:1.2px;"
            "text-transform:uppercase;"
            f"'>{display}</span>"
            "</div>"
        )

    @staticmethod
    def _split_table_cols(body: str) -> list[str]:
        cols = [c.strip() for c in re.split(r"\s{2,}|\t+", body.strip()) if c.strip()]
        return cols if cols else [body.strip()]

    def _looks_like_table_header(self, body: str) -> bool:
        cols = self._split_table_cols(body)
        if len(cols) < 2:
            return False
        if any(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9A-Fa-f]{2}:", c) for c in cols):
            return False
        alpha_ratio = sum(1 for c in cols if re.search(r"[A-Za-z]", c)) / max(len(cols), 1)
        return alpha_ratio >= 0.8

    def _kv_html(self, body: str) -> str:
        if "\t" not in body:
            return self._tagged_card_html("LOG", body)
        label, value = body.split("\t", 1)
        safe_label = html_mod.escape(label.strip())
        raw_value = value.strip()
        metric_match = re.match(r"^([#=Ã¢â€“Ë†Ã¢â€“â€œÃ¢â€“â€™Ã¢â€“â€˜Ã¢â€“ÂÃ¢â€“â€šÃ¢â€“Æ’Ã¢â€“â€žÃ¢â€“â€¦Ã¢â€“â€ Ã¢â€“â€¡|:\-\. ]{1,})\s+(\d+)$", raw_value)
        if metric_match:
            bar_raw = metric_match.group(1)
            metric_val = metric_match.group(2)
            bar_len = len(re.sub(r"\s+", "", bar_raw))
            bar_len = max(4, min(bar_len, 42))
            slots = 24
            # Non-linear scaling keeps very small values visually present (e.g. "1")
            fill_slots = max(3, min(slots, round((bar_len / 42) ** 0.6 * slots)))
            # Smooth cyan-blue segmented bar; keep Qt rich-text safe by using inline spans.
            def _seg_color(i: int) -> str:
                t = i / max(fill_slots - 1, 1)
                r = int(103 + (56 - 103) * t)
                g = int(232 + (189 - 232) * t)
                b = int(249 + (248 - 249) * t)
                return f"#{r:02x}{g:02x}{b:02x}"

            fill = "".join(
                f"<span style='color:{_seg_color(i)};'>Ã¢â€“Â°</span>"
                for i in range(fill_slots)
            )
            empty = "<span style='color:#224665;'>Ã¢â€“Â±</span>" * (slots - fill_slots)
            pct = int(round((fill_slots / slots) * 100))
            safe_value = (
                "<span style='display:inline-block; min-width:300px; padding:2px 8px; "
                "background:#07182c; border:1px solid #17456e; border-radius:7px;'>"
                f"{fill}{empty}"
                "</span> "
                "<span style='display:inline-block; min-width:28px; text-align:center; "
                "padding:1px 6px; background:#2b1f07; border:1px solid #7a5a1a; border-radius:6px; "
                "color:#fbbf24; font-weight:800;'>"
                f"{metric_val}"
                "</span> "
                "<span style='display:inline-block; min-width:40px; text-align:center; "
                "padding:1px 6px; background:#102236; border:1px solid #2a5f8f; border-radius:6px; "
                "color:#8bd1ff; font-weight:700;'>"
                f"{pct}%"
                "</span>"
            )
        else:
            safe_value = self._hl_semantic(self._hl_addresses(html_mod.escape(raw_value)))
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='"
            "margin:3px 0;"
            "background:#061a2f;"
            "border:1px solid #113253;"
            "border-left:3px solid #1d8ee0;"
            "border-radius:5px;"
            "'>"
            "<tr>"
            "<td width='250' style='padding:6px 10px; color:#8dbce1; font-family:Consolas,monospace; font-size:8.5pt; font-weight:700;'>"
            f"{safe_label}"
            "</td>"
            "<td style='padding:6px 10px; color:#d6ecff; font-family:Consolas,monospace; font-size:9.5pt; word-break:break-word;'>"
            f"{safe_value}"
            "</td>"
            "</tr>"
            "</table>"
        )

    def _table_header_html(self, body: str) -> str:
        cols = self._split_table_cols(body)
        cells = "".join(
            "<th style='"
            "padding:7px 10px;"
            "text-align:left;"
            "color:#7eb5e6;"
            "font-family:Consolas,monospace;"
            "font-size:8pt;"
            "font-weight:800;"
            "letter-spacing:0.8px;"
            "text-transform:uppercase;"
            "border-bottom:1px solid #2e6ba7;"
            "'>"
            f"{html_mod.escape(col)}"
            "</th>"
            for col in cols
        )
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='"
            "margin:6px 0 0 0;"
            "border-collapse:collapse;"
            "border:1px solid #12385e;"
            "border-radius:6px;"
            "overflow:hidden;"
            "background:#091b31;"
            "'>"
            "<thead><tr style='background:#0b2240;'>"
            f"{cells}"
            "</tr></thead><tbody>"
        )

    def _meter_html(self, body: str) -> str:
        safe = html_mod.escape(body)
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='"
            "margin:4px 0 8px 0;"
            "background:#06111f;"
            "border:1px solid #143a62;"
            "border-left:3px solid #38bdf8;"
            "border-radius:6px;"
            "'>"
            "<tr>"
            "<td width='64' style='padding:5px 8px; text-align:center; color:#7ec3f6; font-family:Consolas,monospace; font-size:7pt; font-weight:900; letter-spacing:1px; border-right:1px solid #1f4f7f;'>METER</td>"
            "<td style='padding:6px 10px; color:#cde8ff; font-family:Consolas,monospace; font-size:8.5pt; white-space:pre;'>"
            f"{safe}"
            "</td>"
            "</tr>"
            "</table>"
        )

    def _table_row_html(self, body: str, idx: int, col_count: int = 0) -> str:
        cols = self._split_table_cols(body)
        target_cols = max(col_count, len(cols))
        if len(cols) < target_cols:
            cols.extend([""] * (target_cols - len(cols)))
        bg            = "#071627" if idx % 2 == 0 else "#0a1e35"
        border_accent = "#0d3258" if idx % 2 == 0 else "#102c4a"
        cells = "".join(
            "<td style='"
            "padding:6px 10px;"
            "color:#b8ddf8;"
            "font-family:Consolas,monospace;"
            "font-size:9pt;"
            "border-bottom:1px solid #0d2d4a;"
            "white-space:nowrap;"
            "'>"
            f"{self._hl_addresses(html_mod.escape(col))}"
            "</td>"
            for col in cols
        )
        return (
            f"<tr style='background:{bg}; border-left:2px solid {border_accent};'>"
            f"{cells}"
            f"</tr>"
        )

    def _tagged_card_html(self, tag: str, body: str) -> str:
        bg, accent, badge_text, badge_bg = self._TAG_CFG.get(tag, self._TAG_CFG["LOG"])
        is_placeholder = (body == "Ã¢â‚¬â€")
        safe = html_mod.escape(body)
        if not is_placeholder:
            safe = self._hl_semantic(self._hl_addresses(safe))
        body_color = "#597894" if is_placeholder else "#d9eeff"
        body_size  = "8.5pt"   if is_placeholder else "9.5pt"
        body_style = "font-style:italic;" if is_placeholder else ""

        # Update pill counts
        tag_lower = tag.lower()
        if tag_lower in self._pill_counts and not is_placeholder:
            self._pill_counts[tag_lower] += 1
            count = self._pill_counts[tag_lower]
            pill_map = {
                "info":  self._recon_pill_info,
                "data":  self._recon_pill_data,
                "warn":  self._recon_pill_warn,
                "error": self._recon_pill_error,
            }
            if tag_lower in pill_map:
                pill_map[tag_lower].setText(f"{tag.capitalize()} {count}")

        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='"
            f"margin:3px 0;"
            f"background:{bg};"
            f"border:1px solid #0d2d4e;"
            f"border-left:3px solid {accent};"
            f"border-radius:5px;"
            f"'>"
            f"<tr>"
            f"<td width='64' style='"
            f"padding:5px 8px;"
            f"background:{badge_bg};"
            f"color:{badge_text};"
            f"font-family:Consolas,monospace;"
            f"font-size:7pt;"
            f"font-weight:900;"
            f"letter-spacing:1px;"
            f"text-align:center;"
            f"border-right:1px solid {accent}33;"
            f"'>{tag}</td>"
            f"<td style='"
            f"padding:6px 10px;"
            f"color:{body_color};"
            f"font-family:Consolas,monospace;"
            f"font-size:{body_size};"
            f"line-height:1.72;"
            f"word-break:break-word;"
            f"{body_style}"
            f"'>{safe}</td>"
            f"</tr>"
            f"</table>"
        )

    def _render_recon_output(self, raw: str) -> None:
        cleaned = self._strip_ansi(raw)
        lines   = self._split_into_lines(cleaned)
        if not lines:
            return

        parsed_records: list[dict] = []
        table_row_i = 0
        in_table    = False
        table_cols  = 0

        for line in lines:
            tag, body = self._classify_line(line)

            entering_table = (tag == "TABLE" and not in_table)
            leaving_table  = (tag != "TABLE" and in_table)

            if entering_table:
                in_table    = True
                table_row_i = 0
                table_cols = 0
            elif leaving_table:
                in_table = False
                table_row_i = 0
                table_cols = 0

            if tag == "DIVIDER":
                parsed_records.append({"tag": "DIVIDER", "kind": "divider", "content": body})

            elif tag == "SECTION":
                parsed_records.append({"tag": "SECTION", "kind": "section", "content": body})

            elif tag == "KV":
                label, value = body.split("\t", 1) if "\t" in body else (body, "")
                parsed_records.append({
                    "tag": "DATA",
                    "kind": "kv",
                    "label": label.strip(),
                    "value": value.strip(),
                    "content": f"{label.strip()}: {value.strip()}",
                })

            elif tag == "METER":
                parsed_records.append({"tag": "DATA", "kind": "meter", "content": body})

            elif tag == "TABLE":
                cols = self._split_table_cols(body)
                is_header = entering_table and self._looks_like_table_header(body)
                if is_header:
                    table_cols = len(cols)
                    parsed_records.append({"tag": "DATA", "kind": "table_header", "columns": cols, "content": " | ".join(cols)})
                else:
                    parsed_records.append({"tag": "DATA", "kind": "table_row", "index": table_row_i, "col_count": table_cols, "columns": cols, "content": " | ".join(cols)})
                    table_row_i += 1

            else:
                parsed_records.append({"tag": tag, "kind": "line", "content": body})

        self._recon_records.extend(parsed_records)
        self._refresh_recon_view()

    def _append_recon_card(self, tag: str, body: str, color: str) -> None:
        self._recon_records.append({"tag": tag, "kind": "line", "content": body})
        self._refresh_recon_view()

    def _refresh_recon_view(self):
        self._reset_recon_metrics()
        self._update_recon_summary()
        self.recon_output.clear()
        if not self._recon_records:
            return

        parts: list[str] = []
        prev_kind = None
        in_table = False

        for rec in self._recon_records:
            if not self._passes_recon_filter(rec):
                continue

            kind = rec.get("kind", "")
            tag = str(rec.get("tag", "LOG")).upper()
            content = str(rec.get("content", ""))

            if self._recon_collapse_sections and kind not in ("section", "divider"):
                if tag not in ("WARN", "ERROR"):
                    continue

            if kind == "divider":
                if in_table:
                    parts.append("</tbody></table>")
                    in_table = False
                parts.append(self._divider_html())

            elif kind == "section":
                if in_table:
                    parts.append("</tbody></table>")
                    in_table = False
                if prev_kind not in (None, "section", "divider"):
                    parts.append("<div style='height:4px;'></div>")
                parts.append(self._section_html(content))

            elif kind == "kv":
                if in_table:
                    parts.append("</tbody></table>")
                    in_table = False
                label = str(rec.get("label", "")).strip()
                value = str(rec.get("value", "")).strip()
                parts.append(self._kv_html(f"{label}\t{value}"))

            elif kind == "meter":
                if in_table:
                    parts.append("</tbody></table>")
                    in_table = False
                parts.append(self._meter_html(content))

            elif kind == "table_header":
                if in_table:
                    parts.append("</tbody></table>")
                parts.append(self._table_header_html(content))
                in_table = True

            elif kind == "table_row":
                if not in_table:
                    parts.append(
                        "<table width='100%' cellspacing='0' cellpadding='0' style='"
                        "margin:6px 0 0 0;"
                        "border-collapse:collapse;"
                        "border:1px solid #12385e;"
                        "border-radius:6px;"
                        "overflow:hidden;"
                        "background:#091b31;"
                        "'><tbody>"
                    )
                    in_table = True
                idx = int(rec.get("index", 0))
                col_count = int(rec.get("col_count", 0))
                cols = rec.get("columns", [])
                if isinstance(cols, list) and cols:
                    row_text = "  ".join(str(c) for c in cols)
                else:
                    row_text = content
                parts.append(self._table_row_html(row_text, idx, col_count))

            else:
                if in_table:
                    parts.append("</tbody></table>")
                    in_table = False
                parts.append(self._tagged_card_html(tag, content))

            prev_kind = kind

        if in_table:
            parts.append("</tbody></table>")

        if parts:
            self.recon_output.insertHtml("\n".join(parts))
            self.recon_output.insertHtml("<br>")
            if self._autoscroll_check.isChecked():
                self.recon_output.moveCursor(QTextCursor.End)

    # Ã¢â€â‚¬Ã¢â€â‚¬ Legacy compat stubs Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_F:
            if hasattr(self, "scan_search_edit"):
                self.tabs.setCurrentIndex(0)
                self.scan_search_edit.setFocus()
                self.scan_search_edit.selectAll()
                event.accept()
                return
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if self.tabs.currentIndex() == 0 and hasattr(self, "scan_table") and self.scan_table.hasFocus():
                if self.select_btn.isEnabled():
                    self.select_target()
                    event.accept()
                    return
        super().keyPressEvent(event)
    def _normalize_recon_stream(self, text: str) -> str:   return text
    def _parse_recon_line(self, line: str):                 return self._classify_line(line)
    def _is_divider_line(self, text: str) -> bool:         return len(text) >= 6 and bool(re.fullmatch(r"[=\-_.\s]{6,}", text.strip()))
    def _is_section_title(self, text: str) -> bool:        tag, _ = self._classify_line(text); return tag == "SECTION"

