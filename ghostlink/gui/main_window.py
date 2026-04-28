import sys
import os
import ctypes
import io
import re
import html as html_mod
import csv
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QSpinBox, QLineEdit, QCheckBox,
    QTextEdit, QProgressBar, QGroupBox, QFormLayout, QMessageBox,
    QFileDialog, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSplitter, QScrollArea, QApplication,
    QDialog, QMenu,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QTextCursor, QIcon

from ghostlink.engine.profiles import PROFILES
from ghostlink.core.constants import (
    DEFAULT_MINLEN, DEFAULT_MAXLEN, DEFAULT_THREADS, DEFAULT_TIMEOUT,
)
from .workers import ScanWorker, AttackWorker, ReconWorker
from ghostlink.network.scanner import WiFiScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _calc_candidates(charset: str, minlen: int, maxlen: int) -> int:
    """Total brute-force candidates for the given charset and length range."""
    base = len(charset)
    if base == 0:
        return 0
    return sum(base ** n for n in range(max(1, minlen), maxlen + 1))


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"


# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GHOSTLINK")
        self.resize(1280, 860)
        self.setMinimumSize(1080, 720)
        self.setFont(QFont("Segoe UI", 10))
        self.setWindowIcon(QIcon("ghostlink.ico"))

        # ── State ──────────────────────────────────────────────────────────
        self.scan_results: list = []
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
        self._scan_seen_at: dict = {}
        self._scan_new_bssids: set = set()
        self._scan_cycle = 0
        self._scan_prev_by_bssid: dict = {}
        self._pulse_new_on = False
        self._scan_density_mode = "comfortable"
        self._scan_compare_enabled = True
        self._scan_pulse_timer = QTimer(self)
        self._scan_pulse_timer.timeout.connect(self._tick_new_pulse)
        self._scan_pulse_timer.start(700)
        self._recon_records: list[dict] = []
        self._recon_filter_mode = "all"
        self._recon_collapse_sections = False
        self.filtered_scan_results: list = []
        self.active_scan_filter = "all"

        # ── Build UI ───────────────────────────────────────────────────────
        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self._create_chrome_bar())

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(False)
        self.tabs.setElideMode(Qt.ElideNone)
        shell_layout.addWidget(self.tabs)

        self.setCentralWidget(shell)

        self.create_scan_tab()
        self.create_attack_tab()
        self.create_progress_tab()
        self.create_recon_tab()

        self.apply_theme()
        self.statusBar().showMessage("System ready")

        # Deferred scan hint (after window shown)
        self._scan_hint_shown = False
        QTimer.singleShot(400, self._maybe_show_scan_hints)

    # ──────────────────────────────────────────────────────────────────────
    # Chrome bar
    # ──────────────────────────────────────────────────────────────────────

    def _create_chrome_bar(self) -> QWidget:
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

        layout.addWidget(dot_red)
        layout.addWidget(dot_yellow)
        layout.addWidget(dot_green)
        layout.addSpacing(10)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(version)
        return bar

    def _make_tab_header(self, title: str, subtitle: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(2)
        t = QLabel(title);    t.setProperty("role", "title")
        s = QLabel(subtitle); s.setProperty("role", "subtitle")
        layout.addWidget(t)
        layout.addWidget(s)
        return container

    # ──────────────────────────────────────────────────────────────────────
    # Theme
    # ──────────────────────────────────────────────────────────────────────

    def apply_theme(self):
        self.setStyleSheet("""
        QWidget {
            color: #d4d4d8;
            font-family: 'Inter', 'Segoe UI', sans-serif;
            font-size: 10pt;
        }
        QMainWindow { background-color: #09090b; }
        QFrame[role="chrome"] { background: #121214; border-bottom: 1px solid #27272a; }
        QLabel[role="dot_red"]    { color: #ef4444; font-size: 12pt; }
        QLabel[role="dot_yellow"] { color: #f59e0b; font-size: 12pt; }
        QLabel[role="dot_green"]  { color: #22c55e; font-size: 12pt; }
        QLabel[role="chrome_title"] { color: #f4f4f5; font-weight: 700; letter-spacing: 3px; }
        QLabel[role="chrome_meta"]  { color: #a1a1aa; font-size: 9pt; }
        QStatusBar { background: #2563eb; border-top: none; color: #ffffff; }
        QTabWidget::pane {
            background: #09090b; border: 1px solid #27272a; border-top: none;
            border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;
        }
        QTabBar::tab {
            background: #18181b; color: #a1a1aa; border: 1px solid #27272a;
            border-top-left-radius: 8px; border-top-right-radius: 8px;
            padding: 10px 20px; margin-right: 4px; font-weight: 600;
        }
        QTabBar::tab:selected { background: #09090b; color: #f4f4f5; border-bottom: none; border-top: 3px solid #3b82f6; }
        QTabBar::tab:hover:!selected { background: #27272a; color: #d4d4d8; }
        QLabel[role="title"]    { font-size: 22px; font-weight: 700; color: #ffffff; }
        QLabel[role="subtitle"] { color: #a1a1aa; font-size: 10pt; }
        QLabel[role="meta"]     { color: #a1a1aa; font-size: 9pt; }
        QLabel[role="pill"] {
            background: #27272a; border: 1px solid #3f3f46; border-radius: 6px;
            color: #d4d4d8; font-weight: 600; padding: 6px 12px;
        }
        QLabel[role="target_left"]  { color: #3b82f6; font-size: 10pt; font-weight: 700; }
        QLabel[role="target_right"] { color: #f4f4f5; font-size: 10pt; font-weight: 600; }
        QFrame[role="target_strip"] { background: #18181b; border: 1px solid #27272a; border-radius: 8px; }
        QFrame[role="target_strip_locked"] { background: #0a1f0f; border: 1px solid #166534; border-radius: 8px; }
        QLabel[role="metric"] {
            background: #18181b; border: 1px solid #27272a; border-radius: 8px;
            color: #d4d4d8; font-weight: 600; padding: 8px 14px;
        }
        QLabel[role="stat_card"] {
            background: #18181b; border: 1px solid #27272a; border-radius: 8px;
            font-weight: 700; padding: 10px 14px;
        }
        QGroupBox {
            color: #e0e0e0; background: #18181b; border: 1px solid #27272a;
            border-radius: 8px; margin-top: 12px; padding-top: 12px; font-weight: 600;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #3b82f6; }
        QTableWidget, QTextEdit {
            background: #121214; border: 1px solid #27272a; border-radius: 8px;
            color: #d4d4d8; gridline-color: transparent;
            selection-background-color: #1e3a8a; selection-color: #ffffff;
        }
        QHeaderView::section {
            background: #18181b; color: #a1a1aa; border: none;
            border-bottom: 2px solid #27272a; padding: 10px 8px; font-weight: 700;
        }
        QTableWidget[role="scan_table"] {
            background: #121214; border: 1px solid #27272a; border-radius: 8px;
            gridline-color: #27272a; alternate-background-color: #18181b;
            selection-background-color: #1e3a8a; selection-color: #ffffff; padding: 2px;
        }
        QTableWidget[role="scan_table"]::item { border-bottom: 1px solid #27272a; padding: 8px 8px; }
        QTableWidget[role="scan_table"]::item:selected { border-left: 4px solid #3b82f6; background: #1e3a8a; }
        QTableWidget[role="scan_table"] QHeaderView::section {
            background: #121214; color: #a1a1aa; border: none;
            border-bottom: 2px solid #27272a; padding: 12px 10px;
            font-weight: 700; text-transform: uppercase; font-size: 9pt;
        }
        QLineEdit, QSpinBox, QComboBox {
            background: #18181b; border: 1px solid #3f3f46; border-radius: 6px;
            color: #d4d4d8; padding: 8px 12px; min-height: 22px;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus,
        QTextEdit:focus, QTableWidget:focus { border: 1px solid #3b82f6; background: #27272a; }
        QComboBox::drop-down {
            subcontrol-origin: padding; subcontrol-position: top right;
            width: 30px; border-left: 1px solid #3f3f46; background: #27272a;
            border-top-right-radius: 6px; border-bottom-right-radius: 6px;
        }
        QComboBox::down-arrow {
            width: 0px; height: 0px; border-left: 5px solid transparent;
            border-right: 5px solid transparent; border-top: 5px solid #a1a1aa;
        }
        QComboBox::down-arrow:on { border-top: 5px solid #d4d4d8; }
        QComboBox QAbstractItemView {
            background: #18181b; border: 1px solid #3f3f46; border-radius: 6px;
            outline: 0; padding: 4px; color: #d4d4d8;
            selection-background-color: #1e3a8a; selection-color: #ffffff;
        }
        QComboBox QAbstractItemView::item { min-height: 28px; padding: 4px 8px; border-radius: 4px; }
        QComboBox QAbstractItemView::item:hover { background: #27272a; }
        QComboBox QAbstractItemView::item:selected { background: #1e3a8a; }
        QCheckBox { spacing: 8px; color: #d4d4d8; }
        QCheckBox::indicator { width: 18px; height: 18px; border-radius: 4px; border: 1px solid #71717a; background: #18181b; }
        QCheckBox::indicator:checked { background: #3b82f6; border: 1px solid #3b82f6; }
        QPushButton {
            background: #3b82f6; border: 1px solid #2563eb; color: #ffffff;
            border-radius: 6px; padding: 8px 16px; font-weight: 600; min-height: 22px;
        }
        QPushButton:hover   { background: #2563eb; border: 1px solid #1d4ed8; }
        QPushButton:pressed { background: #1d4ed8; }
        QPushButton[variant="secondary"] { background: #27272a; border: 1px solid #3f3f46; color: #d4d4d8; }
        QPushButton[variant="secondary"]:hover { background: #3f3f46; border: 1px solid #52525b; }
        QPushButton[variant="danger"]    { background: #ef4444; border: 1px solid #dc2626; color: #ffffff; }
        QPushButton[variant="danger"]:hover { background: #dc2626; border: 1px solid #b91c1c; }
        QPushButton[variant="success"]   { background: #16a34a; border: 1px solid #15803d; color: #ffffff; }
        QPushButton[variant="success"]:hover { background: #15803d; border: 1px solid #166534; }
        QPushButton[variant="critical"]  { background: #f59e0b; border: 1px solid #d97706; color: #1a0d00; font-weight: 700; }
        QPushButton[variant="critical"]:hover { background: #d97706; }
        QPushButton:disabled { background: #27272a; border: 1px solid #27272a; color: #52525b; }
        QProgressBar {
            background: #18181b; border: 1px solid #27272a; border-radius: 6px;
            text-align: center; color: #d4d4d8; min-height: 18px; font-weight: 600;
        }
        QProgressBar::chunk { border-radius: 5px; background: #3b82f6; }
        QSplitter::handle { background: #27272a; }
        QSplitter::handle:horizontal { width: 2px; }
        QSplitter::handle:vertical   { height: 2px; }
        QSplitter::handle:hover { background: #3b82f6; }
        QScrollArea { border: none; background: transparent; }
        QScrollBar:vertical { background: #09090b; width: 12px; border-radius: 6px; }
        QScrollBar::handle:vertical { background: #3f3f46; border-radius: 6px; min-height: 24px; }
        QScrollBar::handle:vertical:hover { background: #52525b; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QFrame[role="recon_running"] {
            background: #18181b; border: 1px solid #27272a; border-left: 4px solid #3b82f6; border-radius: 8px;
        }
        QFrame[role="recon_sidebar"]       { background: #18181b; border: 1px solid #27272a; border-radius: 8px; }
        QFrame[role="recon_output_frame"]  { background: #121214; border: 1px solid #27272a; border-radius: 8px; }
        QFrame[role="recon_summary"]       { background: #18181b; border: 1px solid #27272a; border-radius: 8px; }
        QLabel[role="summary_card"] {
            background: #121214; border: 1px solid #27272a; border-radius: 6px;
            color: #d4d4d8; font-size: 9pt; font-weight: 500;
            padding: 0px 12px; margin-bottom: 4px; min-height: 28px;
            qproperty-alignment: 'AlignVCenter | AlignLeft';
        }
        QPushButton[role="mod_btn"] {
            background: #0e1e35; border: 1px solid #1e3a5e; border-radius: 6px;
            color: #7ab8e8; font-size: 9pt; font-weight: 600; padding: 6px 10px;
            text-align: left;
        }
        QPushButton[role="mod_btn"]:hover   { background: #1e3a8a; border-color: #3b82f6; color: #bfdbfe; }
        QPushButton[role="mod_btn"]:pressed { background: #1e40af; }
        QPushButton[role="mod_btn_done"] {
            background: #0a2e18; border: 1px solid #166534; border-radius: 6px;
            color: #4ade80; font-size: 9pt; font-weight: 600; padding: 6px 10px;
            text-align: left;
        }
        QPushButton[role="mod_btn_error"] {
            background: #2e0a0a; border: 1px solid #7f1d1d; border-radius: 6px;
            color: #f87171; font-size: 9pt; font-weight: 600; padding: 6px 10px;
            text-align: left;
        }
        QPushButton[role="mod_btn_running"] {
            background: #0d2f56; border: 1px solid #00b8ff; border-radius: 6px;
            color: #00e5ff; font-size: 9pt; font-weight: 600; padding: 6px 10px;
            text-align: left;
        }
        QPushButton[role="run_all_btn"] {
            background: #451a03; border: 1px solid #78350f; border-radius: 8px;
            color: #fcd34d; font-size: 9pt; font-weight: 800; letter-spacing: 1px; padding: 10px 12px;
        }
        QPushButton[role="run_all_btn"]:hover { background: #78350f; border-color: #b45309; color: #fde68a; }
        QPushButton[role="toolbar_btn"] {
            background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;
            color: #94a3b8; font-size: 8pt; font-weight: 800; letter-spacing: 0.5px;
            padding: 6px 12px; min-height: 0;
        }
        QPushButton[role="toolbar_btn"]:hover { background: #1e293b; border-color: #334155; color: #cbd5e1; }
        QPushButton[role="scan_filter"] {
            background: #18181b; border: 1px solid #27272a; border-radius: 6px;
            color: #a1a1aa; font-size: 9pt; font-weight: 700; letter-spacing: 1px;
            padding: 7px 14px; min-height: 22px;
        }
        QPushButton[role="scan_filter"]:hover   { background: #27272a; border-color: #3f3f46; color: #d4d4d8; }
        QPushButton[role="scan_filter"]:checked {
            background: #1e3a8a; border: 1px solid #3b82f6; color: #93c5fd;
        }
        QPushButton[role="clear_btn"] {
            background: #1e0a0a; border: 1px solid #5a2020; border-radius: 6px;
            color: #c06060; font-size: 8pt; font-weight: 800; letter-spacing: 0.5px;
            padding: 4px 10px; min-height: 0;
        }
        QPushButton[role="clear_btn"]:hover { background: #2e1010; border-color: #8a3030; color: #e08080; }
        """)

    # ──────────────────────────────────────────────────────────────────────
    # Tab 1 — Scan & Select
    # ──────────────────────────────────────────────────────────────────────

    def create_scan_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "SCAN & SELECT")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)
        # ── Header & Stats ──────────────────────────────────────────────
        header_layout = QHBoxLayout()
        header_layout.addWidget(self._make_tab_header("Target Discovery", "Scan nearby Wi-Fi networks and select a target to attack."))
        header_layout.addStretch()
        
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        for attr, text in [
            ("scan_total_label",  "Total: 0"),
            ("scan_open_label",   "Open: 0"),
            ("scan_secure_label", "WPA2/WPA3: 0"),
            ("scan_strong_label", "Strong (>70%): 0"),
        ]:
            lbl = QLabel(text)
            lbl.setProperty("role", "stat_card")
            lbl.setAlignment(Qt.AlignCenter)
            setattr(self, attr, lbl)
            stats_layout.addWidget(lbl)
        header_layout.addLayout(stats_layout)
        layout.addLayout(header_layout)

        # ── Main Controls ───────────────────────────────────────────────
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)
        
        self.scan_btn = QPushButton("SCAN NETWORKS")
        self.scan_btn.setProperty("variant", "success")
        self.scan_btn.setMinimumHeight(32)
        self.scan_btn.setStyleSheet("font-weight: 800; padding: 0 20px; font-size: 11pt;")
        self.scan_btn.clicked.connect(self.start_scan)
        controls_layout.addWidget(self.scan_btn)
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(180)
        controls_layout.addWidget(self.interface_combo)
        
        self.refresh_iface_btn = QPushButton("REFRESH")
        self.refresh_iface_btn.setProperty("variant", "secondary")
        self.refresh_iface_btn.clicked.connect(self.refresh_interfaces)
        controls_layout.addWidget(self.refresh_iface_btn)

        self.iface_health_label = QLabel("Interface: unknown")
        self.iface_health_label.setProperty("role", "meta")
        controls_layout.addWidget(self.iface_health_label)

        controls_layout.addStretch()

        self.auto_rescan_check = QCheckBox("Auto-rescan")
        self.auto_rescan_check.toggled.connect(self.toggle_auto_rescan)
        controls_layout.addWidget(self.auto_rescan_check)
        
        self.auto_rescan_interval = QSpinBox()
        self.auto_rescan_interval.setRange(5, 300)
        self.auto_rescan_interval.setValue(20)
        self.auto_rescan_interval.setSuffix(" s")
        self.auto_rescan_interval.valueChanged.connect(self.update_auto_rescan_interval)
        controls_layout.addWidget(self.auto_rescan_interval)

        self.last_scan_label = QLabel("Last scan: never")
        self.last_scan_label.setProperty("role", "meta")
        controls_layout.addWidget(self.last_scan_label)

        layout.addLayout(controls_layout)

        # ── Search & Filters ────────────────────────────────────────────
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(8)
        
        self.scan_search_edit = QLineEdit()
        self.scan_search_edit.setPlaceholderText("Search SSID / BSSID... (Ctrl+F)")
        self.scan_search_edit.setMinimumWidth(250)
        self.scan_search_edit.textChanged.connect(self.apply_scan_filters)
        filter_layout.addWidget(self.scan_search_edit)

        self.scan_filter_buttons: dict[str, QPushButton] = {}
        for key, label in [("all", "ALL"), ("strong", "STRONG"), ("open", "OPEN"), ("secure", "WPA2/WPA3"), ("band5", "5 GHZ")]:
            btn = QPushButton(label)
            btn.setProperty("role", "scan_filter")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _checked, k=key: self.set_scan_filter(k))
            self.scan_filter_buttons[key] = btn
            filter_layout.addWidget(btn)
        self.scan_filter_buttons["all"].setChecked(True)

        filter_layout.addStretch()

        self.show_hidden_check = QCheckBox("Show hidden")
        self.show_hidden_check.toggled.connect(self.apply_scan_filters)
        filter_layout.addWidget(self.show_hidden_check)

        self.compare_check = QCheckBox("Compare scans")
        self.compare_check.setChecked(True)
        self.compare_check.toggled.connect(self.toggle_compare_scans)
        filter_layout.addWidget(self.compare_check)

        self.columns_btn = QPushButton("COLUMNS")
        self.columns_btn.setProperty("variant", "secondary")
        self.columns_btn.clicked.connect(self.open_column_menu)
        filter_layout.addWidget(self.columns_btn)

        self.filter_preset_combo = QComboBox()
        for label, data in [
            ("Preset: Custom", "custom"),
            ("Preset: Audit mode", "audit"),
            ("Preset: Open only", "open_only"),
            ("Preset: 5GHz strong", "5g_strong"),
        ]:
            self.filter_preset_combo.addItem(label, data)
        self.filter_preset_combo.currentIndexChanged.connect(self.apply_filter_preset)
        filter_layout.addWidget(self.filter_preset_combo)

        self.density_combo = QComboBox()
        self.density_combo.addItem("Comfortable", "comfortable")
        self.density_combo.addItem("Compact", "compact")
        self.density_combo.currentIndexChanged.connect(self.update_scan_density)
        filter_layout.addWidget(self.density_combo)
        
        self.debug_btn = QPushButton("DEBUG")
        self.debug_btn.setProperty("variant", "secondary")
        self.debug_btn.clicked.connect(self.debug_scanner)
        filter_layout.addWidget(self.debug_btn)

        layout.addLayout(filter_layout)

        # ── Table + side panel ──────────────────────────────────────────
        table_shell = QHBoxLayout(); table_shell.setSpacing(10)
        self.scan_table = QTableWidget(0, 9)
        self.scan_table.setProperty("role", "scan_table")
        self.scan_table.setHorizontalHeaderLabels(["SSID", "STATUS", "SIGNAL", "SECURITY", "RISK", "BAND", "CHANNEL", "CONGESTION", "BSSID / VENDOR"])
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setShowGrid(True)
        self.scan_table.setAlternatingRowColors(True)
        self.scan_table.setWordWrap(False)
        self.scan_table.verticalHeader().setDefaultSectionSize(52)
        self.scan_table.setSortingEnabled(True)
        self.scan_table.horizontalHeader().setStretchLastSection(False)
        self.scan_table.horizontalHeader().setMinimumSectionSize(70)
        for col, mode in [(0, QHeaderView.Stretch), (1, QHeaderView.Fixed), (2, QHeaderView.Fixed),
                          (3, QHeaderView.Fixed), (4, QHeaderView.Fixed), (5, QHeaderView.Fixed),
                          (6, QHeaderView.Fixed), (7, QHeaderView.Fixed), (8, QHeaderView.Stretch)]:
            self.scan_table.horizontalHeader().setSectionResizeMode(col, mode)
        for col, w in [(1, 165), (2, 155), (3, 175), (4, 110), (5, 95), (6, 80), (7, 130)]:
            self.scan_table.setColumnWidth(col, w)
        self.scan_table.itemSelectionChanged.connect(self._sync_scan_selection_state)
        self.scan_table.itemDoubleClicked.connect(self.on_scan_row_double_clicked)
        self.scan_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_table.customContextMenuRequested.connect(self.open_scan_context_menu)
        self.scan_table.setMinimumHeight(260)
        table_shell.addWidget(self.scan_table, 4)

        # Side panel
        self.scan_side_panel = QFrame()
        self.scan_side_panel.setProperty("role", "recon_summary")
        self.scan_side_panel.setMinimumWidth(250)
        side_l = QVBoxLayout(self.scan_side_panel)
        side_l.setContentsMargins(10, 10, 10, 10)
        side_l.setSpacing(8)
        QLabel("Selected Network").setProperty("role", "meta")
        hdr = QLabel("Selected Network"); hdr.setProperty("role", "meta")
        side_l.addWidget(hdr)
        for attr, text in [
            ("sel_ssid", "SSID: -"), ("sel_bssid", "BSSID: -"),
            ("sel_vendor", "Vendor: -"), ("sel_risk", "Risk: -"),
            ("sel_channel", "Channel: -"), ("sel_seen", "Last seen: -"),
        ]:
            lbl = QLabel(text); lbl.setProperty("role", "summary_card")
            setattr(self, attr, lbl)
            side_l.addWidget(lbl)
        sa = QHBoxLayout()
        self.side_set_target_btn = QPushButton("SET TARGET")
        self.side_set_target_btn.setProperty("variant", "success")
        self.side_set_target_btn.clicked.connect(self.select_target)
        self.side_copy_bssid_btn = QPushButton("COPY BSSID")
        self.side_copy_bssid_btn.setProperty("variant", "secondary")
        self.side_copy_bssid_btn.clicked.connect(self.copy_selected_bssid)
        sa.addWidget(self.side_set_target_btn)
        sa.addWidget(self.side_copy_bssid_btn)
        side_l.addLayout(sa)
        side_l.addStretch()
        table_shell.addWidget(self.scan_side_panel, 1)
        layout.addLayout(table_shell)

        # Empty state
        self.empty_state_frame = QFrame()
        self.empty_state_frame.setProperty("role", "recon_summary")
        ef = QVBoxLayout(self.empty_state_frame)
        ef.setContentsMargins(18, 14, 18, 14); ef.setSpacing(8)
        et = QLabel("No Networks Visible"); et.setStyleSheet("font-size:14px;font-weight:800;color:#e8f6ff;")
        ex = QLabel("1) Run as Administrator\n2) Ensure Wi-Fi adapter is enabled\n3) Choose correct interface")
        ex.setProperty("role", "meta")
        self.empty_retry_btn = QPushButton("RETRY SCAN")
        self.empty_retry_btn.setProperty("variant", "success")
        self.empty_retry_btn.clicked.connect(self.start_scan)
        ef.addWidget(et); ef.addWidget(ex); ef.addWidget(self.empty_retry_btn, 0, Qt.AlignLeft)
        self.empty_state_frame.hide()
        layout.addWidget(self.empty_state_frame)

        # ── Bottom action bar ────────────────────────────────────────────
        ar = QHBoxLayout(); ar.setSpacing(10)
        self.select_btn = QPushButton("SET AS TARGET"); self.select_btn.setProperty("variant", "success")
        self.select_btn.clicked.connect(self.select_target); self.select_btn.setEnabled(False)
        self.rescan_btn = QPushButton("RESCAN"); self.rescan_btn.setProperty("variant", "secondary"); self.rescan_btn.clicked.connect(self.start_scan)
        self.export_scan_btn = QPushButton("EXPORT CSV"); self.export_scan_btn.setProperty("variant", "secondary"); self.export_scan_btn.clicked.connect(self.export_scan_csv)
        self.export_scan_json_btn = QPushButton("EXPORT JSON"); self.export_scan_json_btn.setProperty("variant", "secondary"); self.export_scan_json_btn.clicked.connect(self.export_scan_json)
        self.copy_scan_btn = QPushButton("COPY TABLE"); self.copy_scan_btn.setProperty("variant", "secondary"); self.copy_scan_btn.clicked.connect(self.copy_scan_results)
        for w in [self.select_btn, self.rescan_btn, self.export_scan_btn, self.export_scan_json_btn, self.copy_scan_btn]:
            ar.addWidget(w)
        self.scan_footer_stats = QLabel("Delta: +0 / -0 / ~0"); self.scan_footer_stats.setProperty("role", "meta")
        ar.addWidget(self.scan_footer_stats)
        ar.addStretch()
        self.scan_selection_label = QLabel("Selected: none"); self.scan_selection_label.setProperty("role", "meta")
        ar.addWidget(self.scan_selection_label)
        layout.addLayout(ar)

        # ── Target strip ─────────────────────────────────────────────────
        self.target_strip = QFrame()
        self.target_strip.setProperty("role", "target_strip")
        sl = QHBoxLayout(self.target_strip); sl.setContentsMargins(12, 10, 12, 10)
        self.target_state_left  = QLabel("○   NO TARGET"); self.target_state_left.setProperty("role", "target_left")
        self.target_state_right = QLabel("None");          self.target_state_right.setProperty("role", "target_right")
        sl.addWidget(self.target_state_left); sl.addStretch(); sl.addWidget(self.target_state_right)
        layout.addWidget(self.target_strip)

        # Init
        self.refresh_interfaces()
        self._sync_scan_selection_state()

    # ── Cell widgets ───────────────────────────────────────────────────────

    def _chip_widget(self, text: str, fg: str, bg: str) -> QWidget:
        chip = QLabel(text)
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(
            f"QLabel{{color:{fg};background:{bg};border-radius:4px;"
            "padding:3px 8px;font-size:8pt;font-weight:700;}}"
        )
        holder = QWidget()
        lay = QHBoxLayout(holder)
        lay.setContentsMargins(8, 3, 8, 3)
        lay.addWidget(chip)
        return holder

    def _security_item(self, security: str) -> QTableWidgetItem:
        sec = security.upper()
        if "WPA3" in sec:   label, rank = "WPA3", 4
        elif "WPA2" in sec: label, rank = "WPA2", 3
        elif "OPEN" in sec: label, rank = "OPEN", 1
        else:               label, rank = sec or "UNKNOWN", 2
        item = QTableWidgetItem(label)
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, rank)
        return item

    def _security_cell_widget(self, security: str) -> QWidget:
        sec = (security or "Unknown").upper()
        if "WPA3" in sec:   text, fg, bg = "WPA3 SECURE", "#4ade80", "#0a2e18"
        elif "WPA2" in sec: text, fg, bg = "WPA2 SECURE", "#4ade80", "#0a2e18"
        elif "OPEN" in sec: text, fg, bg = "OPEN  RISK",  "#f87171", "#2e0a0a"
        else:               text, fg, bg = sec,           "#d4d4d8", "#2d2d2d"
        return self._chip_widget(f"🔒 {text}" if "SECURE" in text else f"⚠ {text}", fg, bg)

    def _status_cell_widget(self, status: str) -> QWidget:
        up = (status or "").upper()
        if up.startswith("NEW"):
            fg, bg = ("#22c55e" if self._pulse_new_on else "#3b82f6"), ("#14532d" if self._pulse_new_on else "#1e3a8a")
        else:
            fg, bg = "#a1a1aa", "#27272a"
        return self._chip_widget(status, fg, bg)

    def _risk_cell_widget(self, risk: str) -> QWidget:
        r = (risk or "").upper()
        if r == "HIGH": return self._chip_widget("● HIGH", "#ef4444", "#450a0a")
        if r == "MED":  return self._chip_widget("● MED",  "#f59e0b", "#451a03")
        return self._chip_widget("● LOW", "#22c55e", "#052e16")

    def _congestion_cell_widget(self, congestion: str) -> QWidget:
        c = (congestion or "").upper()
        if c == "CROWDED": return self._chip_widget("CROWDED", "#ef4444", "#450a0a")
        if c == "BUSY":    return self._chip_widget("BUSY",    "#f59e0b", "#451a03")
        return self._chip_widget("CLEAR", "#22c55e", "#052e16")

    def _signal_item(self, signal: int) -> QTableWidgetItem:
        signal = max(0, min(100, int(signal)))
        item = QTableWidgetItem(f"{signal:03d}%")
        item.setTextAlignment(Qt.AlignCenter)
        item.setData(Qt.UserRole, signal)
        return item

    def _signal_cell_widget(self, signal: int) -> QWidget:
        signal = max(0, min(100, int(signal)))
        if signal >= 80:   tone = ("#4ade80", "#052e16", "EXCELLENT")
        elif signal >= 60: tone = ("#60a5fa", "#0c2340", "STRONG")
        elif signal >= 40: tone = ("#fbbf24", "#2d1f06", "FAIR")
        else:              tone = ("#f87171", "#2e0a0a", "WEAK")
        color, bg, tier = tone

        root = QWidget()
        rl = QHBoxLayout(root)
        rl.setContentsMargins(10, 4, 10, 4)
        rl.setSpacing(8)

        # Bar
        track = QFrame()
        track.setFixedHeight(8)
        track.setMinimumWidth(100)
        track.setMaximumWidth(100)
        track.setStyleSheet("QFrame{background:#2d2d2d;border-radius:4px;}")
        fill = QFrame(track)
        fill_w = max(6, int((signal / 100) * 98))
        fill.setGeometry(1, 1, fill_w, 6)
        fill.setStyleSheet(f"QFrame{{background:{color};border-radius:3px;}}")

        pct = QLabel(f"{signal}%")
        pct.setStyleSheet(f"QLabel{{color:{color};font-weight:700;font-size:9pt;}}")
        pct.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)

        chip = QLabel(tier)
        chip.setStyleSheet(
            f"QLabel{{background:{bg};border-radius:4px;color:{color};"
            "font-size:7pt;font-weight:800;padding:1px 6px;letter-spacing:0.5px;}}"
        )
        chip.setMinimumWidth(68)
        chip.setAlignment(Qt.AlignCenter)

        rl.addWidget(track)
        rl.addWidget(pct)
        rl.addWidget(chip)
        rl.addStretch()
        return root

    # ── Scan logic ─────────────────────────────────────────────────────────

    def _set_scan_placeholder(self, text: str):
        self.scan_table.setRowCount(1)
        for c in range(9):
            item = QTableWidgetItem(text if c == 0 else "")
            item.setTextAlignment(Qt.AlignCenter if c else (Qt.AlignVCenter | Qt.AlignLeft))
            self.scan_table.setItem(0, c, item)
        self.select_btn.setEnabled(False)
        self.scan_selection_label.setText("Selected: none")

    def _tick_new_pulse(self):
        self._pulse_new_on = not self._pulse_new_on
        if not hasattr(self, "scan_table"):
            return
        for row in range(self.scan_table.rowCount()):
            item = self.scan_table.item(row, 1)
            if item and item.text().upper().startswith("NEW"):
                self.scan_table.setCellWidget(row, 1, self._status_cell_widget(item.text()))

    def _channel_to_band(self, channel: int) -> str:
        if channel >= 36: return "5 GHz"
        if 1 <= channel <= 14: return "2.4 GHz"
        return "Unknown"

    def _vendor_from_bssid(self, bssid: str) -> str:
        oui = (bssid or "").upper().replace("-", ":")
        if len(oui) < 8:
            return "Unknown"
        vendors = {
            "00:1A:11": "Cisco",   "00:26:5A": "Apple",   "3C:84:6A": "TP-Link",
            "D8:0D:17": "Huawei",  "F4:F2:6D": "Samsung", "FC:FB:FB": "Google",
            "B8:27:EB": "RPi",     "9C:3D:CF": "Xiaomi",  "50:C7:BF": "TP-Link",
            "EC:08:6B": "TP-Link", "18:D6:C7": "Apple",   "AC:37:43": "HTC",
        }
        return vendors.get(oui[:8], "Unknown")

    def _risk_label(self, signal: int, security: str) -> str:
        sec = (security or "").upper()
        score = 0
        if "OPEN" in sec:   score += 2
        elif "WPA2" in sec: score += 1
        if signal >= 70:    score += 1
        if score >= 3: return "HIGH"
        if score == 2: return "MED"
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

    def _congestion_map(self, networks) -> dict:
        counts: dict[int, int] = {}
        for net in networks:
            ch = int(net.channel or 0)
            if ch > 0:
                counts[ch] = counts.get(ch, 0) + 1
        return {ch: ("Crowded" if c >= 4 else "Busy" if c >= 2 else "Clear") for ch, c in counts.items()}

    def set_scan_filter(self, filter_key: str):
        self.active_scan_filter = filter_key
        for key, btn in self.scan_filter_buttons.items():
            btn.setChecked(key == filter_key)
        self.apply_scan_filters()

    def apply_scan_filters(self):
        query = self.scan_search_edit.text().strip().lower() if hasattr(self, "scan_search_edit") else ""
        filtered = []
        for net in self.scan_results:
            sec  = (net.security or "").upper()
            band = self._channel_to_band(int(net.channel or 0))
            if self.active_scan_filter == "strong" and int(net.signal or 0) <= 70: continue
            if self.active_scan_filter == "open"   and "OPEN" not in sec:           continue
            if self.active_scan_filter == "secure" and "WPA2" not in sec and "WPA3" not in sec: continue
            if self.active_scan_filter == "band5"  and band != "5 GHz":             continue
            if not self.show_hidden_check.isChecked() and (net.hidden or not (net.ssid or "").strip()): continue
            if query and query not in (net.ssid or "").lower() and query not in (net.bssid or "").lower(): continue
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

    def _sync_scan_selection_state(self):
        row = self.scan_table.currentRow() if hasattr(self, "scan_table") else -1
        net = self._network_from_row(row)
        valid = net is not None
        self.select_btn.setEnabled(valid)
        if not valid:
            self.scan_selection_label.setText("Selected: none")
            self.sel_ssid.setText("SSID: -"); self.sel_bssid.setText("BSSID: -")
            self.sel_vendor.setText("Vendor: -"); self.sel_risk.setText("Risk: -")
            self.sel_channel.setText("Channel: -"); self.sel_seen.setText("Last seen: -")
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
        total   = len(networks)
        open_n  = sum(1 for n in networks if "OPEN" in (n.security or "").upper())
        secure  = sum(1 for n in networks if "WPA2" in (n.security or "").upper() or "WPA3" in (n.security or "").upper())
        strong  = sum(1 for n in networks if int(n.signal or 0) > 70)
        self.scan_total_label.setText(f"Total: {total}")
        self.scan_open_label.setText(f"Open: {open_n}")
        self.scan_secure_label.setText(f"WPA2/WPA3: {secure}")
        self.scan_strong_label.setText(f"Strong (>70%): {strong}")
        # Colour the open count red if any open networks
        self.scan_open_label.setStyleSheet(
            "color:#f87171;" if open_n > 0 else "color:#d4d4d8;"
        )

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

    def on_scan_row_double_clicked(self, *_args):
        if self.select_btn.isEnabled():
            self.select_target()
            self.tabs.setCurrentIndex(1)

    def open_scan_context_menu(self, pos):
        row = self.scan_table.rowAt(pos.y())
        if row < 0:
            return
        self.scan_table.selectRow(row)
        net = self._network_from_row(row)
        if not net:
            return
        menu = QMenu(self)
        set_target_action  = menu.addAction("Set as Target")
        menu.addSeparator()
        copy_ssid_action   = menu.addAction("Copy SSID")
        copy_bssid_action  = menu.addAction("Copy BSSID")
        copy_row_action    = menu.addAction("Copy Row")
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

    def copy_selected_bssid(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if not net:
            return
        QApplication.clipboard().setText(net.bssid or "")
        self.statusBar().showMessage("BSSID copied to clipboard")

    def toggle_auto_rescan(self, enabled: bool):
        self._scan_auto_enabled = bool(enabled)
        if enabled:
            self.update_auto_rescan_interval()
            self.statusBar().showMessage("Auto-rescan enabled")
        else:
            self._scan_auto_timer.stop()
            self.statusBar().showMessage("Auto-rescan disabled")

    def update_auto_rescan_interval(self):
        if self._scan_auto_enabled:
            self._scan_auto_timer.start(int(self.auto_rescan_interval.value()) * 1000)

    def _on_auto_rescan_tick(self):
        if self.scan_btn.isEnabled():
            self.start_scan()

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
            self.show_hidden_check.setChecked(True); self.set_scan_filter("all")
        elif preset == "open_only":
            self.show_hidden_check.setChecked(True); self.set_scan_filter("open")
        elif preset == "5g_strong":
            self.show_hidden_check.setChecked(False); self.set_scan_filter("band5"); self.scan_search_edit.setText("")
        elif preset == "custom":
            return
        self.apply_scan_filters()

    def open_column_menu(self):
        menu = QMenu(self)
        for col, label in [(1, "Status"), (4, "Risk"), (5, "Band"), (6, "Channel"), (7, "Congestion"), (8, "BSSID/Vendor")]:
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(not self.scan_table.isColumnHidden(col))
            action.toggled.connect(lambda checked, c=col: self.scan_table.setColumnHidden(c, not checked))
        menu.exec(self.columns_btn.mapToGlobal(self.columns_btn.rect().bottomLeft()))

    def refresh_interfaces(self):
        current = self.interface_combo.currentText().strip() if hasattr(self, "interface_combo") else ""
        if not hasattr(self, "interface_combo"):
            return
        self.interface_combo.clear()
        self.interface_combo.addItem("Auto (default)", "")
        ifaces = WiFiScanner.list_interfaces()
        for iface in ifaces:
            self.interface_combo.addItem(iface, iface)
        self.iface_health_label.setText("Interface: ready" if ifaces else "Interface: no adapter detected")
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
                "Please restart as Administrator (right-click → Run as administrator).")
            self.iface_health_label.setText("Interface: admin required")
            return
        self.statusBar().showMessage("Scanning for Wi-Fi networks...")
        self.last_scan_label.setText("Last scan: scanning...")
        self.scan_btn.setEnabled(False)
        self._set_scan_placeholder("Scanning...")
        selected_iface = self.interface_combo.currentData() if hasattr(self, "interface_combo") else None
        self.worker = ScanWorker(selected_iface or None)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_finished(self, networks):
        self._scan_cycle += 1
        previous_bssids = set(self._scan_seen_at.keys())
        self._scan_prev_by_bssid = {
            (n.bssid or "").strip().lower(): {"signal": int(n.signal or 0)}
            for n in self.scan_results if (n.bssid or "").strip()
        }
        current_bssids = {(n.bssid or "").strip().lower() for n in networks if (n.bssid or "").strip()}
        self._scan_new_bssids = current_bssids - previous_bssids
        disappeared = previous_bssids - current_bssids
        changed = sum(
            1 for n in networks
            if (n.bssid or "").strip().lower() in self._scan_prev_by_bssid
            and abs(int(n.signal or 0) - self._scan_prev_by_bssid[(n.bssid or "").strip().lower()]["signal"]) >= 3
        )
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
            self._set_scan_placeholder("No networks found. Check adapter and permissions, then click RESCAN.")
            self.statusBar().showMessage("Scan complete: no networks found")
            self.iface_health_label.setText("Interface: no networks")
        self.last_scan_label.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        self.scan_btn.setEnabled(True)

    def on_scan_error(self, message):
        self.scan_btn.setEnabled(True)
        self._set_scan_placeholder("Scan failed. Run as Admin, ensure adapter is enabled, then retry.")
        self.statusBar().showMessage("Scan failed")
        self.last_scan_label.setText("Last scan: failed")
        self.iface_health_label.setText("Interface: scan error")
        QMessageBox.critical(self, "Scan Error", message)

    def select_target(self):
        row = self.scan_table.currentRow()
        net = self._network_from_row(row)
        if net is None:
            return
        ssid = net.ssid or "<hidden>"
        self.config["ssid"]         = ssid
        self.config["interface"]    = net.interface
        self.config["target_bssid"] = net.bssid or ""
        # Update attack tab label
        self.attack_target_label.setText(
            f"  ●  {ssid}  ·  {net.security}  ·  {self._channel_to_band(int(net.channel or 0))}  ·  ch {int(net.channel or 0)}  ·  {int(net.signal or 0)}%"
        )
        self.attack_target_label.setStyleSheet(
            "QLabel{background:#0a1f0f;border:1px solid #166534;border-radius:6px;"
            "color:#4ade80;font-weight:700;padding:6px 12px;}"
        )
        # Update target strip (scan tab)
        self.target_strip.setProperty("role", "target_strip_locked")
        self.target_strip.style().unpolish(self.target_strip)
        self.target_strip.style().polish(self.target_strip)
        self.target_state_left.setText("●   TARGET LOCKED")
        self.target_state_left.setStyleSheet("color:#4ade80;font-size:10pt;font-weight:700;")
        self.target_state_right.setText(f"{ssid} — {net.security}")
        self.statusBar().showMessage(f"Target selected: {ssid}")
        # Refresh attack estimate
        self._update_attack_estimate()

    def _maybe_show_scan_hints(self):
        if self._scan_hint_shown:
            return
        self._scan_hint_shown = True
        QMessageBox.information(
            self, "Scan Tips",
            "Tips:\n• Double-click a row to set it as target.\n"
            "• Right-click for quick actions.\n"
            "• Press Ctrl+F to focus the search box.",
        )

    def export_scan_csv(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export Scan Results", "ghostlink_scan.csv", "CSV files (*.csv)")
        if not path: return
        congestion = self._congestion_map(self.filtered_scan_results)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["SSID","Status","Signal","Security","Risk","Band","Channel","Congestion","BSSID","Vendor","Interface"])
            for net in self.filtered_scan_results:
                w.writerow([
                    net.ssid or "<hidden>", self._status_label(net), int(net.signal or 0),
                    net.security or "Unknown", self._risk_label(int(net.signal or 0), net.security or ""),
                    self._channel_to_band(int(net.channel or 0)), int(net.channel or 0),
                    congestion.get(int(net.channel or 0), "-"), net.bssid or "",
                    self._vendor_from_bssid(net.bssid or ""), net.interface or "",
                ])
        self.statusBar().showMessage(f"CSV exported: {path}")

    def export_scan_json(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Export Scan", "No scan results to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export Scan Results (JSON)", "ghostlink_scan.json", "JSON files (*.json)")
        if not path: return
        congestion = self._congestion_map(self.filtered_scan_results)
        data = [{"ssid": net.ssid or "<hidden>", "bssid": net.bssid or "", "signal": int(net.signal or 0),
                 "security": net.security or "Unknown", "risk": self._risk_label(int(net.signal or 0), net.security or ""),
                 "band": self._channel_to_band(int(net.channel or 0)), "channel": int(net.channel or 0),
                 "congestion": congestion.get(int(net.channel or 0), "-"),
                 "vendor": self._vendor_from_bssid(net.bssid or ""), "status": self._status_label(net),
                 "interface": net.interface or ""} for net in self.filtered_scan_results]
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.statusBar().showMessage(f"JSON exported: {path}")

    def copy_scan_results(self):
        if not self.filtered_scan_results:
            QMessageBox.information(self, "Copy Scan", "No scan results to copy."); return
        congestion = self._congestion_map(self.filtered_scan_results)
        lines = ["SSID\tStatus\tSignal\tSecurity\tRisk\tBand\tChannel\tCongestion\tBSSID\tVendor"]
        for net in self.filtered_scan_results:
            lines.append("\t".join([
                net.ssid or "<hidden>", self._status_label(net), f"{int(net.signal or 0)}%",
                net.security or "Unknown", self._risk_label(int(net.signal or 0), net.security or ""),
                self._channel_to_band(int(net.channel or 0)), str(int(net.channel or 0)),
                congestion.get(int(net.channel or 0), "-"), net.bssid or "",
                self._vendor_from_bssid(net.bssid or ""),
            ]))
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage("Scan table copied to clipboard")

    def debug_scanner(self):
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Admin Required", "Run as Administrator."); return
        import traceback
        try:
            networks = WiFiScanner.scan()
            if networks:
                info = "\n".join(f"{n.ssid:<25} {n.signal}%  {n.security}" for n in networks)
                QMessageBox.information(self, "Scanner Diagnostics", f"Found {len(networks)} networks:\n\n{info}")
            else:
                QMessageBox.warning(self, "Scanner Diagnostics", "Scanner returned an empty list.\n\nTry: netsh wlan show networks mode=Bssid")
        except Exception as e:
            QMessageBox.critical(self, "Scanner Error", f"{e}\n\n{traceback.format_exc()}")

    # ──────────────────────────────────────────────────────────────────────
    # Tab 2 — Attack Config
    # ──────────────────────────────────────────────────────────────────────

    def create_attack_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "ATTACK CONFIG")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)
        layout.addWidget(self._make_tab_header("Attack Configuration", "Define search strategy, performance limits, and optional wordlist source."))

        # Target banner
        self.attack_target_label = QLabel("  ○  No target selected — go to SCAN & SELECT first")
        self.attack_target_label.setStyleSheet(
            "QLabel{background:#1e0a0a;border:1px solid #7f1d1d;border-radius:6px;"
            "color:#f87171;font-weight:600;padding:6px 12px;}"
        )
        layout.addWidget(self.attack_target_label)

        grid = QGridLayout(); grid.setHorizontalSpacing(12); grid.setVerticalSpacing(8)

        # Search Strategy
        pg = QGroupBox("Search Strategy"); pf = QFormLayout(pg)
        pf.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        pf.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        pf.setSpacing(10)
        self.profile_combo = QComboBox()
        for pid, prof in PROFILES.items():
            self.profile_combo.addItem(f"{prof.icon} {prof.name}", pid)
        self.profile_combo.setMaxVisibleItems(9)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        pf.addRow("Profile:", self.profile_combo)
        self.charset_edit = QLineEdit(self.config["charset"])
        self.charset_edit.setPlaceholderText("Characters to brute force")
        self.charset_edit.textChanged.connect(self._update_attack_estimate)
        pf.addRow("Charset:", self.charset_edit)
        self.minlen_spin = QSpinBox(); self.minlen_spin.setRange(1, 12); self.minlen_spin.setValue(self.config["minlen"])
        self.minlen_spin.valueChanged.connect(self._update_attack_estimate)
        pf.addRow("Min Length:", self.minlen_spin)
        self.maxlen_spin = QSpinBox(); self.maxlen_spin.setRange(1, 12); self.maxlen_spin.setValue(self.config["maxlen"])
        self.maxlen_spin.valueChanged.connect(self._update_attack_estimate)
        pf.addRow("Max Length:", self.maxlen_spin)

        # Execution Limits
        eg = QGroupBox("Execution Limits"); ef = QFormLayout(eg)
        ef.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        ef.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        ef.setSpacing(10)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1, 32); self.threads_spin.setValue(self.config["threads"])
        self.threads_spin.valueChanged.connect(self._update_attack_estimate)
        ef.addRow("Threads:", self.threads_spin)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3, 60); self.timeout_spin.setValue(self.config["timeout"])
        ef.addRow("Timeout (s):", self.timeout_spin)

        # Attack Estimate box (lives inside Execution Limits group)
        self.estimate_frame = QFrame()
        self.estimate_frame.setStyleSheet(
            "QFrame{background:#0a0a0c;border:1px solid #2a2a2e;border-radius:6px;}"
        )
        est_layout = QVBoxLayout(self.estimate_frame)
        est_layout.setContentsMargins(10, 8, 10, 8)
        est_layout.setSpacing(4)
        est_hdr = QLabel("ATTACK ESTIMATE")
        est_hdr.setStyleSheet("color:#555;font-size:8pt;font-weight:800;letter-spacing:0.08em;")
        est_layout.addWidget(est_hdr)
        self.est_candidates_lbl = QLabel("Candidates: —")
        self.est_candidates_lbl.setStyleSheet("color:#fbbf24;font-size:9pt;font-weight:600;")
        self.est_time_lbl = QLabel("Est. time: —")
        self.est_time_lbl.setStyleSheet("color:#60a5fa;font-size:9pt;")
        est_layout.addWidget(self.est_candidates_lbl)
        est_layout.addWidget(self.est_time_lbl)
        ef.addRow("", self.estimate_frame)

        # Wordlist Source
        wg = QGroupBox("Wordlist Source"); wl = QVBoxLayout(wg); wl.setSpacing(10)
        self.wordlist_edit = QTextEdit()
        self.wordlist_edit.setPlaceholderText("Paste/type passwords here (one per line), or paste a full wordlist file path.")
        self.wordlist_edit.setFixedHeight(88)
        self.wordlist_edit.textChanged.connect(self.update_wordlist_mode_hint)
        wl.addWidget(self.wordlist_edit)
        self.wordlist_mode_hint = QLabel("Mode: none (optional)")
        self.wordlist_mode_hint.setProperty("role", "meta")
        wl.addWidget(self.wordlist_mode_hint)
        wb = QHBoxLayout(); wb.setSpacing(8)
        self.browse_btn   = QPushButton("BROWSE");   self.browse_btn.setProperty("variant", "secondary");   self.browse_btn.clicked.connect(self.browse_wordlist);               wb.addWidget(self.browse_btn)
        self.template_btn = QPushButton("TEMPLATE"); self.template_btn.setProperty("variant", "secondary"); self.template_btn.clicked.connect(self.download_wordlist_template); wb.addWidget(self.template_btn)
        self.clear_wl_btn = QPushButton("CLEAR");    self.clear_wl_btn.setProperty("variant", "secondary"); self.clear_wl_btn.clicked.connect(lambda: self.wordlist_edit.clear()); wb.addWidget(self.clear_wl_btn)
        wb.addStretch(); wl.addLayout(wb)

        # Execution
        xg = QGroupBox("Execution"); xl = QVBoxLayout(xg); xl.setSpacing(10)
        self.cache_check = QCheckBox("Include previously cached passwords")
        self.cache_check.setChecked(not self.config["skip_cached"])
        xl.addWidget(self.cache_check)
        pl = QLabel("Start will switch to Progress and begin worker execution.")
        pl.setProperty("role", "meta"); xl.addWidget(pl)
        self.start_attack_btn = QPushButton("START ATTACK")
        self.start_attack_btn.setProperty("variant", "critical")
        self.start_attack_btn.clicked.connect(self.start_attack)
        xl.addWidget(self.start_attack_btn)

        grid.addWidget(pg, 0, 0); grid.addWidget(wg, 0, 1)
        grid.addWidget(eg, 1, 0); grid.addWidget(xg, 1, 1)
        grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addStretch()

        self._update_attack_estimate()

    def _update_attack_estimate(self):
        if not hasattr(self, "est_candidates_lbl"):
            return
        charset = self.charset_edit.text() if hasattr(self, "charset_edit") else self.config["charset"]
        minlen  = self.minlen_spin.value()  if hasattr(self, "minlen_spin")  else self.config["minlen"]
        maxlen  = self.maxlen_spin.value()  if hasattr(self, "maxlen_spin")  else self.config["maxlen"]
        threads = self.threads_spin.value() if hasattr(self, "threads_spin") else self.config["threads"]

        if minlen > maxlen:
            self.est_candidates_lbl.setText("Candidates: invalid range")
            self.est_time_lbl.setText("Est. time: —")
            return

        total = _calc_candidates(charset, minlen, maxlen)
        # Rough estimate: ~500 attempts/s per thread on WPA2 handshake
        speed = threads * 500
        est_s = total / speed if speed > 0 else 0
        self.est_candidates_lbl.setText(f"Candidates: {total:,}")
        self.est_time_lbl.setText(f"Est. time @ {threads}t: ~{_fmt_duration(est_s)}")

    def on_profile_changed(self):
        pid = self.profile_combo.currentData()
        if pid and pid in PROFILES:
            self.charset_edit.setText(PROFILES[pid].charset)
        self._update_attack_estimate()

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text files (*.txt *.lst *.dic);;All files (*.*)")
        if path:
            self.wordlist_edit.setPlainText(path)

    def download_wordlist_template(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Wordlist Template", "ghostlink_wordlist_template.txt", "Text files (*.txt)")
        if not path: return
        sample = [
            "# GHOSTLINK Wordlist Template", "# One candidate per line.",
            "password123", "welcome123", "letmein2026", "qwerty123",
            "admin@123", "wifi@home", "company2026", "summer2026!",
        ]
        Path(path).write_text("\n".join(sample) + "\n", encoding="utf-8")
        self.statusBar().showMessage(f"Template saved: {path}")

    def update_wordlist_mode_hint(self):
        wl_raw = self.wordlist_edit.toPlainText().strip()
        if not wl_raw:
            self.wordlist_mode_hint.setText("Mode: none (optional)"); return
        if "\n" not in wl_raw and Path(wl_raw).exists():
            self.wordlist_mode_hint.setText("Mode: file path detected"); return
        count = len([w for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")])
        self.wordlist_mode_hint.setText(f"Mode: inline list ({count} candidates)")

    def update_config_from_gui(self):
        self.config["charset"]  = self.charset_edit.text()
        self.config["minlen"]   = self.minlen_spin.value()
        self.config["maxlen"]   = self.maxlen_spin.value()
        self.config["threads"]  = self.threads_spin.value()
        self.config["timeout"]  = self.timeout_spin.value()
        wl_raw = self.wordlist_edit.toPlainText().strip()
        self.config["wordlist"] = self.config["wordlist_inline"] = None
        if wl_raw:
            if "\n" not in wl_raw and Path(wl_raw).exists():
                self.config["wordlist"] = Path(wl_raw)
            else:
                words = [w.strip() for w in re.split(r"[\r\n,]+", wl_raw) if w.strip() and not w.strip().startswith("#")]
                self.config["wordlist_inline"] = words or None
        self.config["skip_cached"] = not self.cache_check.isChecked()

    def start_attack(self):
        if not self.config.get("ssid"):
            QMessageBox.warning(self, "No Target", "Please scan and select a target first."); return
        self.update_config_from_gui()
        self.tabs.setCurrentIndex(2)
        self.progress_text.clear()
        self.progress_text.append("Starting attack…\n")
        self.progress_bar.setValue(0)
        self.progress_percent_label.setText("0%")
        self.speed_label.setText("0 pwd/s")
        self.attempts_label.setText("Attempts: 0")
        self.current_pwd_label.setText("—")
        self.eta_label.setText("ETA: —")
        self.attack_worker = AttackWorker(self.config)
        self.attack_worker.attack_started.connect(self.on_attack_started)
        self.attack_worker.progress_update.connect(self.on_progress_update)
        self.attack_worker.finished.connect(self.on_attack_finished)
        self.attack_worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.attack_worker.start()
        self.start_attack_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage(f"Attack running against {self.config['ssid']}")
        self._attack_start_time = datetime.now()

    # ──────────────────────────────────────────────────────────────────────
    # Tab 3 — Progress
    # ──────────────────────────────────────────────────────────────────────

    def create_progress_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "PROGRESS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)
        layout.addWidget(self._make_tab_header("Live Telemetry", "Track candidate processing rate, attempts, and active password candidate."))

        # ── Stat cards ──────────────────────────────────────────────────
        sc = QHBoxLayout(); sc.setSpacing(8)
        self.progress_percent_label = QLabel("0%")
        self.speed_label            = QLabel("0 pwd/s")
        self.attempts_label         = QLabel("Attempts: 0")
        self.eta_label              = QLabel("ETA: —")
        for lbl, caption in [
            (self.progress_percent_label, "Progress"),
            (self.speed_label,            "Speed"),
            (self.attempts_label,         "Attempts"),
            (self.eta_label,              "ETA"),
        ]:
            card = QFrame()
            card.setStyleSheet("QFrame{background:#18181b;border:1px solid #27272a;border-radius:8px;}")
            cl = QVBoxLayout(card); cl.setContentsMargins(12, 8, 12, 8); cl.setSpacing(2)
            cap = QLabel(caption)
            cap.setStyleSheet("color:#71717a;font-size:9pt;")
            lbl.setStyleSheet("font-size:18px;font-weight:700;color:#f4f4f5;")
            cl.addWidget(cap); cl.addWidget(lbl)
            sc.addWidget(card)
        layout.addLayout(sc)

        # ── Current candidate ────────────────────────────────────────────
        cand_frame = QFrame()
        cand_frame.setStyleSheet("QFrame{background:#0a1f0f;border:1px solid #166534;border-radius:8px;}")
        cl2 = QHBoxLayout(cand_frame); cl2.setContentsMargins(14, 10, 14, 10)
        cap2 = QLabel("CURRENT CANDIDATE")
        cap2.setStyleSheet("color:#4ade80;font-size:8pt;font-weight:800;letter-spacing:0.08em;")
        self.current_pwd_label = QLabel("—")
        self.current_pwd_label.setStyleSheet("font-family:'Consolas',monospace;font-size:14px;font-weight:700;color:#f4f4f5;letter-spacing:0.1em;")
        cl2.addWidget(cap2); cl2.addWidget(self.current_pwd_label, 1); cl2.addStretch()
        layout.addWidget(cand_frame)

        # ── Progress bar ─────────────────────────────────────────────────
        pbg = QGroupBox("Progress"); pbl = QVBoxLayout(pbg)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100); self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%  ·  %v / %m candidates")
        self.progress_bar.setMinimumHeight(28)
        pbl.addWidget(self.progress_bar)
        layout.addWidget(pbg)

        # ── Execution log ────────────────────────────────────────────────
        lg = QGroupBox("Execution Log"); ll = QVBoxLayout(lg)
        self.progress_text = QTextEdit()
        self.progress_text.setReadOnly(True)
        self.progress_text.setFont(QFont("Consolas", 10))
        self.progress_text.setPlaceholderText("Log output will appear here once the attack starts…")
        ll.addWidget(self.progress_text)
        layout.addWidget(lg, 1)

        # ── Controls ─────────────────────────────────────────────────────
        ctrl = QHBoxLayout()
        target_info = QLabel("")
        target_info.setProperty("role", "meta")
        self._progress_target_info = target_info
        ctrl.addWidget(target_info)
        ctrl.addStretch()
        self.stop_btn = QPushButton("■  STOP ATTACK")
        self.stop_btn.setProperty("variant", "danger")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.stop_btn)
        layout.addLayout(ctrl)

    def on_attack_started(self, total: int):
        self.total_combinations = total
        self.progress_bar.setRange(0, max(total, 1))
        if total > 0:
            self.progress_text.append(f"Search space: {total:,} passwords\n")
        self._progress_target_info.setText(
            f"Target: {self.config.get('ssid', '—')}  ·  {self.config.get('threads', 1)} threads"
        )

    def on_progress_update(self, current_password: str, attempts: int, speed: float):
        self.attempts_label.setText(f"Attempts: {attempts:,}")
        self.speed_label.setText(f"{speed:.0f} pwd/s")
        self.current_pwd_label.setText(current_password[:40] if current_password else "—")

        if self.total_combinations > 0:
            pct = min(int((attempts / self.total_combinations) * 100), 100)
            self.progress_bar.setValue(attempts)
            self.progress_percent_label.setText(f"{pct}%")
            remaining = max(0, self.total_combinations - attempts)
            eta_s = (remaining / speed) if speed > 0 else 0
            self.eta_label.setText(f"ETA: {_fmt_duration(eta_s)}" if eta_s > 0 else "ETA: —")

        # Log every 100 attempts to avoid flooding the QTextEdit
        if attempts % 100 == 0:
            self.progress_text.append(f"[{attempts:>8,}]  {current_password:<30}  @ {speed:.0f}/s")
            self.progress_text.moveCursor(QTextCursor.End)

    def stop_attack(self):
        if self.attack_worker:
            self.attack_worker.stop()
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopping attack worker…")

    def on_attack_finished(self, password, attempts, elapsed, verified):
        self.start_attack_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        was_stopped = bool(self.attack_worker and self.attack_worker.stop_requested)
        if password:
            self.progress_bar.setValue(self.total_combinations or 100)
            self.progress_percent_label.setText("100%")
        if password and verified:
            self.show_compromised_dialog(password, attempts, elapsed)
            self.statusBar().showMessage("Attack complete: password verified")
        elif was_stopped:
            QMessageBox.information(self, "Attack Stopped", "Attack was stopped by user.")
            self.statusBar().showMessage("Attack stopped by user")
        else:
            QMessageBox.information(self, "Attack Complete", "Password not found within search space.")
            self.statusBar().showMessage("Attack complete: password not found")

    def show_compromised_dialog(self, password: str, attempts: int, elapsed: float):
        dlg = QDialog(self)
        dlg.setWindowTitle("Target Compromised")
        dlg.setModal(True)
        dlg.setMinimumWidth(430)
        dlg.setStyleSheet("""
            QDialog { background:#060f1f; border:1px solid #1d5c8f; border-radius:14px; }
            QLabel[role="tag"] { color:#8ecfff; font-size:9pt; font-weight:700; letter-spacing:1px; }
            QLabel[role="headline"] { color:#f4fbff; font-size:19px; font-weight:900; }
            QFrame[role="card"] { background:#07152b; border:1px solid #1f507d; border-radius:10px; }
            QLabel[role="key"]   { color:#57b7ff; font-size:9pt; font-weight:700; }
            QLabel[role="value"] { color:#f2f9ff; font-size:10.5pt; font-weight:700; }
            QPushButton {
                background:#008dd8; color:#01182b; border:none; border-radius:10px;
                min-height:38px; padding:0 20px; font-size:10pt; font-weight:900;
            }
            QPushButton:hover { background:#00a0f2; }
        """)
        root = QVBoxLayout(dlg); root.setContentsMargins(18, 14, 18, 14); root.setSpacing(12)
        tag = QLabel("VERIFIED ACCESS"); tag.setProperty("role", "tag"); root.addWidget(tag)
        hl = QLabel("Password Found"); hl.setProperty("role", "headline"); root.addWidget(hl)
        sub = QLabel("Target compromised successfully."); sub.setStyleSheet("color:#8ab0cf;"); root.addWidget(sub)
        card = QFrame(); card.setProperty("role", "card")
        cl = QGridLayout(card); cl.setContentsMargins(12, 12, 12, 12); cl.setSpacing(8)
        for row, (key, value) in enumerate([
            ("SSID", str(self.config.get("ssid") or "—")),
            ("Password", str(password)),
            ("Attempts", f"{attempts:,}"),
            ("Time", f"{elapsed:.1f}s"),
        ]):
            kl = QLabel(key.upper()); kl.setProperty("role", "key")
            vl = QLabel(value);       vl.setProperty("role", "value")
            vl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cl.addWidget(kl, row, 0); cl.addWidget(vl, row, 1)
        root.addWidget(card)
        br = QHBoxLayout(); br.addStretch()
        ok_btn = QPushButton("CONTINUE"); ok_btn.clicked.connect(dlg.accept)
        br.addWidget(ok_btn); root.addLayout(br)
        dlg.exec()

    # ──────────────────────────────────────────────────────────────────────
    # Tab 4 — Recon
    # ──────────────────────────────────────────────────────────────────────

    def create_recon_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "RECON")
        root = QHBoxLayout(tab)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter)

        # ── LEFT SIDEBAR ──────────────────────────────────────────────
        sidebar_outer = QWidget()
        sidebar_outer.setProperty("role", "recon_sidebar")
        sidebar_outer.setFixedWidth(200)
        sb = QVBoxLayout(sidebar_outer)
        sb.setContentsMargins(12, 14, 8, 14)
        sb.setSpacing(0)

        title_lbl = QLabel("Recon")
        title_lbl.setStyleSheet("color:#f6fcff;font-size:16px;font-weight:800;letter-spacing:1px;")
        sub_lbl = QLabel("Network intelligence")
        sub_lbl.setStyleSheet("color:#3c8ad0;font-size:8.5pt;")
        sb.addWidget(title_lbl); sb.addWidget(sub_lbl); sb.addSpacing(14)

        mod_section = QLabel("MODULES")
        mod_section.setStyleSheet("color:#1e5a8a;font-size:7pt;font-weight:900;letter-spacing:2px;")
        sb.addWidget(mod_section); sb.addSpacing(6)

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
        self._mod_buttons: dict[str, QPushButton] = {}
        self._mod_status: dict[str, str] = {}  # "idle" | "running" | "done" | "error"
        for label, mid in modules:
            btn = QPushButton(f"  {label}")
            btn.setProperty("role", "mod_btn")
            btn.setFixedHeight(30)
            btn.clicked.connect(lambda _checked, m=mid: self._run_recon_module(m))
            sb.addWidget(btn); sb.addSpacing(3)
            self._mod_buttons[mid] = btn
            self._mod_status[mid] = "idle"

        sb.addSpacing(8)
        run_all_btn = QPushButton(">  RUN ALL MODULES")
        run_all_btn.setProperty("role", "run_all_btn")
        run_all_btn.setFixedHeight(34)
        run_all_btn.clicked.connect(lambda: self._run_recon_module("all"))
        sb.addWidget(run_all_btn)
        sb.addStretch()

        # Running indicator
        self.recon_status_strip = QFrame()
        self.recon_status_strip.setProperty("role", "recon_running")
        self.recon_status_strip.setVisible(False)
        self.recon_status_strip.setFixedHeight(52)
        ss = QVBoxLayout(self.recon_status_strip)
        ss.setContentsMargins(10, 6, 10, 6); ss.setSpacing(4)
        ss_top = QHBoxLayout(); ss_top.setSpacing(6)
        self.recon_spinner_label = QLabel("◐")
        self.recon_spinner_label.setStyleSheet("color:#00b8ff;font-size:12pt;font-weight:900;")
        self._spinner_frames = ["◐", "◓", "◑", "◒"]
        self._spinner_idx = 0
        self.recon_running_label = QLabel("Running…")
        self.recon_running_label.setStyleSheet("color:#a0d4ff;font-size:8pt;font-weight:700;")
        ss_top.addWidget(self.recon_spinner_label); ss_top.addWidget(self.recon_running_label); ss_top.addStretch()
        self.recon_pulse_bar = QProgressBar()
        self.recon_pulse_bar.setRange(0, 0); self.recon_pulse_bar.setFixedHeight(4); self.recon_pulse_bar.setTextVisible(False)
        self.recon_pulse_bar.setStyleSheet(
            "QProgressBar{background:#071930;border:none;border-radius:2px;}"
            "QProgressBar::chunk{border-radius:2px;background:#00b8ff;}"
        )
        ss.addLayout(ss_top); ss.addWidget(self.recon_pulse_bar)
        sb.addWidget(self.recon_status_strip)

        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(120)
        self._spinner_timer.timeout.connect(self._tick_spinner)

        splitter.addWidget(sidebar_outer)

        # ── RIGHT OUTPUT PANEL ─────────────────────────────────────────
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(8, 14, 14, 14)
        right_layout.setSpacing(8)

        # Toolbar
        toolbar_frame = QFrame()
        toolbar_frame.setStyleSheet("QFrame{background:#04111f;border:1px solid #0f2d47;border-radius:7px;}")
        tbl = QHBoxLayout(toolbar_frame)
        tbl.setContentsMargins(8, 5, 8, 5); tbl.setSpacing(5)

        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_all   = self._make_filter_pill("All", active=True)
        self._recon_pill_info  = self._make_filter_pill("Info 0")
        self._recon_pill_data  = self._make_filter_pill("Data 0")
        self._recon_pill_warn  = self._make_filter_pill("Warn 0")
        self._recon_pill_error = self._make_filter_pill("Error 0")
        for pill in (self._recon_pill_all, self._recon_pill_info, self._recon_pill_data, self._recon_pill_warn, self._recon_pill_error):
            tbl.addWidget(pill)
        tbl.addStretch()

        for label, slot in [("COPY", self._recon_copy_log), ("CSV", self._recon_export_csv), ("JSON", self._recon_export_json)]:
            btn = QPushButton(label); btn.setProperty("role", "toolbar_btn"); btn.setFixedHeight(26); btn.clicked.connect(slot); tbl.addWidget(btn)
        clr = QPushButton("CLEAR"); clr.setProperty("role", "clear_btn"); clr.setFixedHeight(26); clr.clicked.connect(self._recon_clear); tbl.addWidget(clr)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setStyleSheet("color:#1a3d5e;"); tbl.addWidget(sep)

        self._autoscroll_check = QCheckBox("Auto-scroll"); self._autoscroll_check.setChecked(True)
        self._autoscroll_check.setStyleSheet("font-size:8.5pt;color:#7aaac8;"); tbl.addWidget(self._autoscroll_check)

        self._severity_combo = QComboBox()
        self._severity_combo.addItems(["All", "Alerts (Warn + Error)", "Info", "Data", "Warn", "Error"])
        self._severity_combo.setFixedHeight(24)
        self._severity_combo.currentIndexChanged.connect(self._on_recon_view_changed)
        tbl.addWidget(self._severity_combo)

        self._collapse_sections_check = QCheckBox("Collapse sections")
        self._collapse_sections_check.setChecked(False)
        self._collapse_sections_check.setStyleSheet("font-size:8.5pt;color:#7aaac8;")
        self._collapse_sections_check.toggled.connect(self._on_recon_view_changed)
        tbl.addWidget(self._collapse_sections_check)
        right_layout.addWidget(toolbar_frame)

        # Summary strip
        summary_frame = QFrame(); summary_frame.setProperty("role", "recon_summary")
        sl2 = QHBoxLayout(summary_frame); sl2.setContentsMargins(8, 6, 8, 6); sl2.setSpacing(6)
        self._summary_sections = QLabel("Sections 0"); self._summary_sections.setProperty("role", "summary_card")
        self._summary_entries  = QLabel("Entries 0");  self._summary_entries.setProperty("role", "summary_card")
        self._summary_alerts   = QLabel("Alerts 0");   self._summary_alerts.setProperty("role", "summary_card")
        self._summary_view     = QLabel("View ALL");   self._summary_view.setProperty("role", "summary_card")
        for w in [self._summary_sections, self._summary_entries, self._summary_alerts, self._summary_view]:
            sl2.addWidget(w)
        sl2.addStretch()
        right_layout.addWidget(summary_frame)

        # Output QTextEdit
        output_frame = QFrame(); output_frame.setProperty("role", "recon_output_frame")
        ofl = QVBoxLayout(output_frame); ofl.setContentsMargins(0, 0, 0, 0); ofl.setSpacing(0)
        self.recon_output = QTextEdit()
        self.recon_output.setReadOnly(True)
        self.recon_output.setFont(QFont("Consolas", 10))
        self.recon_output.setPlaceholderText("Select a module from the sidebar and click Run, or press > RUN ALL MODULES.")
        self.recon_output.setStyleSheet("""
            QTextEdit {
                background:#060f1c; border:none; border-radius:8px;
                color:#ebf8ff; padding:6px 8px; line-height:1.45;
                selection-background-color:#0e3358; selection-color:#ffffff;
            }
        """)
        ofl.addWidget(self.recon_output)
        right_layout.addWidget(output_frame, 1)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        self._update_recon_summary()

    # ── Recon helpers ──────────────────────────────────────────────────────

    def _make_filter_pill(self, text: str, active: bool = False) -> QLabel:
        pill = QLabel(text)
        pill.setFixedHeight(22)
        base = "border-radius:4px;padding:2px 9px;font-size:7.5pt;font-weight:800;font-family:'Consolas',monospace;letter-spacing:0.5px;"
        if active:
            pill.setStyleSheet(base + "background:#0d2d4a;border:1px solid #00b8ff;color:#00e5ff;")
        else:
            pill.setStyleSheet(base + "background:#061426;border:1px solid #1e4d79;color:#4b95d5;")
        return pill

    def _recon_copy_log(self):
        QApplication.clipboard().setText(self.recon_output.toPlainText())
        self.statusBar().showMessage("Log copied to clipboard")

    def _recon_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "recon_data.csv", "CSV Files (*.csv)")
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Tag", "Kind", "Label", "Value", "Content"])
            rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()}
                                            for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
            for row in rows:
                w.writerow([row.get("tag",""), row.get("kind",""), row.get("label",""), row.get("value",""), row.get("content","")])
        self.statusBar().showMessage(f"CSV exported → {path}")

    def _recon_export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "recon_data.json", "JSON Files (*.json)")
        if not path: return
        rows = self._recon_records or [{"tag": "LOG", "kind": "line", "content": ln.strip()}
                                        for ln in self.recon_output.toPlainText().splitlines() if ln.strip()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        self.statusBar().showMessage(f"JSON exported → {path}")

    def _recon_clear(self):
        self.recon_output.clear()
        self._reset_recon_metrics()
        self._recon_records = []
        self._update_recon_summary()
        self.statusBar().showMessage("Recon output cleared")

    def _reset_recon_metrics(self):
        self._pill_counts = {"info": 0, "data": 0, "warn": 0, "error": 0}
        self._recon_pill_info.setText("Info 0")
        self._recon_pill_data.setText("Data 0")
        self._recon_pill_warn.setText("Warn 0")
        self._recon_pill_error.setText("Error 0")

    def _on_recon_view_changed(self):
        combo_text = self._severity_combo.currentText().lower()
        if "alerts"  in combo_text: self._recon_filter_mode = "alerts"
        elif "info"  in combo_text: self._recon_filter_mode = "info"
        elif "data"  in combo_text: self._recon_filter_mode = "data"
        elif "warn"  in combo_text: self._recon_filter_mode = "warn"
        elif "error" in combo_text: self._recon_filter_mode = "error"
        else:                       self._recon_filter_mode = "all"
        self._recon_collapse_sections = self._collapse_sections_check.isChecked()
        self._refresh_recon_view()

    def _passes_recon_filter(self, rec: dict) -> bool:
        mode = self._recon_filter_mode
        if mode == "all": return True
        kind = rec.get("kind", "")
        tag  = str(rec.get("tag", "")).upper()
        if kind in ("section",): return True
        if kind in ("divider", "table_header", "table_row", "kv", "meter"): return mode == "all"
        if mode == "alerts": return tag in ("WARN", "ERROR")
        return tag == mode.upper()

    def _update_recon_summary(self):
        sections = sum(1 for r in self._recon_records if r.get("kind") == "section")
        entries  = sum(1 for r in self._recon_records if r.get("kind") not in ("section", "divider"))
        alerts   = sum(1 for r in self._recon_records if str(r.get("tag", "")).upper() in ("WARN", "ERROR"))
        view = self._recon_filter_mode.upper() if self._recon_filter_mode != "alerts" else "ALERTS"
        if self._recon_collapse_sections: view += " + COLLAPSED"
        self._summary_sections.setText(f"Sections {sections}")
        self._summary_entries.setText(f"Entries {entries}")
        self._summary_alerts.setText(f"Alerts {alerts}")
        self._summary_view.setText(f"View {view}")

    def _tick_spinner(self):
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
        self.recon_spinner_label.setText(self._spinner_frames[self._spinner_idx])

    def _set_mod_button_role(self, mid: str, role: str):
        btn = self._mod_buttons.get(mid)
        if not btn: return
        self._mod_status[mid] = role
        prefix_map = {"running": "⟳ ", "done": "✓ ", "error": "✗ ", "idle": "  "}
        prefix = prefix_map.get(role, "  ")
        # Find the original label text (strip any existing prefix)
        base = btn.text().strip().lstrip("⟳✓✗").strip()
        btn.setText(f"{prefix}{base}")
        btn.setProperty("role", f"mod_btn_{role}" if role != "idle" else "mod_btn")
        btn.style().unpolish(btn); btn.style().polish(btn)

    def _set_recon_running(self, module_name: str):
        self.recon_running_label.setText(f"{module_name.upper().replace('_', ' ')}…")
        self.recon_status_strip.setVisible(True)
        self._spinner_timer.start()
        for mid in self._mod_buttons:
            if mid == module_name:
                self._set_mod_button_role(mid, "running")

    def _set_recon_idle(self, module_name: str = "", success: bool = True):
        self._spinner_timer.stop()
        self.recon_status_strip.setVisible(False)
        if module_name:
            self._set_mod_button_role(module_name, "done" if success else "error")

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
            self._set_recon_idle(module_id, success=False)
            self._append_recon_card("ERROR", f"Unknown module: {module_id}", "#ff5f6d")
            return

        self._current_recon_module = module_id
        self.worker = ReconWorker(func)
        self.worker.output.connect(self._render_recon_output)
        self.worker.finished.connect(self._on_recon_module_done)
        self.worker.error.connect(self._on_recon_module_error)
        self.worker.start()

    def _on_recon_module_done(self):
        mid = getattr(self, "_current_recon_module", "")
        self._set_recon_idle(mid, success=True)
        self.statusBar().showMessage("Recon module complete")
        self._append_recon_card("DONE", "Module finished successfully.", "#22c55e")

    def _on_recon_module_error(self, e: str):
        mid = getattr(self, "_current_recon_module", "")
        self._set_recon_idle(mid, success=False)
        self._append_recon_card("ERROR", str(e), "#ff5f6d")
        self.statusBar().showMessage("Recon module failed")

    def _run_all_modules(self):
        import ghostlink.network.recon as recon_mod
        for m in [recon_mod.scan_my_device, recon_mod.scan_infrastructure, recon_mod.scan_wireless,
                  recon_mod.scan_internet_identity, recon_mod.scan_performance, recon_mod.scan_resources,
                  recon_mod.scan_security, recon_mod.scan_traffic]:
            m()

    # ──────────────────────────────────────────────────────────────────────
    # Recon rendering
    # ──────────────────────────────────────────────────────────────────────

    _TAG_CFG: dict[str, tuple] = {
        "DATA":  ("#061e10", "#22c55e", "#22c55e", "#0a2e18"),
        "INFO":  ("#051a28", "#38bdf8", "#38bdf8", "#062233"),
        "WARN":  ("#1e1505", "#f59e0b", "#f59e0b", "#2a1c06"),
        "ERROR": ("#1e0509", "#ff5f6d", "#ff5f6d", "#2a070c"),
        "DONE":  ("#031a0a", "#22c55e", "#22c55e", "#0a2e18"),
        "LOG":   ("#06111e", "#1e4d7a", "#4a8ab5", "#071525"),
    }

    @staticmethod
    def _hl_addresses(safe: str) -> str:
        safe = re.sub(r"(\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)",
                      r"<span style='color:#c084fc;font-weight:700;'>\1</span>", safe)
        safe = re.sub(r"(\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d+)?\b)",
                      r"<span style='color:#67e8f9;font-weight:600;'>\1</span>", safe)
        safe = re.sub(r"(\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b)",
                      r"<span style='color:#2dd4bf;font-weight:700;'>\1</span>", safe)
        safe = re.sub(r"(?<![=#\w\-])(\b\d+\b)(?![;%\w\-])",
                      r"<span style='color:#fbbf24;'>\1</span>", safe)
        return safe

    @staticmethod
    def _hl_semantic(safe: str) -> str:
        safe = re.sub(r"\b(enabled|on|active|responsive|connected|listening|established|secure|good|excellent)\b",
                      r"<span style='color:#22c55e;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        safe = re.sub(r"\b(warn|warning|degraded|unknown|limited|congested)\b",
                      r"<span style='color:#f59e0b;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        safe = re.sub(r"\b(error|failed|disabled|off|blocked|critical|vulnerable|open network)\b",
                      r"<span style='color:#ff6b7a;font-weight:700;'>\1</span>", safe, flags=re.IGNORECASE)
        return safe

    def _strip_ansi(self, text: str) -> str:
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\uFFFD?\[[0-9;]*m", "", text)
        return text.replace("\r", "")

    def _split_into_lines(self, raw: str) -> list[str]:
        raw = re.sub(r"\b(LOG|DATA|INFO|WARN|ERROR)(None|null|n/a|-)\b", r"\1 \2", raw, flags=re.IGNORECASE)
        text = re.sub(r"(?<!\n)(?<!\A)\b(LOG|DATA|INFO|WARN|ERROR)\b", r"\n\1", raw)
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    _SECTION_KW = [
        "route table","ipv4","ipv6","persistent routes","active routes","active tcp","active udp",
        "connections","system identity","network interfaces","dns servers","internet identity",
        "my device","infrastructure","performance","resources","security","traffic analysis",
        "recon result","wireless","ghostlink",
    ]

    @staticmethod
    def _is_meter_line(line: str) -> bool:
        compact = line.strip()
        if len(compact) < 8: return False
        return bool(re.fullmatch(r"[#=\[\]\(\)\|/\\+\-_.:;%\s◆◇▓▒░█▌▐┼┤├┬┴╪╫]+", compact))

    def _classify_line(self, line: str) -> tuple[str, str]:
        if line.strip().lower() in ("none","null","n/a","-"):
            return "LOG", "—"
        m = re.match(r"^(LOG|DATA|INFO|WARN|ERROR|DONE)\s*(.*)", line, re.IGNORECASE)
        if m:
            tag, body = m.group(1).upper(), m.group(2).strip()
            return tag, body if body and body.lower() not in ("none","null","n/a","-") else "—"
        if len(line) >= 6 and re.fullmatch(r"[=\-_.\s]{6,}", line):
            return "DIVIDER", line
        if self._is_meter_line(line):
            return "METER", line.strip()
        kv = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-(). ]{2,36}):\s+(.+)$", line)
        if kv: return "KV", f"{kv.group(1).strip()}\t{kv.group(2).strip()}"
        kv2 = re.match(r"^([A-Za-z][A-Za-z0-9 _/\-(). ]{2,36})\s{2,}(.+)$", line)
        if kv2 and len(re.split(r"\s{2,}|\t+", kv2.group(2).strip())) <= 2:
            return "KV", f"{kv2.group(1).strip()}\t{kv2.group(2).strip()}"
        low = line.lower()
        is_section = (
            bool(re.match(r"^\[\d+\]", line))
            or bool(re.fullmatch(r"[=\-]{3,}.*", line))
            or (len(line) <= 64 and any(kw in low for kw in self._SECTION_KW) and not line.rstrip().endswith("."))
            or bool(re.match(r"^[A-Za-z][A-Za-z0-9 _/\-(). ]{2,80}:$", line))
        )
        if is_section: return "SECTION", line
        if "\t" in line or re.search(r" {3,}", line): return "TABLE", line
        return "LOG", line

    def _divider_html(self) -> str:
        return "<div style='height:1px;margin:8px 2px;background:#0f2d4a;'></div>"

    def _section_html(self, body: str) -> str:
        display = html_mod.escape(body).rstrip(":")
        is_major = bool(re.match(r"^\[\d+\]", body.strip())) or "ghostlink" in body.lower()
        if is_major:
            margin, pad, bg, border, left, size = "16px 0 6px 0", "10px 16px", "#0a2442", "1px solid #245489", "5px solid #60a5fa", "9.5pt"
        else:
            margin, pad, bg, border, left, size = "10px 0 4px 0", "7px 12px", "#081a2f", "1px solid #17395f", "3px solid #2e88d8", "9pt"
        return (
            f"<div style='margin:{margin};padding:{pad};background:{bg};border:{border};"
            f"border-left:{left};border-radius:7px;'>"
            f"<span style='color:#dbeafe;font-family:Consolas,monospace;font-size:{size};"
            f"font-weight:800;letter-spacing:1.2px;text-transform:uppercase;'>{display}</span></div>"
        )

    @staticmethod
    def _split_table_cols(body: str) -> list[str]:
        return [c.strip() for c in re.split(r"\s{2,}|\t+", body.strip()) if c.strip()] or [body.strip()]

    def _kv_html(self, body: str) -> str:
        if "\t" not in body:
            return self._tagged_card_html("LOG", body)
        label, value = body.split("\t", 1)
        safe_label = html_mod.escape(label.strip())
        safe_value = self._hl_semantic(self._hl_addresses(html_mod.escape(value.strip())))
        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='margin:3px 0;"
            "background:#061a2f;border:1px solid #113253;border-left:3px solid #1d8ee0;border-radius:5px;'>"
            "<tr>"
            f"<td width='250' style='padding:6px 10px;color:#8dbce1;font-family:Consolas,monospace;font-size:8.5pt;font-weight:700;'>{safe_label}</td>"
            f"<td style='padding:6px 10px;color:#d6ecff;font-family:Consolas,monospace;font-size:9.5pt;word-break:break-word;'>{safe_value}</td>"
            "</tr></table>"
        )

    def _table_header_html(self, body: str) -> str:
        cols = self._split_table_cols(body)
        cells = "".join(
            f"<th style='padding:7px 10px;text-align:left;color:#7eb5e6;"
            f"font-family:Consolas,monospace;font-size:8pt;font-weight:800;"
            f"letter-spacing:0.8px;text-transform:uppercase;border-bottom:1px solid #2e6ba7;'>"
            f"{html_mod.escape(col)}</th>" for col in cols
        )
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='margin:6px 0 0 0;"
            "border-collapse:collapse;border:1px solid #12385e;border-radius:6px;"
            "overflow:hidden;background:#091b31;'>"
            f"<thead><tr style='background:#0b2240;'>{cells}</tr></thead><tbody>"
        )

    def _meter_html(self, body: str) -> str:
        return (
            "<table width='100%' cellspacing='0' cellpadding='0' style='margin:4px 0 8px 0;"
            "background:#06111f;border:1px solid #143a62;border-left:3px solid #38bdf8;border-radius:6px;'>"
            "<tr>"
            "<td width='64' style='padding:5px 8px;text-align:center;color:#7ec3f6;"
            "font-family:Consolas,monospace;font-size:7pt;font-weight:900;letter-spacing:1px;"
            "border-right:1px solid #1f4f7f;'>METER</td>"
            f"<td style='padding:6px 10px;color:#cde8ff;font-family:Consolas,monospace;"
            f"font-size:8.5pt;white-space:pre;'>{html_mod.escape(body)}</td>"
            "</tr></table>"
        )

    def _table_row_html(self, body: str, idx: int, col_count: int = 0) -> str:
        cols = self._split_table_cols(body)
        target = max(col_count, len(cols))
        cols.extend([""] * (target - len(cols)))
        bg = "#071627" if idx % 2 == 0 else "#0a1e35"
        cells = "".join(
            f"<td style='padding:6px 10px;color:#b8ddf8;font-family:Consolas,monospace;"
            f"font-size:9pt;border-bottom:1px solid #0d2d4a;white-space:nowrap;'>"
            f"{self._hl_addresses(html_mod.escape(col))}</td>" for col in cols
        )
        return f"<tr style='background:{bg};'>{cells}</tr>"

    def _tagged_card_html(self, tag: str, body: str) -> str:
        bg, accent, badge_text, badge_bg = self._TAG_CFG.get(tag, self._TAG_CFG["LOG"])
        is_placeholder = body == "—"
        safe = html_mod.escape(body)
        if not is_placeholder:
            safe = self._hl_semantic(self._hl_addresses(safe))
        body_color = "#597894" if is_placeholder else "#d9eeff"
        body_size  = "8.5pt"   if is_placeholder else "9.5pt"
        body_style = "font-style:italic;" if is_placeholder else ""

        # Increment pill counts — only once per actual record insertion
        tag_lower = tag.lower()
        if tag_lower in self._pill_counts and not is_placeholder:
            self._pill_counts[tag_lower] += 1
            count = self._pill_counts[tag_lower]
            pill_map = {"info": self._recon_pill_info, "data": self._recon_pill_data,
                        "warn": self._recon_pill_warn, "error": self._recon_pill_error}
            if tag_lower in pill_map:
                pill_map[tag_lower].setText(f"{tag.capitalize()} {count}")

        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='margin:3px 0;"
            f"background:{bg};border:1px solid #0d2d4e;border-left:3px solid {accent};border-radius:5px;'>"
            "<tr>"
            f"<td width='64' style='padding:5px 8px;background:{badge_bg};color:{badge_text};"
            f"font-family:Consolas,monospace;font-size:7pt;font-weight:900;letter-spacing:1px;"
            f"text-align:center;border-right:1px solid {accent}33;'>{tag}</td>"
            f"<td style='padding:6px 10px;color:{body_color};font-family:Consolas,monospace;"
            f"font-size:{body_size};line-height:1.72;word-break:break-word;{body_style}'>{safe}</td>"
            "</tr></table>"
        )

    def _render_recon_output(self, raw: str) -> None:
        cleaned = self._strip_ansi(raw)
        lines   = self._split_into_lines(cleaned)
        if not lines:
            return

        parsed: list[dict] = []
        in_table = False
        table_row_i = 0
        table_cols  = 0

        for line in lines:
            tag, body = self._classify_line(line)
            entering_table = (tag == "TABLE" and not in_table)
            leaving_table  = (tag != "TABLE" and in_table)
            if entering_table:
                in_table = True; table_row_i = 0; table_cols = 0
            elif leaving_table:
                in_table = False; table_row_i = 0; table_cols = 0

            if tag == "DIVIDER":
                parsed.append({"tag": "DIVIDER", "kind": "divider", "content": body})
            elif tag == "SECTION":
                parsed.append({"tag": "SECTION", "kind": "section", "content": body})
            elif tag == "KV":
                label, value = body.split("\t", 1) if "\t" in body else (body, "")
                parsed.append({"tag": "DATA", "kind": "kv", "label": label.strip(), "value": value.strip(), "content": f"{label.strip()}: {value.strip()}"})
            elif tag == "METER":
                parsed.append({"tag": "DATA", "kind": "meter", "content": body})
            elif tag == "TABLE":
                cols = self._split_table_cols(body)
                is_header = entering_table and self._looks_like_table_header(body)
                if is_header:
                    table_cols = len(cols)
                    parsed.append({"tag": "DATA", "kind": "table_header", "columns": cols, "content": " | ".join(cols)})
                else:
                    parsed.append({"tag": "DATA", "kind": "table_row", "index": table_row_i, "col_count": table_cols, "columns": cols, "content": " | ".join(cols)})
                    table_row_i += 1
            else:
                parsed.append({"tag": tag, "kind": "line", "content": body})

        self._recon_records.extend(parsed)
        self._refresh_recon_view()

    def _looks_like_table_header(self, body: str) -> bool:
        cols = self._split_table_cols(body)
        if len(cols) < 2: return False
        if any(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9A-Fa-f]{2}:", c) for c in cols): return False
        return sum(1 for c in cols if re.search(r"[A-Za-z]", c)) / max(len(cols), 1) >= 0.8

    def _append_recon_card(self, tag: str, body: str, _color: str = "") -> None:
        self._recon_records.append({"tag": tag, "kind": "line", "content": body})
        self._refresh_recon_view()

    def _refresh_recon_view(self):
        """
        Rebuild the HTML view from _recon_records.
        Pill counts are re-tallied here so they always reflect the filtered view accurately.
        """
        self._reset_recon_metrics()
        self._update_recon_summary()
        self.recon_output.clear()
        if not self._recon_records:
            return

        parts: list[str] = []
        prev_kind = None
        in_table  = False

        for rec in self._recon_records:
            if not self._passes_recon_filter(rec):
                continue

            kind    = rec.get("kind", "")
            tag     = str(rec.get("tag", "LOG")).upper()
            content = str(rec.get("content", ""))

            if self._recon_collapse_sections and kind not in ("section", "divider"):
                if tag not in ("WARN", "ERROR"):
                    continue

            if kind == "divider":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._divider_html())

            elif kind == "section":
                if in_table: parts.append("</tbody></table>"); in_table = False
                if prev_kind not in (None, "section", "divider"):
                    parts.append("<div style='height:4px;'></div>")
                parts.append(self._section_html(content))

            elif kind == "kv":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._kv_html(f"{rec.get('label','').strip()}\t{rec.get('value','').strip()}"))

            elif kind == "meter":
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._meter_html(content))

            elif kind == "table_header":
                if in_table: parts.append("</tbody></table>")
                parts.append(self._table_header_html(content))
                in_table = True

            elif kind == "table_row":
                if not in_table:
                    parts.append(
                        "<table width='100%' cellspacing='0' cellpadding='0' style='margin:6px 0 0 0;"
                        "border-collapse:collapse;border:1px solid #12385e;border-radius:6px;"
                        "overflow:hidden;background:#091b31;'><tbody>"
                    )
                    in_table = True
                cols = rec.get("columns", [])
                row_text = "  ".join(str(c) for c in cols) if isinstance(cols, list) and cols else content
                parts.append(self._table_row_html(row_text, int(rec.get("index", 0)), int(rec.get("col_count", 0))))

            else:
                if in_table: parts.append("</tbody></table>"); in_table = False
                parts.append(self._tagged_card_html(tag, content))

            prev_kind = kind

        if in_table:
            parts.append("</tbody></table>")

        if parts:
            self.recon_output.insertHtml("\n".join(parts))
            self.recon_output.insertHtml("<br>")
            if self._autoscroll_check.isChecked():
                self.recon_output.moveCursor(QTextCursor.End)

    # ──────────────────────────────────────────────────────────────────────
    # Keyboard shortcuts
    # ──────────────────────────────────────────────────────────────────────

    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_F:
            if hasattr(self, "scan_search_edit"):
                self.tabs.setCurrentIndex(0)
                self.scan_search_edit.setFocus()
                self.scan_search_edit.selectAll()
                event.accept(); return
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if self.tabs.currentIndex() == 0 and hasattr(self, "scan_table") and self.scan_table.hasFocus():
                if self.select_btn.isEnabled():
                    self.select_target(); event.accept(); return
        super().keyPressEvent(event)

    # ──────────────────────────────────────────────────────────────────────
    # Legacy compat stubs
    # ──────────────────────────────────────────────────────────────────────

    def _normalize_recon_stream(self, text: str) -> str: return text
    def _parse_recon_line(self, line: str): return self._classify_line(line)
    def _is_divider_line(self, text: str) -> bool: return len(text) >= 6 and bool(re.fullmatch(r"[=\-_.\s]{6,}", text.strip()))
    def _is_section_title(self, text: str) -> bool: tag, _ = self._classify_line(text); return tag == "SECTION"