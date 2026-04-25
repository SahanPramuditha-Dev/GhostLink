import sys
import os
import ctypes
import io
import re
import html as html_mod

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
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QTextCursor

from ghostlink.engine.profiles import PROFILES
from ghostlink.core.constants import (
    DEFAULT_MINLEN,
    DEFAULT_MAXLEN,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
)

from .workers import ScanWorker, AttackWorker, ReconWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GHOSTLINK")
        self.resize(1240, 840)
        self.setMinimumSize(1080, 720)
        self.setFont(QFont("Segoe UI", 10))

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

    # ──────────────────────────────────────────────────────────────────────
    # Chrome bar
    # ──────────────────────────────────────────────────────────────────────

    def create_chrome_bar(self) -> QWidget:
        bar = QFrame()
        bar.setProperty("role", "chrome")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(8)

        dot_red    = QLabel("●"); dot_red.setProperty("role", "dot_red")
        dot_yellow = QLabel("●"); dot_yellow.setProperty("role", "dot_yellow")
        dot_green  = QLabel("●"); dot_green.setProperty("role", "dot_green")
        title      = QLabel("G H O S T L I N K"); title.setProperty("role", "chrome_title")
        version    = QLabel("Wi-Fi Security Framework // v2.1.0"); version.setProperty("role", "chrome_meta")

        layout.addWidget(dot_red); layout.addWidget(dot_yellow); layout.addWidget(dot_green)
        layout.addSpacing(10); layout.addWidget(title); layout.addStretch(); layout.addWidget(version)
        return bar

    def make_tab_header(self, title: str, subtitle: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 2); layout.setSpacing(4)
        t = QLabel(title);    t.setProperty("role", "title")
        s = QLabel(subtitle); s.setProperty("role", "subtitle")
        layout.addWidget(t); layout.addWidget(s)
        return container

    # ──────────────────────────────────────────────────────────────────────
    # Theme
    # ──────────────────────────────────────────────────────────────────────

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
        QLineEdit, QSpinBox, QComboBox {
            background: #081a30; border: 1px solid #255785; border-radius: 8px;
            color: #eff8ff; padding: 6px 8px; min-height: 20px;
        }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus,
        QTextEdit:focus, QTableWidget:focus { border: 1px solid #00b8ff; }
        QComboBox::drop-down { border: none; width: 24px; }
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
        QFrame[role="recon_running"] {
            background: #030f1f;
            border: 1px solid rgba(0, 184, 255, 0.25);
            border-left: 3px solid #00b8ff;
            border-radius: 8px;
        }
        """)

    # ──────────────────────────────────────────────────────────────────────
    # Tab 1 — Scan
    # ──────────────────────────────────────────────────────────────────────

    def create_scan_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, "SCAN & SELECT")
        layout = QVBoxLayout(tab); layout.setContentsMargins(14, 14, 14, 14); layout.setSpacing(12)
        layout.addWidget(self.make_tab_header("Target Discovery", "Scan nearby Wi-Fi networks and select a target to attack."))

        row = QHBoxLayout(); row.setSpacing(10)
        self.scan_btn = QPushButton("SCAN NETWORKS"); self.scan_btn.clicked.connect(self.start_scan); row.addWidget(self.scan_btn)
        self.debug_btn = QPushButton("DEBUG SCANNER"); self.debug_btn.setProperty("variant", "secondary"); self.debug_btn.clicked.connect(self.debug_scanner); row.addWidget(self.debug_btn)
        row.addStretch(); layout.addLayout(row)

        self.scan_table = QTableWidget(0, 3)
        self.scan_table.setHorizontalHeaderLabels(["SSID", "SIGNAL", "SECURITY"])
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setShowGrid(True); self.scan_table.setAlternatingRowColors(False)
        self.scan_table.horizontalHeader().setStretchLastSection(False)
        self.scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.scan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.scan_table.setMinimumHeight(260); layout.addWidget(self.scan_table)

        ar = QHBoxLayout(); ar.setSpacing(10)
        self.select_btn = QPushButton("SELECT TARGET"); self.select_btn.setProperty("variant", "success")
        self.select_btn.clicked.connect(self.select_target); self.select_btn.setEnabled(False)
        ar.addWidget(self.select_btn); ar.addStretch(); layout.addLayout(ar)

        strip = QFrame(); strip.setProperty("role", "target_strip")
        sl = QHBoxLayout(strip); sl.setContentsMargins(12, 10, 12, 10)
        self.target_state_left  = QLabel("●   TARGET LOCKED"); self.target_state_left.setProperty("role", "target_left")
        self.target_state_right = QLabel("None");              self.target_state_right.setProperty("role", "target_right")
        sl.addWidget(self.target_state_left); sl.addStretch(); sl.addWidget(self.target_state_right)
        layout.addWidget(strip)

    def _set_scan_placeholder(self, text: str):
        self.scan_table.setRowCount(1)
        for c, v in enumerate([text, "", ""]): self.scan_table.setItem(0, c, QTableWidgetItem(v))

    def _security_item(self, security: str) -> QTableWidgetItem:
        item = QTableWidgetItem(security.upper()); sec = security.upper()
        if "WPA3" in sec:   item.setForeground(Qt.cyan)
        elif "WPA2" in sec: item.setForeground(Qt.green)
        elif "OPEN" in sec: item.setForeground(Qt.yellow)
        else:               item.setForeground(Qt.white)
        return item

    def start_scan(self):
        try:    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except: is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Administrator Required",
                "GHOSTLINK must be run as Administrator to scan Wi-Fi networks.\n\n"
                "Please restart the application as Administrator.\n(Right-click -> Run as administrator)")
            return
        self.statusBar().showMessage("Scanning for Wi-Fi networks...")
        self.scan_btn.setEnabled(False); self.scan_table.setRowCount(0); self._set_scan_placeholder("Scanning...")
        self.worker = ScanWorker(None); self.worker.finished.connect(self.on_scan_finished); self.worker.error.connect(self.on_scan_error); self.worker.start()

    def on_scan_finished(self, networks):
        self.scan_results = networks; self.scan_table.setRowCount(0)
        if networks:
            self.scan_table.setRowCount(len(networks))
            for row, net in enumerate(networks):
                self.scan_table.setItem(row, 0, QTableWidgetItem(net.ssid))
                self.scan_table.setItem(row, 1, QTableWidgetItem(f"{net.signal}%"))
                self.scan_table.setItem(row, 2, self._security_item(net.security))
            self.statusBar().showMessage(f"Scan complete: {len(networks)} network(s) found")
        else:
            self._set_scan_placeholder("No networks found."); self.statusBar().showMessage("Scan complete: no networks found")
        self.scan_btn.setEnabled(True); self.select_btn.setEnabled(bool(networks))

    def on_scan_error(self, message):
        self.scan_btn.setEnabled(True); self.scan_table.setRowCount(0)
        self._set_scan_placeholder("Scan failed - see error message."); self.statusBar().showMessage("Scan failed")
        QMessageBox.critical(self, "Scan Error", message)

    def select_target(self):
        row = self.scan_table.currentRow()
        if 0 <= row < len(self.scan_results):
            net = self.scan_results[row]
            self.config["ssid"] = net.ssid; self.config["interface"] = net.interface
            self.attack_target_label.setText(f"SSID: {net.ssid}")
            self.target_state_right.setText(f"{net.ssid} · {net.security}")
            self.statusBar().showMessage(f"Target selected: {net.ssid}")

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

    # ──────────────────────────────────────────────────────────────────────
    # Tab 2 — Attack Config
    # ──────────────────────────────────────────────────────────────────────

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
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed); pf.addRow("Profile:", self.profile_combo)
        self.charset_edit = QLineEdit(self.config["charset"]); self.charset_edit.setPlaceholderText("Characters to brute force"); pf.addRow("Charset:", self.charset_edit)
        self.minlen_spin = QSpinBox(); self.minlen_spin.setRange(1, 12); self.minlen_spin.setValue(self.config["minlen"]); pf.addRow("Min Length:", self.minlen_spin)
        self.maxlen_spin = QSpinBox(); self.maxlen_spin.setRange(1, 12); self.maxlen_spin.setValue(self.config["maxlen"]); pf.addRow("Max Length:", self.maxlen_spin)

        eg = QGroupBox("Execution Limits"); ef = QFormLayout(eg)
        ef.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter); ef.setFormAlignment(Qt.AlignLeft | Qt.AlignTop); ef.setSpacing(10)
        self.threads_spin = QSpinBox(); self.threads_spin.setRange(1, 8);  self.threads_spin.setValue(self.config["threads"]); ef.addRow("Threads:", self.threads_spin)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3, 30); self.timeout_spin.setValue(self.config["timeout"]); ef.addRow("Timeout (s):", self.timeout_spin)

        wg = QGroupBox("Wordlist Source"); wl = QVBoxLayout(wg); wl.setSpacing(10)
        self.wordlist_edit = QLineEdit(); self.wordlist_edit.setPlaceholderText("No wordlist selected"); self.wordlist_edit.setReadOnly(True); wl.addWidget(self.wordlist_edit)
        wb = QHBoxLayout(); wb.setSpacing(8)
        self.browse_btn   = QPushButton("BROWSE"); self.browse_btn.setProperty("variant", "secondary");   self.browse_btn.clicked.connect(self.browse_wordlist);               wb.addWidget(self.browse_btn)
        self.clear_wl_btn = QPushButton("CLEAR");  self.clear_wl_btn.setProperty("variant", "secondary"); self.clear_wl_btn.clicked.connect(lambda: self.wordlist_edit.setText("")); wb.addWidget(self.clear_wl_btn)
        wb.addStretch(); wl.addLayout(wb)

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
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist")
        if path: self.wordlist_edit.setText(path)

    def update_config_from_gui(self):
        self.config["charset"]     = self.charset_edit.text()
        self.config["minlen"]      = self.minlen_spin.value()
        self.config["maxlen"]      = self.maxlen_spin.value()
        self.config["threads"]     = self.threads_spin.value()
        self.config["timeout"]     = self.timeout_spin.value()
        wl = self.wordlist_edit.text().strip()
        self.config["wordlist"]    = wl if wl else None
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

    # ──────────────────────────────────────────────────────────────────────
    # Tab 3 — Progress
    # ──────────────────────────────────────────────────────────────────────

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
        if password:
            self.progress_bar.setValue(100); self.progress_percent_label.setText("Progress: 100%")
        else:
            self.progress_percent_label.setText(f"Progress: {self.progress_bar.value()}%")
        if password and verified:
            QMessageBox.information(self, "Target Compromised",
                f"Password Found!\n\nSSID: {self.config['ssid']}\nPassword: {password}\nAttempts: {attempts}\nTime: {elapsed:.1f}s")
            self.statusBar().showMessage("Attack complete: password verified")
        else:
            QMessageBox.information(self, "Attack Complete", "Password not found within search space.")
            self.statusBar().showMessage("Attack complete: password not found")

    # ──────────────────────────────────────────────────────────────────────
    # Tab 4 — Recon
    # ──────────────────────────────────────────────────────────────────────

    def create_recon_tab(self):
        tab = QWidget(); self.tabs.addTab(tab, "RECON")
        layout = QVBoxLayout(tab); layout.setContentsMargins(14, 14, 14, 14); layout.setSpacing(12)
        layout.addWidget(self.make_tab_header("Reconnaissance", "Run network intelligence modules and view clean, structured output."))

        mg = QGridLayout(); mg.setHorizontalSpacing(8); mg.setVerticalSpacing(8)
        for idx, (label, mid) in enumerate([
            ("1. Full Recon", "full"), ("2. My Device", "my_device"), ("3. Infrastructure", "infrastructure"),
            ("4. Wireless Analysis", "wireless"), ("5. Internet Identity", "internet"), ("6. Performance", "performance"),
            ("7. Resources & Sharing", "resources"), ("8. Security Insights", "security"), ("9. Traffic Analysis", "traffic"),
        ]):
            r, c = divmod(idx, 3)
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, m=mid: self._run_recon_module(m))
            mg.addWidget(btn, r, c)
        layout.addLayout(mg)

        run_all = QPushButton("RUN ALL MODULES")
        run_all.setProperty("variant", "critical")
        run_all.clicked.connect(lambda: self._run_recon_module("all"))
        layout.addWidget(run_all)

        # ── Running indicator strip ──────────────────────────────────────
        self.recon_status_strip = QFrame()
        self.recon_status_strip.setProperty("role", "recon_running")
        self.recon_status_strip.setVisible(False)
        ss_layout = QHBoxLayout(self.recon_status_strip)
        ss_layout.setContentsMargins(14, 8, 14, 8)
        ss_layout.setSpacing(10)

        self.recon_spinner_label = QLabel("◐")
        self.recon_spinner_label.setStyleSheet(
            "color:#00b8ff; font-size:14pt; font-weight:900;"
        )
        self._spinner_frames = ["◐", "◓", "◑", "◒"]
        self._spinner_idx = 0

        self.recon_running_label = QLabel("Module running…")
        self.recon_running_label.setStyleSheet(
            "color:#a0d4ff; font-size:9.5pt; font-weight:700; letter-spacing:1px;"
        )

        self.recon_pulse_bar = QProgressBar()
        self.recon_pulse_bar.setRange(0, 0)   # indeterminate marquee
        self.recon_pulse_bar.setFixedHeight(6)
        self.recon_pulse_bar.setTextVisible(False)
        self.recon_pulse_bar.setStyleSheet("""
            QProgressBar {
                background: #071930;
                border: none;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                border-radius: 3px;
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00b8ff, stop:1 #09de9a
                );
            }
        """)

        ss_layout.addWidget(self.recon_spinner_label)
        ss_layout.addWidget(self.recon_running_label)
        ss_layout.addStretch()
        ss_layout.addWidget(self.recon_pulse_bar, 1)
        layout.addWidget(self.recon_status_strip)

        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(120)
        self._spinner_timer.timeout.connect(self._tick_spinner)

        # ── Output area ──────────────────────────────────────────────────
        og = QGroupBox("Recon Output"); ol = QVBoxLayout(og)
        self.recon_output = QTextEdit()
        self.recon_output.setReadOnly(True)
        self.recon_output.setFont(QFont("Consolas", 10))
        ol.addWidget(self.recon_output)
        layout.addWidget(og, 1)

    # ── Spinner helpers ───────────────────────────────────────────────────

    def _tick_spinner(self):
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
        self.recon_spinner_label.setText(self._spinner_frames[self._spinner_idx])

    def _set_recon_running(self, module_name: str):
        label = module_name.upper().replace("_", " ")
        self.recon_running_label.setText(f"Running: {label}…")
        self.recon_status_strip.setVisible(True)
        self._spinner_timer.start()

    def _set_recon_idle(self):
        self._spinner_timer.stop()
        self.recon_status_strip.setVisible(False)

    # ── Module dispatch ───────────────────────────────────────────────────

    def _run_recon_module(self, module_id: str):
        self.recon_output.clear()
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

    # ══════════════════════════════════════════════════════════════════════
    # Recon rendering — fully finetuned v3
    # ══════════════════════════════════════════════════════════════════════

    # Per-tag config: (card-bg, left-accent, badge-text, badge-bg)
    _TAG_CFG: dict[str, tuple[str, str, str, str]] = {
        "DATA":  ("#061e10", "#22c55e", "#22c55e", "#0a2e18"),
        "INFO":  ("#051a28", "#38bdf8", "#38bdf8", "#062233"),
        "WARN":  ("#1e1505", "#f59e0b", "#f59e0b", "#2a1c06"),
        "ERROR": ("#1e0509", "#ff5f6d", "#ff5f6d", "#2a070c"),
        # LOG uses a more readable mid-blue-grey — not too dark, not noisy
        "LOG":   ("#06111e", "#1e4d7a", "#4a8ab5", "#071525"),
    }

    # ── Address syntax highlighter ────────────────────────────────────────

    @staticmethod
    def _hl_addresses(safe: str) -> str:
        """
        Highlight network addresses inside already-HTML-escaped text.
        Application order: MAC → IPv6 → IPv4 → bare integers.
        We skip content already inside a <span> tag to avoid double-wrapping.
        """
        # MAC  aa:bb:cc:dd:ee:ff  /  aa-bb-cc-dd-ee-ff
        safe = re.sub(
            r"(\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)",
            r"<span style='color:#c084fc;font-weight:700;'>\1</span>",
            safe,
        )
        # IPv6 (two or more colon-separated hex groups, optional prefix length)
        safe = re.sub(
            r"(\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d+)?\b)",
            r"<span style='color:#67e8f9;font-weight:600;'>\1</span>",
            safe,
        )
        # IPv4 with optional CIDR
        safe = re.sub(
            r"(\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b)",
            r"<span style='color:#2dd4bf;font-weight:700;'>\1</span>",
            safe,
        )
        # Standalone integers — exclude digits already inside HTML attribute values
        # (e.g. inside color:#2dd4bf or font-size:9pt)
        safe = re.sub(
            r"(?<![=#\w\-])(\b\d+\b)(?![;%\w\-])",
            r"<span style='color:#fbbf24;'>\1</span>",
            safe,
        )
        return safe

    # ── Stream pre-processing ─────────────────────────────────────────────

    def _strip_ansi(self, text: str) -> str:
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
        text = re.sub(r"\uFFFD?\[[0-9;]*m", "", text)
        return text.replace("\r", "")

    def _split_into_lines(self, raw: str) -> list[str]:
        """
        Force LOG/DATA/INFO/WARN/ERROR tokens onto their own line.
        The recon worker sometimes emits them concatenated with prior output
        (e.g.  "...192.168.1.3   306LOGNone").
        """
        text = re.sub(
            r"(?<!\n)(?<!\A)\b(LOG|DATA|INFO|WARN|ERROR)\b",
            r"\n\1",
            raw,
        )
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    # ── Line classifier ───────────────────────────────────────────────────

    # Keywords that promote a plain line to a SECTION heading
    _SECTION_KW = [
        "route table", "ipv4", "ipv6", "persistent routes", "active routes",
        "active tcp", "active udp", "connections", "system identity",
        "network interfaces", "dns servers", "internet identity", "my device",
        "infrastructure", "performance", "resources", "security",
        "traffic analysis", "recon result", "wireless", "ghostlink",
    ]

    def _classify_line(self, line: str) -> tuple[str, str]:
        """Return (tag, body).  Tags: LOG DATA INFO WARN ERROR SECTION DIVIDER TABLE"""

        # 1. Explicit stream token — allow zero or more spaces between tag and body
        m = re.match(r"^(LOG|DATA|INFO|WARN|ERROR)\s*(.*)", line, re.IGNORECASE)
        if m:
            tag  = m.group(1).upper()
            body = m.group(2).strip()
            # Normalise empty / "None" bodies to an em-dash placeholder
            if not body or body.lower() in ("none", "null", "n/a", "-"):
                return tag, "—"
            return tag, body

        # 2. Pure divider (6+ repeated decoration chars)
        if len(line) >= 6 and re.fullmatch(r"[=\-─═_·\s]{6,}", line):
            return "DIVIDER", line

        # 3. Section / sub-heading detection
        low = line.lower()
        is_section_pattern = any(re.search(p, line, re.IGNORECASE) for p in [
            r"^\[\d+\]", r"^={3,}", r"─{4,}", r"^#+\s",
        ])
        is_section_keyword = any(kw in low for kw in self._SECTION_KW)
        # Lines ending in ":" that look like sub-headings (e.g. "Active Routes:")
        is_subheader = bool(re.match(r"^[A-Za-z][A-Za-z0-9 _/\-]{2,50}:$", line))

        if is_section_pattern or is_section_keyword or is_subheader:
            return "SECTION", line

        # 4. Preformatted / tabular (tabs or 3+ consecutive spaces)
        if "\t" in line or re.search(r" {3,}", line):
            return "TABLE", line

        # 5. Default
        return "LOG", line

    # ── HTML card builders ────────────────────────────────────────────────

    def _divider_html(self) -> str:
        return (
            "<div style='"
            "height:1px;"
            "margin:8px 2px;"
            "background:#0f2d4a;"
            "'></div>"
        )

    def _section_html(self, body: str) -> str:
        # Strip trailing colon — the visual treatment is enough
        display = html_mod.escape(body).rstrip(":")
        return (
            "<div style='"
            "margin:16px 0 4px 0;"
            "padding:9px 16px;"
            "background:#091d36;"
            "border-top:1px solid #1c4a82;"
            "border-bottom:1px solid #1c4a82;"
            "border-left:4px solid #818cf8;"
            "border-radius:5px;"
            "'>"
            "<span style='"
            "color:#ddd6fe;"
            "font-family:Consolas,monospace;"
            "font-size:10pt;"
            "font-weight:800;"
            "letter-spacing:1.5px;"
            "text-transform:uppercase;"
            f"'>{display}</span>"
            "</div>"
        )

    def _table_header_html(self, body: str) -> str:
        safe = html_mod.escape(body)
        return (
            "<div style='"
            "margin:6px 0 0 0;"
            "padding:5px 14px;"
            "background:#0b2240;"
            "border-bottom:2px solid #1e5090;"
            "border-radius:4px 4px 0 0;"
            "font-family:Consolas,monospace;"
            "font-size:8pt;"
            "color:#5b9bd5;"
            "font-weight:800;"
            "letter-spacing:2px;"
            "text-transform:uppercase;"
            "white-space:pre;"
            f"'>{safe}</div>"
        )

    def _table_row_html(self, body: str, idx: int) -> str:
        safe = html_mod.escape(body)
        safe = self._hl_addresses(safe)
        # Clearly alternating rows: slightly more contrast than before
        bg            = "#071627" if idx % 2 == 0 else "#0a1e35"
        border_accent = "#0d3258" if idx % 2 == 0 else "#102c4a"
        return (
            f"<div style='"
            f"margin:0;"
            f"padding:4px 14px;"
            f"background:{bg};"
            f"border-left:2px solid {border_accent};"
            f"font-family:Consolas,monospace;"
            f"font-size:9pt;"
            f"color:#a8d4f0;"
            f"line-height:1.65;"
            f"white-space:pre;"
            f"'>{safe}</div>"
        )

    def _tagged_card_html(self, tag: str, body: str) -> str:
        bg, accent, badge_text, badge_bg = self._TAG_CFG.get(tag, self._TAG_CFG["LOG"])

        is_placeholder = (body == "—")

        safe = html_mod.escape(body)
        if not is_placeholder:
            safe = self._hl_addresses(safe)

        # Visual treatment for empty/placeholder lines
        body_color = "#2e5272" if is_placeholder else "#cce8ff"
        body_size  = "8.5pt"   if is_placeholder else "9.5pt"
        body_style = "font-style:italic;" if is_placeholder else ""

        return (
            # Outer container — overflow:hidden clips badge to card height
            f"<div style='"
            f"margin:2px 0;"
            f"background:{bg};"
            f"border:1px solid #0d2d4e;"
            f"border-left:3px solid {accent};"
            f"border-radius:5px;"
            f"overflow:hidden;"
            f"'>"
            # Badge — no outer padding on the card; badge fills its own height via padding
            f"<span style='"
            f"display:inline-block;"
            f"background:{badge_bg};"
            f"color:{badge_text};"
            f"font-family:Consolas,monospace;"
            f"font-size:6.5pt;"
            f"font-weight:900;"
            f"padding:5px 10px;"          # top/bottom padding = row height control
            f"margin-right:12px;"
            f"border-right:1px solid {accent}22;"
            f"min-width:38px;"
            f"text-align:center;"
            f"letter-spacing:1.5px;"
            f"vertical-align:middle;"
            f"'>{tag}</span>"
            # Body text — line-height makes the row feel spacious
            f"<span style='"
            f"color:{body_color};"
            f"font-family:Consolas,monospace;"
            f"font-size:{body_size};"
            f"line-height:1.9;"
            f"vertical-align:middle;"
            f"word-break:break-all;"
            f"{body_style}"
            f"'>{safe}</span>"
            f"</div>"
        )

    # ── Main render entry point ───────────────────────────────────────────

    def _render_recon_output(self, raw: str) -> None:
        cleaned = self._strip_ansi(raw)
        lines   = self._split_into_lines(cleaned)
        if not lines:
            return

        parts: list[str] = []
        prev_tag    = None
        table_row_i = 0
        in_table    = False

        for line in lines:
            tag, body = self._classify_line(line)

            # ── Track TABLE block boundaries for header detection ──────
            entering_table = (tag == "TABLE" and not in_table)
            leaving_table  = (tag != "TABLE" and in_table)

            if entering_table:
                in_table    = True
                table_row_i = 0
            elif leaving_table:
                in_table = False
                # Thin bottom rule closes the table block visually
                parts.append(
                    "<div style='height:1px;background:#0d2d4a;margin-bottom:8px;'></div>"
                )
                table_row_i = 0

            # ── Render ────────────────────────────────────────────────
            if tag == "DIVIDER":
                parts.append(self._divider_html())

            elif tag == "SECTION":
                if prev_tag is not None and prev_tag not in ("SECTION", "DIVIDER"):
                    parts.append("<div style='height:4px;'></div>")
                parts.append(self._section_html(body))

            elif tag == "TABLE":
                # Classify first row of a new block as a header when it looks like one:
                # all-caps-starting tokens, multiple alignment spaces, no IP octets, no MACs
                is_header = (
                    entering_table
                    and bool(re.match(r"^[A-Z][A-Za-z0-9 _/]{2,}", body))
                    and len(re.findall(r" {2,}", body)) >= 1
                    and not re.search(r"\d{1,3}\.\d{1,3}", body)
                    and not re.search(r"[0-9A-Fa-f]{2}:", body)
                )
                if is_header:
                    parts.append(self._table_header_html(body))
                    # table_row_i stays 0 so first data row is even-shaded
                else:
                    parts.append(self._table_row_html(body, table_row_i))
                    table_row_i += 1

            else:  # LOG DATA INFO WARN ERROR
                parts.append(self._tagged_card_html(tag, body))

            prev_tag = tag

        # Close any table that was still open when the stream ended
        if in_table:
            parts.append(
                "<div style='height:1px;background:#0d2d4a;margin-bottom:8px;'></div>"
            )

        self.recon_output.insertHtml("\n".join(parts))
        self.recon_output.insertHtml("<br>")
        self.recon_output.moveCursor(QTextCursor.End)

    # ── One-off status card (errors, completion) ──────────────────────────

    def _append_recon_card(self, tag: str, body: str, color: str) -> None:
        safe = html_mod.escape(body).replace("\n", "<br>")
        self.recon_output.insertHtml(
            f"<div style='"
            f"margin:6px 0;"
            f"background:#07172a;"
            f"border:1px solid #1a3f6a;"
            f"border-left:3px solid {color};"
            f"border-radius:6px;"
            f"overflow:hidden;"
            f"'>"
            f"<span style='"
            f"display:inline-block;"
            f"background:{color}18;"
            f"color:{color};"
            f"font-family:Consolas,monospace;"
            f"font-size:6.5pt;"
            f"font-weight:900;"
            f"padding:5px 10px;"
            f"border-right:1px solid {color}22;"
            f"margin-right:12px;"
            f"min-width:38px;"
            f"text-align:center;"
            f"letter-spacing:1.5px;"
            f"vertical-align:middle;"
            f"'>{tag}</span>"
            f"<span style='"
            f"color:#d9efff;"
            f"font-family:Consolas,monospace;"
            f"font-size:9.5pt;"
            f"line-height:1.9;"
            f"vertical-align:middle;"
            f"'>{safe}</span>"
            f"</div>"
        )
        self.recon_output.insertHtml("<br>")
        self.recon_output.moveCursor(QTextCursor.End)

    # ── Legacy compat stubs ───────────────────────────────────────────────
    def _normalize_recon_stream(self, text: str) -> str:   return text
    def _parse_recon_line(self, line: str):                 return self._classify_line(line)
    def _is_divider_line(self, text: str) -> bool:         return len(text) >= 6 and bool(re.fullmatch(r"[=\-─═_·\s]{6,}", text.strip()))
    def _is_section_title(self, text: str) -> bool:        tag, _ = self._classify_line(text); return tag == "SECTION"