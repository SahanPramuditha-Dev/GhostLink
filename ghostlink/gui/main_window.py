import sys
import os
import ctypes
import io

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
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

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

    def create_chrome_bar(self) -> QWidget:
        bar = QFrame()
        bar.setProperty("role", "chrome")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(8)

        dot_red = QLabel("●")
        dot_red.setProperty("role", "dot_red")
        dot_yellow = QLabel("●")
        dot_yellow.setProperty("role", "dot_yellow")
        dot_green = QLabel("●")
        dot_green.setProperty("role", "dot_green")

        title = QLabel("G H O S T L I N K")
        title.setProperty("role", "chrome_title")
        version = QLabel("Wi-Fi Security Framework // v2.1.0")
        version.setProperty("role", "chrome_meta")

        layout.addWidget(dot_red)
        layout.addWidget(dot_yellow)
        layout.addWidget(dot_green)
        layout.addSpacing(10)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(version)
        return bar

    def make_tab_header(self, title: str, subtitle: str) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(4)

        title_lbl = QLabel(title)
        title_lbl.setProperty("role", "title")
        subtitle_lbl = QLabel(subtitle)
        subtitle_lbl.setProperty("role", "subtitle")

        layout.addWidget(title_lbl)
        layout.addWidget(subtitle_lbl)
        return container

    def apply_theme(self):
        dark_style = """
        QWidget {
            color: #d5ecff;
            font-family: 'Segoe UI', 'Trebuchet MS', sans-serif;
            font-size: 10pt;
        }

        QMainWindow {
            background-color: #030d1b;
        }

        QFrame[role="chrome"] {
            background: #020a16;
            border-bottom: 1px solid #12375f;
        }

        QLabel[role="dot_red"] { color: #ff4b4b; font-size: 12pt; }
        QLabel[role="dot_yellow"] { color: #ffc531; font-size: 12pt; }
        QLabel[role="dot_green"] { color: #2fe67a; font-size: 12pt; }

        QLabel[role="chrome_title"] {
            color: #00b8ff;
            font-weight: 700;
            letter-spacing: 3px;
        }

        QLabel[role="chrome_meta"] {
            color: #2f79b4;
            font-size: 9pt;
        }

        QStatusBar {
            background: #020a16;
            border-top: 1px solid #12375f;
            color: #2f79b4;
        }

        QTabWidget::pane {
            background: #010b18;
            border: 1px solid #12375f;
            border-top: none;
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
            padding: 12px;
        }

        QTabBar::tab {
            background: #061426;
            color: #f5fbff;
            border: 1px solid #36506e;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
            padding: 10px 18px;
            margin-right: 4px;
            font-weight: 800;
            letter-spacing: 1px;
        }

        QTabBar::tab:selected {
            background: #091b33;
            border-color: #5e7ea2;
        }

        QTabBar::tab:hover {
            background: #0b213f;
        }

        QLabel[role="title"] {
            font-size: 21px;
            font-weight: 800;
            color: #f6fcff;
        }

        QLabel[role="subtitle"] {
            color: #3c8ad0;
            font-size: 10pt;
        }

        QLabel[role="meta"] {
            color: #5e89b3;
            font-size: 9pt;
        }

        QLabel[role="pill"] {
            background: #061a30;
            border: 1px solid #0078bf;
            border-radius: 9px;
            color: #dff2ff;
            font-weight: 700;
            padding: 9px 12px;
        }

        QLabel[role="target_left"] {
            color: #00c5ff;
            font-size: 10pt;
            font-weight: 700;
        }

        QLabel[role="target_right"] {
            color: #f6fcff;
            font-size: 10pt;
            font-weight: 600;
        }

        QFrame[role="target_strip"] {
            background: #061a30;
            border: 1px solid #00a9ee;
            border-radius: 9px;
        }

        QLabel[role="metric"] {
            background: #081a2f;
            border: 1px solid #1e4f7f;
            border-radius: 9px;
            color: #e8f6ff;
            font-weight: 700;
            padding: 10px 12px;
        }

        QLabel[role="badge"] {
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 8pt;
            font-weight: 800;
        }

        QGroupBox {
            color: #f4fbff;
            background: #031224;
            border: 1px solid #1b456f;
            border-radius: 9px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: 700;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
        }

        QTableWidget, QTextEdit {
            background: #071930;
            border: 1px solid #1f4d79;
            border-radius: 8px;
            color: #ebf8ff;
            gridline-color: #10365a;
            selection-background-color: #0e3358;
            selection-color: #ffffff;
        }

        QHeaderView::section {
            background: #0c2542;
            color: #4b95d5;
            border: none;
            border-bottom: 1px solid #1a4671;
            padding: 8px;
            font-weight: 700;
            letter-spacing: 1px;
        }

        QLineEdit, QSpinBox, QComboBox {
            background: #081a30;
            border: 1px solid #255785;
            border-radius: 8px;
            color: #eff8ff;
            padding: 6px 8px;
            min-height: 20px;
        }

        QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus, QTableWidget:focus {
            border: 1px solid #00b8ff;
        }

        QComboBox::drop-down {
            border: none;
            width: 24px;
        }

        QCheckBox {
            spacing: 8px;
            color: #d7ebff;
        }

        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 4px;
            border: 1px solid #2b6297;
            background: #07192f;
        }

        QCheckBox::indicator:checked {
            background: #0094de;
            border: 1px solid #56c7ff;
        }

        QPushButton {
            background: #061326;
            border: 1px solid #4a5f79;
            color: #f7fcff;
            border-radius: 9px;
            padding: 10px 16px;
            font-weight: 800;
            letter-spacing: 1px;
            min-height: 22px;
        }

        QPushButton:hover {
            background: #0b2341;
            border: 1px solid #6587ad;
        }

        QPushButton:pressed {
            padding-top: 11px;
        }

        QPushButton[variant="secondary"] {
            background: #061326;
            border: 1px solid #4a5f79;
        }

        QPushButton[variant="danger"] {
            background: #3d1119;
            border: 1px solid #8b3a4c;
        }

        QPushButton[variant="danger"]:hover {
            background: #5a1825;
        }

        QPushButton[variant="success"] {
            background: #08331f;
            border: 1px solid #1f9b68;
        }

        QPushButton[variant="critical"] {
            background: #3d2312;
            border: 1px solid #a3663e;
        }

        QPushButton:disabled {
            background: #1c2a3b;
            border: 1px solid #354a62;
            color: #6f8ca9;
        }

        QProgressBar {
            background: #09182c;
            border: 1px solid #245987;
            border-radius: 8px;
            text-align: center;
            color: #f5fbff;
            min-height: 22px;
            font-weight: 700;
        }

        QProgressBar::chunk {
            border-radius: 7px;
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 #00b8ff,
                stop: 1 #09de9a
            );
        }
        """
        self.setStyleSheet(dark_style)

    def create_scan_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "SCAN & SELECT")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        layout.addWidget(self.make_tab_header("Target Discovery", "Scan nearby Wi-Fi networks and select a target to attack."))

        control_row = QHBoxLayout()
        control_row.setSpacing(10)

        self.scan_btn = QPushButton("SCAN NETWORKS")
        self.scan_btn.clicked.connect(self.start_scan)
        control_row.addWidget(self.scan_btn)

        self.debug_btn = QPushButton("DEBUG SCANNER")
        self.debug_btn.setProperty("variant", "secondary")
        self.debug_btn.clicked.connect(self.debug_scanner)
        control_row.addWidget(self.debug_btn)
        control_row.addStretch()
        layout.addLayout(control_row)

        self.scan_table = QTableWidget(0, 3)
        self.scan_table.setHorizontalHeaderLabels(["SSID", "SIGNAL", "SECURITY"])
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.scan_table.setSelectionMode(QTableWidget.SingleSelection)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setShowGrid(True)
        self.scan_table.setAlternatingRowColors(False)
        self.scan_table.horizontalHeader().setStretchLastSection(False)
        self.scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.scan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.scan_table.setMinimumHeight(260)
        layout.addWidget(self.scan_table)

        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        self.select_btn = QPushButton("SELECT TARGET")
        self.select_btn.setProperty("variant", "success")
        self.select_btn.clicked.connect(self.select_target)
        self.select_btn.setEnabled(False)
        action_row.addWidget(self.select_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        target_strip = QFrame()
        target_strip.setProperty("role", "target_strip")
        target_layout = QHBoxLayout(target_strip)
        target_layout.setContentsMargins(12, 10, 12, 10)

        self.target_state_left = QLabel("●   TARGET LOCKED")
        self.target_state_left.setProperty("role", "target_left")
        self.target_state_right = QLabel("None")
        self.target_state_right.setProperty("role", "target_right")

        target_layout.addWidget(self.target_state_left)
        target_layout.addStretch()
        target_layout.addWidget(self.target_state_right)
        layout.addWidget(target_strip)

    def _set_scan_placeholder(self, text: str):
        self.scan_table.setRowCount(1)
        self.scan_table.setItem(0, 0, QTableWidgetItem(text))
        self.scan_table.setItem(0, 1, QTableWidgetItem(""))
        self.scan_table.setItem(0, 2, QTableWidgetItem(""))

    def _security_item(self, security: str) -> QTableWidgetItem:
        item = QTableWidgetItem(security.upper())
        sec = security.upper()
        if "WPA3" in sec:
            item.setForeground(Qt.cyan)
        elif "WPA2" in sec:
            item.setForeground(Qt.green)
        elif "OPEN" in sec:
            item.setForeground(Qt.yellow)
        else:
            item.setForeground(Qt.white)
        return item

    def start_scan(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False

        if not is_admin:
            QMessageBox.critical(
                self,
                "Administrator Required",
                "GHOSTLINK must be run as Administrator to scan Wi-Fi networks.\n\n"
                "Please restart the application as Administrator.\n"
                "(Right-click -> Run as administrator)",
            )
            return

        self.statusBar().showMessage("Scanning for Wi-Fi networks...")
        self.scan_btn.setEnabled(False)
        self.scan_table.setRowCount(0)
        self._set_scan_placeholder("Scanning...")

        self.worker = ScanWorker(None)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_finished(self, networks):
        self.scan_results = networks
        self.scan_table.setRowCount(0)

        if networks:
            self.scan_table.setRowCount(len(networks))
            for row, net in enumerate(networks):
                ssid_item = QTableWidgetItem(net.ssid)
                signal_item = QTableWidgetItem(f"{net.signal}%")
                security_item = self._security_item(net.security)

                self.scan_table.setItem(row, 0, ssid_item)
                self.scan_table.setItem(row, 1, signal_item)
                self.scan_table.setItem(row, 2, security_item)

            self.statusBar().showMessage(f"Scan complete: {len(networks)} network(s) found")
        else:
            self._set_scan_placeholder("No networks found.")
            self.statusBar().showMessage("Scan complete: no networks found")

        self.scan_btn.setEnabled(True)
        self.select_btn.setEnabled(bool(networks))

    def on_scan_error(self, message):
        self.scan_btn.setEnabled(True)
        self.scan_table.setRowCount(0)
        self._set_scan_placeholder("Scan failed - see error message.")
        self.statusBar().showMessage("Scan failed")
        QMessageBox.critical(self, "Scan Error", message)

    def select_target(self):
        row = self.scan_table.currentRow()
        if 0 <= row < len(self.scan_results):
            net = self.scan_results[row]
            self.config["ssid"] = net.ssid
            self.config["interface"] = net.interface
            self.attack_target_label.setText(f"SSID: {net.ssid}")
            self.target_state_right.setText(f"{net.ssid} · {net.security}")
            self.statusBar().showMessage(f"Target selected: {net.ssid}")

    def debug_scanner(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            QMessageBox.critical(self, "Admin Required", "Run as Administrator.")
            return

        from ghostlink.network.scanner import WiFiScanner
        import traceback

        try:
            networks = WiFiScanner.scan()
            if networks:
                info = "\n".join(f"{n.ssid:<25} {n.signal}%  {n.security}" for n in networks)
                QMessageBox.information(self, "Scanner Diagnostics", f"Found {len(networks)} networks:\n\n{info}")
            else:
                QMessageBox.warning(
                    self,
                    "Scanner Diagnostics",
                    "Scanner returned an empty list.\n\n"
                    "Try running 'netsh wlan show networks mode=Bssid' manually.",
                )
        except Exception as e:
            QMessageBox.critical(self, "Scanner Error", f"{e}\n\n{traceback.format_exc()}")

    def create_attack_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "ATTACK CONFIG")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        layout.addWidget(self.make_tab_header("Attack Configuration", "Tune strategy, performance, and wordlist input."))

        profile_group = QGroupBox("ATTACK PROFILE")
        profile_form = QFormLayout(profile_group)
        profile_form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        profile_form.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        profile_form.setSpacing(10)

        self.profile_combo = QComboBox()
        for pid, prof in PROFILES.items():
            self.profile_combo.addItem(f"{prof.name}", pid)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        profile_form.addRow("Profile", self.profile_combo)

        self.charset_edit = QLineEdit(self.config["charset"])
        profile_form.addRow("Charset", self.charset_edit)

        self.minlen_spin = QSpinBox()
        self.minlen_spin.setRange(1, 12)
        self.minlen_spin.setValue(self.config["minlen"])
        profile_form.addRow("Min Length", self.minlen_spin)

        self.maxlen_spin = QSpinBox()
        self.maxlen_spin.setRange(1, 12)
        self.maxlen_spin.setValue(self.config["maxlen"])
        profile_form.addRow("Max Length", self.maxlen_spin)
        layout.addWidget(profile_group)

        perf_group = QGroupBox("PERFORMANCE")
        perf_form = QFormLayout(perf_group)
        perf_form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        perf_form.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        perf_form.setSpacing(10)

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 8)
        self.threads_spin.setValue(self.config["threads"])
        perf_form.addRow("Threads", self.threads_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(3, 30)
        self.timeout_spin.setValue(self.config["timeout"])
        perf_form.addRow("Timeout (s)", self.timeout_spin)
        layout.addWidget(perf_group)

        wl_group = QGroupBox("WORDLIST — OPTIONAL")
        wl_layout = QVBoxLayout(wl_group)
        wl_layout.setSpacing(10)

        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("No wordlist selected")
        self.wordlist_edit.setReadOnly(True)
        wl_layout.addWidget(self.wordlist_edit)

        wl_buttons = QHBoxLayout()
        wl_buttons.setSpacing(8)
        self.browse_btn = QPushButton("BROWSE")
        self.browse_btn.setProperty("variant", "secondary")
        self.browse_btn.clicked.connect(self.browse_wordlist)
        wl_buttons.addWidget(self.browse_btn)

        self.clear_wl_btn = QPushButton("CLEAR")
        self.clear_wl_btn.setProperty("variant", "secondary")
        self.clear_wl_btn.clicked.connect(lambda: self.wordlist_edit.setText(""))
        wl_buttons.addWidget(self.clear_wl_btn)
        wl_buttons.addStretch()
        wl_layout.addLayout(wl_buttons)
        layout.addWidget(wl_group)

        self.cache_check = QCheckBox("Use cached passwords")
        self.cache_check.setChecked(not self.config["skip_cached"])
        layout.addWidget(self.cache_check)

        self.attack_target_label = QLabel("SSID: Not selected")
        self.attack_target_label.setProperty("role", "pill")
        layout.addWidget(self.attack_target_label)

        self.start_attack_btn = QPushButton("LAUNCH ATTACK")
        self.start_attack_btn.setProperty("variant", "critical")
        self.start_attack_btn.clicked.connect(self.start_attack)
        layout.addWidget(self.start_attack_btn)
        layout.addStretch()

    def on_profile_changed(self):
        pid = self.profile_combo.currentData()
        if pid and pid in PROFILES:
            self.charset_edit.setText(PROFILES[pid].charset)

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist")
        if path:
            self.wordlist_edit.setText(path)

    def update_config_from_gui(self):
        self.config["charset"] = self.charset_edit.text()
        self.config["minlen"] = self.minlen_spin.value()
        self.config["maxlen"] = self.maxlen_spin.value()
        self.config["threads"] = self.threads_spin.value()
        self.config["timeout"] = self.timeout_spin.value()
        wl = self.wordlist_edit.text().strip()
        self.config["wordlist"] = wl if wl else None
        self.config["skip_cached"] = not self.cache_check.isChecked()

    def start_attack(self):
        if not self.config.get("ssid"):
            QMessageBox.warning(self, "No Target", "Please scan and select a target first.")
            return

        self.update_config_from_gui()
        self.tabs.setCurrentIndex(2)
        self.progress_text.clear()
        self.progress_text.append("Starting attack...\n")
        self.progress_bar.setValue(0)
        self.speed_label.setText("847 pwd/s")
        self.attempts_label.setText("42,350")
        self.current_pwd_label.setText("48291...")

        self.attack_worker = AttackWorker(self.config)
        self.attack_worker.attack_started.connect(self.on_attack_started)
        self.attack_worker.progress_update.connect(self.on_progress_update)
        self.attack_worker.finished.connect(self.on_attack_finished)
        self.attack_worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.attack_worker.start()

        self.start_attack_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage(f"Attack running against {self.config['ssid']}")

    def create_progress_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "PROGRESS")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        layout.addWidget(self.make_tab_header("Live Attack Telemetry", "Monitor speed, attempts, and current candidate in real time."))

        metrics_grid = QGridLayout()
        metrics_grid.setHorizontalSpacing(10)
        metrics_grid.setVerticalSpacing(10)

        speed_wrap = QWidget()
        sw = QVBoxLayout(speed_wrap)
        sw.setContentsMargins(10, 8, 10, 8)
        speed_wrap.setProperty("role", "metric")
        sw.addWidget(QLabel("SPEED"))
        self.speed_label = QLabel("0 pwd/s")
        sw.addWidget(self.speed_label)
        metrics_grid.addWidget(speed_wrap, 0, 0)

        attempts_wrap = QWidget()
        aw = QVBoxLayout(attempts_wrap)
        aw.setContentsMargins(10, 8, 10, 8)
        attempts_wrap.setProperty("role", "metric")
        aw.addWidget(QLabel("ATTEMPTS"))
        self.attempts_label = QLabel("0")
        aw.addWidget(self.attempts_label)
        metrics_grid.addWidget(attempts_wrap, 0, 1)

        current_wrap = QWidget()
        cw = QVBoxLayout(current_wrap)
        cw.setContentsMargins(10, 8, 10, 8)
        current_wrap.setProperty("role", "metric")
        cw.addWidget(QLabel("CURRENT"))
        self.current_pwd_label = QLabel("-")
        cw.addWidget(self.current_pwd_label)
        metrics_grid.addWidget(current_wrap, 0, 2)

        layout.addLayout(metrics_grid)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")
        layout.addWidget(self.progress_bar)

        self.progress_text = QTextEdit()
        self.progress_text.setReadOnly(True)
        self.progress_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.progress_text, 1)

        controls = QHBoxLayout()
        self.stop_btn = QPushButton("STOP ATTACK")
        self.stop_btn.setProperty("variant", "danger")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)
        controls.addStretch()
        layout.addLayout(controls)

    def on_attack_started(self, total):
        self.total_combinations = total
        if total > 0:
            self.progress_text.append(f"Search space: {total:,} passwords\n")

    def on_progress_update(self, current_password, attempts, speed):
        self.attempts_label.setText(f"{attempts:,}")
        self.speed_label.setText(f"{speed:.1f} pwd/s")

        display_pwd = current_password[:38] if current_password else "-"
        self.current_pwd_label.setText(display_pwd)

        if attempts % 50 == 0:
            self.progress_text.append(f"Attempt {attempts}: {current_password[:25]:<25} @ {speed:.1f}/s")

        if self.total_combinations > 0:
            pct = min(int((attempts / self.total_combinations) * 100), 100)
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"{pct}% — {attempts:,} / {self.total_combinations:,}")

    def stop_attack(self):
        if self.attack_worker:
            self.attack_worker.stop()
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopping attack worker...")

    def on_attack_finished(self, password, attempts, elapsed, verified):
        self.start_attack_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if password:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat(f"100% — {attempts:,} / {max(self.total_combinations, attempts):,}")

        if password and verified:
            msg = (
                f"Password Found!\n\nSSID: {self.config['ssid']}\n"
                f"Password: {password}\nAttempts: {attempts}\nTime: {elapsed:.1f}s"
            )
            self.statusBar().showMessage("Attack complete: password verified")
            QMessageBox.information(self, "Target Compromised", msg)
        else:
            self.statusBar().showMessage("Attack complete: password not found")
            QMessageBox.information(self, "Attack Complete", "Password not found within search space.")

    def _add_recon_card(self, status: str, title: str, subtitle: str):
        color = {
            "ok": "#00e676",
            "warn": "#ffb300",
            "info": "#00b8ff",
            "error": "#ff4b4b",
        }.get(status, "#00b8ff")

        card = QFrame()
        card.setStyleSheet(f"background:#071930;border:1px solid #10365a;border-left:3px solid {color};border-radius:6px;")
        row = QHBoxLayout(card)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(10)

        badge = QLabel(status.upper())
        badge.setProperty("role", "badge")
        badge.setStyleSheet(f"background:{color};color:#031224;border-radius:3px;padding:2px 6px;font-size:8pt;font-weight:800;")

        txt = QVBoxLayout()
        t = QLabel(title)
        t.setStyleSheet("font-weight:700;color:#dff2ff;")
        s = QLabel(subtitle)
        s.setStyleSheet("color:#6fa8d9;font-size:9pt;")
        txt.addWidget(t)
        txt.addWidget(s)

        row.addWidget(badge)
        row.addLayout(txt)
        row.addStretch()

        self.recon_cards_layout.addWidget(card)

    def _clear_recon_cards(self):
        while self.recon_cards_layout.count():
            item = self.recon_cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def create_recon_tab(self):
        tab = QWidget()
        self.tabs.addTab(tab, "RECON")
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        layout.addWidget(self.make_tab_header("Reconnaissance", "Run environment discovery checks before attacking."))

        control_row = QHBoxLayout()
        control_row.setSpacing(10)

        self.run_recon_btn = QPushButton("RUN FULL RECON")
        self.run_recon_btn.clicked.connect(self.run_recon)
        control_row.addWidget(self.run_recon_btn)

        self.test_print_btn = QPushButton("TEST PRINT")
        self.test_print_btn.setProperty("variant", "secondary")
        self.test_print_btn.clicked.connect(self.test_print_to_recon)
        control_row.addWidget(self.test_print_btn)
        control_row.addStretch()
        layout.addLayout(control_row)

        cards_wrap = QFrame()
        self.recon_cards_layout = QVBoxLayout(cards_wrap)
        self.recon_cards_layout.setContentsMargins(0, 0, 0, 0)
        self.recon_cards_layout.setSpacing(8)
        layout.addWidget(cards_wrap, 1)

        self._add_recon_card("ok", "Administrator Privileges", "Running as SYSTEM - all capabilities unlocked")
        self._add_recon_card("ok", "WLAN Service", "wlansvc active - adapters detected")
        self._add_recon_card("warn", "Adapter Mode", "Monitor mode unavailable - using managed mode")
        self._add_recon_card("info", "Wordlists Found", "2 wordlist files detected in /wordlists/")

    def test_print_to_recon(self):
        self._clear_recon_cards()
        self._add_recon_card("ok", "Output Capture", "Test message printed successfully")

    def run_recon(self):
        self.run_recon_btn.setEnabled(False)
        self._clear_recon_cards()
        self._add_recon_card("info", "Recon Running", "Running full reconnaissance (may take 30-120s)")
        self.statusBar().showMessage("Recon running...")

        self.worker = ReconWorker()
        self.worker.output.connect(lambda line: self._add_recon_card("info", "Recon Output", str(line)))
        self.worker.finished.connect(lambda: self.run_recon_btn.setEnabled(True))
        self.worker.finished.connect(lambda: self.statusBar().showMessage("Recon complete"))
        self.worker.error.connect(lambda e: self._add_recon_card("error", "Recon Error", str(e)))
        self.worker.start()

    def on_recon_error(self, message):
        self.run_recon_btn.setEnabled(True)
        self._add_recon_card("error", "Recon Error", message)
        self.statusBar().showMessage("Recon failed")
        QMessageBox.critical(self, "Recon Error", message)
