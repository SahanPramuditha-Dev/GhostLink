import io, sys, os, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from PySide6.QtCore import QThread, Signal

from ghostlink.network.scanner import WiFiScanner
from ghostlink.engine.attack import BruteForceEngine, shared_state
from ghostlink.storage.vault import PasswordVault
from ghostlink.core.constants import VAULT_PATH

class ScanWorker(QThread):
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface

    def run(self):
        try:
            scanner = WiFiScanner()
            networks = scanner.scan(self.interface)
            self.finished.emit(networks)
        except Exception as e:
            self.error.emit(str(e))


class AttackWorker(QThread):
    finished = Signal(str, int, float, bool)   # password, attempts, elapsed, verified
    error = Signal(str)
    progress_update = Signal(str, int, float)  # current_password, attempts, speed
    attack_started = Signal(int)               # total_combinations

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.vault = PasswordVault(VAULT_PATH)
        self.vault.load()
        self.stop_requested = False
        self._monitor_thread = None
        self._stop_monitor = threading.Event()

    def stop(self):
        self.stop_requested = True
        self._stop_monitor.set()

    def run(self):
        # ---- calculate total search space ----
        charset = self.config["charset"]
        min_len = self.config["minlen"]
        max_len = self.config["maxlen"]
        if "?" in charset:
            total = 0   # mask, can't estimate
        else:
            total = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        self.attack_started.emit(total)

        # ---- start a monitor thread that reads the shared state ----
        self._stop_monitor.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

        # ---- run the attack ----
        try:
            engine = BruteForceEngine(self.config, self.vault)
            pwd, attempts, elapsed, verified = engine.execute()
            self._stop_monitor.set()
            self.finished.emit(pwd or "", attempts, elapsed, verified)
        except Exception as e:
            self._stop_monitor.set()
            self.error.emit(str(e))

    def _monitor_loop(self):
        """Emit progress every 0.5 seconds using the global shared_state."""
        while not self._stop_monitor.is_set():
            with shared_state.lock:
                pwd = shared_state.current_password or ""
                attempts = shared_state.attempts
                speed = shared_state.speed
            self.progress_update.emit(pwd, attempts, speed)
            time.sleep(0.5)


class ReconWorker(QThread):
    output = Signal(str)
    finished = Signal()
    error = Signal(str)

    def __init__(self, module_func=None):
        super().__init__()
        self.module_func = module_func

    def run(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            from ghostlink.network.recon import full_network_recon, print_recon_result
            result = full_network_recon()
            print_recon_result(result)
            captured = sys.stdout.getvalue()
            sys.stdout = old_stdout
            self.output.emit(captured)
            self.finished.emit()
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            captured = sys.stdout.getvalue()
            sys.stdout = old_stdout
            self.output.emit(captured + f"\n--- ERROR ---\n{e}\n\n{tb}")
            self.finished.emit()