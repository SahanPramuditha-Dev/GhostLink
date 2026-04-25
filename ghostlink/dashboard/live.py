"""
GHOSTLINK Live Dashboard
=========================
Real-time attack progress display.
"""

import sys
import threading
import time
from typing import Dict

from ..core.colors import C

class LiveDashboard:
    """Real-time attack dashboard"""
    
    def __init__(self, state):
        self.state = state
        self.stop_flag = threading.Event()
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def start(self):
        """Start dashboard display thread"""
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
    
    def stop(self):
        """Stop dashboard"""
        self.stop_flag.set()
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
    
    def _run(self):
        """Main dashboard loop"""
        idx = 0
        while not self.stop_flag.is_set():
            if self.state.attempts > 0:
                spinner = self.spinner_chars[idx % len(self.spinner_chars)]
                pwd = self.state.current_password[:30]
                attempts = self.state.attempts
                speed = self.state.speed
                
                status_line = (
                    f"\r{C.GHOST_CYAN}{spinner}{C.RESET} "
                    f"Trying: {C.GHOST_WHITE}{pwd:<30}{C.RESET} | "
                    f"Attempts: {attempts:<8} | "
                    f"Speed: {speed:.1f}/s"
                )
                
                sys.stdout.write(status_line)
                sys.stdout.flush()
            
            idx += 1
            time.sleep(0.1)