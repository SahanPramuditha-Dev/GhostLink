"""
GHOSTLINK Spinner Animation
============================
Animated terminal spinner for loading states.
"""

import sys
import threading
import time

from ..core.colors import C

class Spinner:
    """Terminal spinner animation"""
    
    def __init__(self, message: str = "Loading..."):
        self.message = message
        self._stop = threading.Event()
        self._thread = None
        self._chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def start(self, message: str = None):
        """Start spinner animation"""
        if message:
            self.message = message
        
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    
    def stop(self, final_message: str = None):
        """Stop spinner animation"""
        self._stop.set()
        
        if self._thread:
            self._thread.join(timeout=1)
        
        # Clear spinner line
        sys.stdout.write("\r" + " " * 80 + "\r")
        
        if final_message:
            sys.stdout.write(f"{C.GHOST_CYAN}[✓]{C.RESET} {final_message}\n")
        
        sys.stdout.flush()
    
    def update(self, message: str):
        """Update spinner message"""
        self.message = message
    
    def _spin(self):
        """Spin animation loop"""
        idx = 0
        while not self._stop.is_set():
            char = self._chars[idx % len(self._chars)]
            sys.stdout.write(
                f"\r{C.GHOST_CYAN}[{char}]{C.RESET} {self.message}  "
            )
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
    
    def __enter__(self):
        """Context manager: start spinner"""
        self.start()
        return self
    
    def __exit__(self, *args):
        """Context manager: stop spinner"""
        self.stop()