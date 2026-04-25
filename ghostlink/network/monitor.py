"""
GHOSTLINK Connection Monitor
=============================
Monitor for manual connections and auto-stop.
"""

import threading
import time
from typing import Callable, Optional

from ..network.connector import WiFiConnector

class ConnectionMonitor:
    """Monitor Wi-Fi connection state"""
    
    def __init__(self):
        self.connector = WiFiConnector()
        self._stop = threading.Event()
        self._callback = None
    
    def watch(self, ssid: str, 
              on_connected: Optional[Callable] = None,
              interval: float = 1.0) -> None:
        """
        Watch for connection to specified SSID.
        Calls on_connected when detected.
        """
        self._stop.clear()
        self._callback = on_connected
        
        def _watch_loop():
            while not self._stop.is_set():
                if self.connector.is_connected(ssid):
                    print(f"\n[!] Connection detected to {ssid}")
                    if self._callback:
                        self._callback()
                    break
                time.sleep(interval)
        
        thread = threading.Thread(target=_watch_loop, daemon=True)
        thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self._stop.set()