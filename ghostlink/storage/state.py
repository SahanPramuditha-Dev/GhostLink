"""
GHOSTLINK State Persistence
============================
Save and resume attack progress.
"""

import json
from pathlib import Path
from typing import Dict

from ..core.constants import DEFAULT_STATE

class StateManager:
    """Attack state persistence"""
    
    def __init__(self, path: Path = DEFAULT_STATE):
        self.path = path
    
    def load(self) -> Dict:
        """Load saved state"""
        if not self.path.exists():
            return {"last_pwd": "", "attempts": 0}
        
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"last_pwd": "", "attempts": 0}
    
    def save(self, state: Dict) -> None:
        """Save current state"""
        try:
            self.path.write_text(
                json.dumps(state, indent=2),
                encoding="utf-8"
            )
        except Exception as e:
            print(f"[!] State save error: {e}")
    
    def reset(self) -> None:
        """Reset saved state"""
        self.save({"last_pwd": "", "attempts": 0})