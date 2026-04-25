"""
GHOSTLINK Progress Tracker
===========================
Attack progress estimation and tracking.
"""

from datetime import timedelta
from typing import Dict

from ..core.utils import format_number

class ProgressTracker:
    """Track and estimate attack progress"""
    
    def __init__(self, total_combinations: int):
        self.total = total_combinations
        self.attempted = 0
        self.start_time = 0.0
    
    def update(self, attempts: int, elapsed: float) -> Dict:
        """Update progress and return stats"""
        self.attempted = attempts
        
        if self.total == 0:
            return self._empty_stats()
        
        progress = (attempts / self.total) * 100
        speed = attempts / max(elapsed, 0.1)
        
        # Estimate remaining time
        remaining_attempts = self.total - attempts
        if speed > 0:
            eta_seconds = remaining_attempts / speed
            eta = str(timedelta(seconds=int(eta_seconds)))
        else:
            eta = "Unknown"
        
        return {
            "progress": min(progress, 100),
            "attempted": attempts,
            "total": self.total,
            "speed": speed,
            "eta": eta,
            "elapsed": str(timedelta(seconds=int(elapsed))),
        }
    
    def _empty_stats(self) -> Dict:
        return {
            "progress": 0,
            "attempted": 0,
            "total": 0,
            "speed": 0,
            "eta": "N/A",
            "elapsed": "0:00:00",
        }
    
    @staticmethod
    def display(stats: Dict) -> None:
        """Display progress bar"""
        progress = stats["progress"]
        bar_width = 40
        filled = int(bar_width * progress / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        print(f"\rProgress: [{bar}] {progress:.1f}% | "
              f"{format_number(stats['attempted'])}/{format_number(stats['total'])} | "
              f"ETA: {stats['eta']}", end="", flush=True)