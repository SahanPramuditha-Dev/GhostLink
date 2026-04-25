"""
GHOSTLINK Report Generator
===========================
Generate attack summary reports.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..core.constants import DEFAULT_REPORT

class ReportGenerator:
    """Attack report generator"""
    
    @staticmethod
    def generate(
        config: Dict,
        password: str,
        attempts: int,
        elapsed: float,
        verified: bool = True,
        output_path: Path = DEFAULT_REPORT
    ) -> None:
        """Generate JSON report"""
        
        report = {
            "tool": "GHOSTLINK",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "target": {
                "ssid": config.get("ssid", "Unknown"),
                "security": config.get("security", "Unknown"),
            },
            "attack": {
                "charset_size": len(config.get("charset", "")),
                "length_range": f"{config.get('minlen', 0)}-{config.get('maxlen', 0)}",
                "threads": config.get("threads", 0),
                "timeout": config.get("timeout", 0),
                "wordlist": str(config.get("wordlist", "None")),
            },
            "result": {
                "password": password if verified else "Not verified",
                "attempts": attempts,
                "elapsed_seconds": round(elapsed, 2),
                "speed": round(attempts / max(elapsed, 0.001), 2),
                "verified": verified,
            }
        }
        
        try:
            output_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            print(f"[✓] Report saved: {output_path}")
        except Exception as e:
            print(f"[!] Report error: {e}")
    
    @staticmethod
    def display_summary(password: str, attempts: int, elapsed: float,
                       verified: bool, ssid: str) -> None:
        """Display attack summary"""
        from ..core.colors import C
        
        print()
        if password and verified:
            print(f"{C.GHOST_GREEN}{'═'*60}{C.RESET}")
            print(f"{C.GHOST_GREEN}  ✅ TARGET COMPROMISED{C.RESET}")
            print(f"{C.GHOST_GREEN}{'═'*60}{C.RESET}")
        else:
            print(f"{C.GHOST_RED}{'═'*60}{C.RESET}")
            print(f"{C.GHOST_RED}  Attack Complete - Not Found{C.RESET}")
            print(f"{C.GHOST_RED}{'═'*60}{C.RESET}")
        
        print(f"  SSID:      {ssid}")
        if password:
            print(f"  Password:  {C.GHOST_GREEN}{password}{C.RESET}")
        print(f"  Attempts:  {attempts:,}")
        print(f"  Time:      {elapsed:.1f}s")
        if elapsed > 0:
            print(f"  Speed:     {attempts/elapsed:.1f} pwd/s")
        print(f"  Verified:  {'Yes' if verified else 'No'}")