"""
GHOSTLINK Utilities
====================
Core utility functions.
"""

import platform
import subprocess
import os
import sys
from typing import List, Tuple

from .colors import C

def is_admin() -> bool:
    """Check if running with administrator/root privileges"""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def run_cmd(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Execute system command with timeout"""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "Timeout")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, -1, "", f"Command not found: {cmd[0]}")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, -1, "", str(e))

def clear_terminal() -> None:
    """Clear terminal screen"""
    os.system("cls" if os.name == "nt" else "clear")

def get_terminal_size() -> Tuple[int, int]:
    """Get terminal dimensions"""
    try:
        return os.get_terminal_size()
    except Exception:
        return 120, 40

def format_number(n: int) -> str:
    """Format large numbers with suffixes"""
    if n < 1000:
        return str(n)
    elif n < 1_000_000:
        return f"{n/1_000:.1f}K"
    elif n < 1_000_000_000:
        return f"{n/1_000_000:.1f}M"
    elif n < 1_000_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    else:
        return f"{n/1_000_000_000_000:.1f}T"

def human_bytes(b: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f}{unit}"
        b /= 1024
    return f"{b:.2f}PB"

def check_privileges() -> bool:
    """Check and warn about privileges"""
    if not is_admin():
        print(f"{C.warning('[!] Administrator/root privileges recommended')}")
        print(f"{C.info('[i] Run as Administrator for full functionality')}")
        return False
    return True