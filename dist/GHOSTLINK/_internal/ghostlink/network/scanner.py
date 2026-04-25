"""
GHOSTLINK Wi-Fi Scanner
========================
Network scanning and detection.
"""

import re
from typing import List, Optional
from dataclasses import dataclass

from ..core.utils import run_cmd

@dataclass
class ScanResult:
    """Wi-Fi network scan result"""
    ssid: str
    bssid: str
    signal: int
    security: str
    hidden: bool
    interface: str
    channel: int = 0

class WiFiScanner:
    """Wi-Fi network scanner"""
    
    @staticmethod
    def scan(interface: Optional[str] = None) -> List[ScanResult]:
        """Scan for available networks"""
        import platform
        
        if platform.system() == "Windows":
            return WiFiScanner._scan_windows(interface)
        elif platform.system() == "Linux":
            return WiFiScanner._scan_linux(interface)
        else:
            print(f"[!] Unsupported platform: {platform.system()}")
            return []
    
    @staticmethod
    def _scan_windows(interface: Optional[str] = None) -> List[ScanResult]:
        """Windows network scanning"""
        # Build the command correctly – always use mode=bssid
        cmd = ["netsh", "wlan", "show", "networks", "mode=Bssid"]
        if interface:
            # Proper way to pass interface name to netsh
            cmd.append(f'interface="{interface}"')
        
        res = run_cmd(cmd, timeout=15)
        if res.returncode != 0:
            error_msg = res.stderr.strip() or res.stdout.strip() or "Unknown error (no output)"
            raise RuntimeError(
                f"Wi‑Fi scan failed.\n\n{error_msg}\n\n"
                "Run as Administrator and ensure Wi‑Fi is enabled."
            )
        
        networks = []
        current: Optional[ScanResult] = None
        
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                current = None
                continue
            
            # Detect a new SSID line
            if line.lower().startswith("ssid") and "bssid" not in line.lower():
                try:
                    ssid = line.split(":", 1)[1].strip()
                    if ssid:   # only add non-empty SSIDs
                        current = ScanResult(
                            ssid=ssid, bssid="", signal=0,
                            security="Unknown", hidden=False,
                            interface=interface or "Wi-Fi"
                        )
                        networks.append(current)
                except:
                    pass
            elif current:
                try:
                    if "signal" in line.lower():
                        match = re.search(r"(\d+)%?", line)
                        if match:
                            current.signal = int(match.group(1))
                    elif "authentication" in line.lower():
                        current.security = line.split(":", 1)[1].strip()
                    elif "bssid" in line.lower():
                        current.bssid = line.split(":", 1)[1].strip()
                    elif "channel" in line.lower():
                        match = re.search(r"(\d+)", line)
                        if match:
                            current.channel = int(match.group(1))
                    elif "radio type" in line.lower():
                        # not stored, but could be
                        pass
                except:
                    pass
        
        # Sort by signal strength descending
        return sorted(networks, key=lambda x: x.signal, reverse=True)
    
    @staticmethod
    def _scan_linux(interface: Optional[str] = None) -> List[ScanResult]:
        """Linux network scanning"""
        if not interface:
            interface = WiFiScanner._get_interface_linux()
        
        cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY",
               "device", "wifi", "list"]
        res = run_cmd(cmd, timeout=15)
        
        if res.returncode != 0:
            return []
        
        networks = []
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                networks.append(ScanResult(
                    ssid=parts[0] or "<hidden>",
                    bssid=parts[1],
                    signal=int(parts[2]) if parts[2] else 0,
                    security=parts[3] or "Unknown",
                    hidden=(parts[0] == ""),
                    interface=interface,
                ))
        
        return sorted(networks, key=lambda x: x.signal, reverse=True)
    
    @staticmethod
    def _get_interface_linux() -> str:
        """Get default wireless interface on Linux"""
        res = run_cmd(["iw", "dev"], timeout=5)
        match = re.search(r'Interface (\w+)', res.stdout)
        return match.group(1) if match else "wlan0"
    
    @staticmethod
    def display(networks: List[ScanResult], vault=None) -> None:
        """Display scan results"""
        if not networks:
            print("\n[!] No networks found")
            return
        
        print(f"\n[+] Found {len(networks)} networks:\n")
        print(f"  {'#':<4} {'SSID':<30} {'Signal':<15} {'Security':<12}")
        print(f"  {'─'*4} {'─'*30} {'─'*15} {'─'*12}")
        
        for i, net in enumerate(networks, 1):
            bars = "█" * (net.signal // 10) + "░" * (10 - net.signal // 10)
            cached = " 📦" if vault and vault.get(net.ssid) else ""
            hidden = " 👻" if net.hidden else ""
            
            print(f"  {i:<4} {net.ssid:<30} {bars} {net.signal:>3}%  "
                  f"{net.security:<12}{cached}{hidden}")