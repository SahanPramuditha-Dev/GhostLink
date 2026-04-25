"""
GHOSTLINK Wi-Fi Connector (Strict Verification)
================================================
Forces a clean state – deletes old profile, connects, and confirms DHCP IP.
"""

import platform
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..core.utils import run_cmd
from ..core.colors import C


class WiFiConnector:
    def __init__(self):
        self.system = platform.system()

    def connect(self, ssid: str, password: str, timeout: int = 10,
                cleanup: bool = True) -> bool:
        if self.system == "Windows":
            return self._connect_windows(ssid, password, timeout, cleanup)
        elif self.system == "Linux":
            return self._connect_linux(ssid, password, timeout, cleanup)
        else:
            print(f"{C.RED}[!] Unsupported platform: {self.system}{C.RESET}")
            return False

    def is_connected(self, ssid: str) -> bool:
        if self.system == "Windows":
            return self._is_connected_windows(ssid)
        return False

    def disconnect(self) -> None:
        if self.system == "Windows":
            run_cmd(["netsh", "wlan", "disconnect"], timeout=5)
            time.sleep(1)

    def has_valid_ip(self, interface_name: str = "Wi-Fi") -> bool:
        """Check if the interface has a routable IPv4 address."""
        if self.system == "Windows":
            res = run_cmd(["netsh", "interface", "ip", "show", "addresses",
                           interface_name], timeout=5)
            if res.returncode != 0:
                return False
            for line in res.stdout.splitlines():
                if "IP Address" in line and "169.254" not in line and "0.0.0.0" not in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if ip and not ip.startswith("169.254"):
                            return True
            return False
        return True  # skip on Linux for now

    def _delete_profile(self, ssid: str) -> None:
        """Remove any existing profile for this SSID."""
        run_cmd(["netsh", "wlan", "delete", "profile", f"name={ssid}"], timeout=3)

    # ------------------------------------------------------------------
    # Windows connection
    # ------------------------------------------------------------------
    def _connect_windows(self, ssid: str, password: str, timeout: int,
                         cleanup: bool) -> bool:
        # 1. Disconnect from current network and delete any old profile
        self.disconnect()
        self._delete_profile(ssid)          # *** ENSURE CLEAN SLATE ***

        # 2. Create new XML profile
        xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        tmp = Path(tempfile.mktemp(suffix=".xml"))
        tmp.write_text(xml, encoding="utf-8")

        try:
            # 3. Add profile
            add_res = run_cmd(
                ["netsh", "wlan", "add", "profile", f"filename={tmp}"],
                timeout=5,
            )
            if add_res.returncode != 0:
                err = add_res.stderr.strip() or add_res.stdout.strip()
                print(f"    {C.RED}[✗] Add profile failed:{C.RESET} {err[:200]}")
                return False

            # 4. Connect
            connect_res = run_cmd(
                ["netsh", "wlan", "connect", f"name={ssid}"],
                timeout=5,
            )
            if connect_res.returncode != 0:
                err = connect_res.stderr.strip() or connect_res.stdout.strip()
                print(f"    {C.RED}[✗] Connect failed:{C.RESET} {err[:200]}")
                return False

            # 5. Wait for valid IP
            for _ in range(timeout):
                time.sleep(1)
                if self._is_connected_windows(ssid) and self.has_valid_ip():
                    return True

            print(f"    {C.YELLOW}[!] Timeout – connected={self._is_connected_windows(ssid)}, IP={self.has_valid_ip()}{C.RESET}")
            return False

        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass
            if cleanup:
                run_cmd(
                    ["netsh", "wlan", "delete", "profile", f"name={ssid}"],
                    timeout=3,
                )

    def _is_connected_windows(self, ssid: str) -> bool:
        res = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=5)
        if res.returncode != 0:
            return False
        current_ssid = None
        state_connected = False
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if "SSID" in stripped and "BSSID" not in stripped:
                parts = stripped.split(":", 1)
                if len(parts) > 1:
                    current_ssid = parts[1].strip()
            elif "State" in stripped:
                if "connected" in stripped.lower():
                    state_connected = True
        return (current_ssid and current_ssid.lower() == ssid.lower() and state_connected)

    # ------------------------------------------------------------------
    # Linux (unchanged)
    # ------------------------------------------------------------------
    def _connect_linux(self, ssid: str, password: str, timeout: int,
                       cleanup: bool) -> bool:
        cmd = [
            "nmcli", "device", "wifi", "connect", ssid,
            "password", password,
            "timeout", str(timeout),
        ]
        res = run_cmd(cmd, timeout=timeout + 5)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            print(f"    {C.RED}[✗] nmcli connect failed:{C.RESET} {err[:200]}")
            return False
        return "successfully activated" in res.stdout.lower()