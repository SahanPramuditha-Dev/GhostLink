#!/usr/bin/env python3
"""Test all imports"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

print("Testing imports...")

try:
    from ghostlink.core.colors import C
    print("✓ ghostlink.core.colors")
except Exception as e:
    print(f"✗ ghostlink.core.colors: {e}")

try:
    from ghostlink.core.utils import is_admin
    print("✓ ghostlink.core.utils")
except Exception as e:
    print(f"✗ ghostlink.core.utils: {e}")

try:
    from ghostlink.core.constants import SCRIPT_VERSION
    print("✓ ghostlink.core.constants")
except Exception as e:
    print(f"✗ ghostlink.core.constants: {e}")

try:
    from ghostlink.engine.profiles import PROFILES
    print("✓ ghostlink.engine.profiles")
except Exception as e:
    print(f"✗ ghostlink.engine.profiles: {e}")

try:
    from ghostlink.network.scanner import WiFiScanner
    print("✓ ghostlink.network.scanner")
except Exception as e:
    print(f"✗ ghostlink.network.scanner: {e}")

try:
    from ghostlink.network.connector import WiFiConnector
    print("✓ ghostlink.network.connector")
except Exception as e:
    print(f"✗ ghostlink.network.connector: {e}")

try:
    from ghostlink.storage.vault import PasswordVault
    print("✓ ghostlink.storage.vault")
except Exception as e:
    print(f"✗ ghostlink.storage.vault: {e}")

try:
    from ghostlink.cli.menu import InteractiveMenu
    print("✓ ghostlink.cli.menu")
except Exception as e:
    print(f"✗ ghostlink.cli.menu: {e}")

try:
    from ghostlink.engine.attack import BruteForceEngine
    print("✓ ghostlink.engine.attack")
except Exception as e:
    print(f"✗ ghostlink.engine.attack: {e}")

print("\nImport test complete!")