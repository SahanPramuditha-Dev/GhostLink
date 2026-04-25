#!/usr/bin/env python3
"""
GHOSTLINK - Wi-Fi Security Testing Framework
=============================================
Simple launcher script.
Run this file directly: python run.py
"""

import sys
import os

# Ensure we can import from the ghostlink package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghostlink.main import main

if __name__ == "__main__":
    main()