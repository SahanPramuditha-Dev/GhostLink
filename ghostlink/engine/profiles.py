"""
GHOSTLINK Attack Profiles
==========================
Pre-configured attack profiles for different search spaces.
"""

from collections import OrderedDict
from typing import Dict

class AttackProfile:
    """Attack profile definition"""
    
    def __init__(self, name: str, charset: str, icon: str, description: str):
        self.name = name
        self.charset = charset
        self.icon = icon
        self.description = description
        self.size = len(charset)
    
    def __str__(self) -> str:
        return f"{self.icon} {self.name} ({self.size} chars) - {self.description}"

# Pre-defined attack profiles
PROFILES: Dict[str, AttackProfile] = OrderedDict({
    "1": AttackProfile(
        "Numeric",
        "0123456789",
        "🔢",
        "Numbers only - fastest search"
    ),
    "2": AttackProfile(
        "Lowercase",
        "abcdefghijklmnopqrstuvwxyz",
        "🔤",
        "Lowercase letters only"
    ),
    "3": AttackProfile(
        "Uppercase",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "🔠",
        "Uppercase letters only"
    ),
    "4": AttackProfile(
        "Mixed Case",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "🔡",
        "Both cases - balanced"
    ),
    "5": AttackProfile(
        "Alphanumeric",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "🔣",
        "Letters + numbers"
    ),
    "6": AttackProfile(
        "Extended",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
        "💀",
        "Full coverage - slowest"
    ),
    "7": AttackProfile(
        "Symbols",
        "!@#$%^&*()_+-=[]{}|;:',.<>/?",
        "⚡",
        "Symbols only - specialized"
    ),
    "8": AttackProfile(
        "Hexadecimal",
        "0123456789abcdef",
        "🔮",
        "Hex characters - common in tech"
    ),
})

def get_profile(profile_id: str) -> AttackProfile:
    """Get attack profile by ID"""
    return PROFILES.get(profile_id)

def list_profiles() -> None:
    """Display all available profiles"""
    for pid, profile in PROFILES.items():
        print(f"  [{pid}] {profile}")

def estimate_search_space(profile: AttackProfile, min_len: int, max_len: int) -> int:
    """Calculate total combinations for given profile and length range"""
    charset = profile.charset
    return sum(len(charset) ** i for i in range(min_len, max_len + 1))