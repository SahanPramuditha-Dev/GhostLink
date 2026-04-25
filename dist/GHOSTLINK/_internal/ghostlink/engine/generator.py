"""
GHOSTLINK Password Generators
==============================
Smart password generation with charset filtering.
"""

import itertools
from pathlib import Path
from typing import Iterator, List, Set

# Common password patterns (used before brute‑force)
_COMMON_PASSWORDS = [
    "12345678", "password", "123456789", "1234567890",
    "qwerty123", "admin123", "letmein", "welcome",
    "admin", "12345", "qwerty", "123456789",
    "monkey", "dragon", "master", "123123",
    "football", "baseball", "iloveyou", "trustno1",
]

_KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "1q2w3e4r", "qazwsx",
]

class PasswordGenerator:
    """Generates passwords with optional charset filtering."""

    @staticmethod
    def _allowed(password: str, charset: str) -> bool:
        """Return True if all characters of password belong to charset."""
        return set(password).issubset(set(charset))

    @staticmethod
    def common_patterns(charset: str = None) -> Iterator[str]:
        """
        Yield common passwords, optionally filtered by charset.
        If charset is provided, only passwords fully inside that charset are yielded.
        """
        # Basic common passwords
        for pwd in _COMMON_PASSWORDS:
            if charset is None or PasswordGenerator._allowed(pwd, charset):
                yield pwd

        # Keyboard patterns
        for pwd in _KEYBOARD_PATTERNS:
            if charset is None or PasswordGenerator._allowed(pwd, charset):
                yield pwd
                if charset is None or PasswordGenerator._allowed(pwd.capitalize(), charset):
                    yield pwd.capitalize()

        # Variations (base + suffix)
        bases = ["admin", "password", "qwerty", "letmein"]
        suffixes = ["", "123", "1234", "12345", "!", "@", "#"]
        for base in bases:
            for suffix in suffixes:
                candidate = f"{base}{suffix}"
                if charset is None or PasswordGenerator._allowed(candidate, charset):
                    yield candidate
                candidate_cap = f"{base.capitalize()}{suffix}"
                if charset is None or PasswordGenerator._allowed(candidate_cap, charset):
                    yield candidate_cap

    @staticmethod
    def from_wordlist(path: Path, min_len: int, max_len: int,
                      charset: str = None) -> List[str]:
        """Load passwords from wordlist, optionally filtered by charset."""
        words = []
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if not word or not (min_len <= len(word) <= max_len):
                        continue
                    if charset is not None and not PasswordGenerator._allowed(word, charset):
                        continue
                    words.append(word)
            return words
        except Exception as e:
            print(f"Wordlist error: {e}")
            return []

    @staticmethod
    def brute_force(charset: str, min_len: int, max_len: int) -> Iterator[str]:
        """Systematic brute force over the exact charset."""
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    @staticmethod
    def hybrid(charset: str, min_len: int, max_len: int,
               wordlist_path: Path = None) -> Iterator[str]:
        """
        Hybrid attack: patterns → wordlist → brute force.
        All phases respect the chosen charset.
        """
        # Phase 1: Filtered common patterns
        yield from PasswordGenerator.common_patterns(charset)

        # Phase 2: Filtered wordlist
        if wordlist_path and wordlist_path.exists():
            words = PasswordGenerator.from_wordlist(wordlist_path, min_len, max_len, charset)
            yield from words

        # Phase 3: Full brute force on the charset
        yield from PasswordGenerator.brute_force(charset, min_len, max_len)