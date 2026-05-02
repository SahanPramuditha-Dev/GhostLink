import itertools
from typing import Iterator, List

CHAR_MAP = {
    'd': '0123456789',
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    's': '!@#$%^&*()_+-=[]{}|;:,.<>?',
    'a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
}

def mask_generator(mask: str) -> Iterator[str]:
    """Generate passwords based on a mask, e.g., '?d?d?d?l?l'."""
    charsets: List[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            key = mask[i + 1].lower()
            if key in CHAR_MAP:
                charsets.append(CHAR_MAP[key])
                i += 2
                continue
        charsets.append(mask[i])
        i += 1

    for combo in itertools.product(*charsets):
        yield ''.join(combo)