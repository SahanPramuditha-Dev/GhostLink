import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from pathlib import Path
from ghostlink.engine.generator import PasswordGenerator

def test_common_patterns_filtered_numeric():
    numeric = "0123456789"
    patterns = list(PasswordGenerator.common_patterns(numeric))
    for p in patterns:
        assert set(p).issubset(set(numeric)), f"Non-numeric password: {p}"

def test_brute_force_two_chars():
    charset = "AB"
    gen = PasswordGenerator.brute_force(charset, 2, 2)
    passwords = set(gen)
    expected = {"AA", "AB", "BA", "BB"}
    assert passwords == expected

def test_wordlist_filter_by_charset():
    content = "abc\n123\ndefgh\n"
    tmp = Path(tempfile.mktemp())
    tmp.write_text(content)
    words = PasswordGenerator.from_wordlist(tmp, 2, 4, charset="abcdefgh")
    assert "abc" in words
    assert "123" not in words
    assert "defgh" not in words
    tmp.unlink()