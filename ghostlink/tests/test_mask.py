import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ghostlink.engine.mask import mask_generator

def test_digit_mask():
    gen = mask_generator("?d?d")
    passwords = set(gen)
    assert "00" in passwords
    assert "99" in passwords
    assert len(passwords) == 100

def test_mixed_mask():
    gen = mask_generator("?l?d")
    passwords = set(gen)
    assert "a0" in passwords
    assert "z9" in passwords
    for p in passwords:
        assert p[0].isalpha() and p[1].isdigit()