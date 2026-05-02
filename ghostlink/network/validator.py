import urllib.request

def verify_internet(timeout: int = 5) -> bool:
    """Return True if a known internet host is reachable."""
    try:
        urllib.request.urlopen("http://clients3.google.com/generate_204", timeout=timeout)
        return True
    except Exception:
        return False