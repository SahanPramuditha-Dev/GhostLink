"""
GHOSTLINK Color System
=======================
Advanced ANSI color formatting with ghost-themed palette.
"""

class Colors:
    """Ghost-themed color palette"""
    
    # Reset
    RESET = "\033[0m"
    
    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    HIDDEN = "\033[8m"
    
    # Ghost Colors
    GHOST_WHITE = "\033[38;5;255m"
    GHOST_GRAY = "\033[38;5;246m"
    GHOST_BLUE = "\033[38;5;75m"
    GHOST_CYAN = "\033[38;5;51m"
    GHOST_GREEN = "\033[38;5;48m"
    GHOST_RED = "\033[38;5;196m"
    GHOST_YELLOW = "\033[38;5;226m"
    GHOST_PURPLE = "\033[38;5;129m"
    
    # Standard Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BLACK = "\033[90m"
    
    # Bright Colors
    BRIGHT_RED = "\033[1;91m"
    BRIGHT_GREEN = "\033[1;92m"
    BRIGHT_YELLOW = "\033[1;93m"
    BRIGHT_BLUE = "\033[1;94m"
    BRIGHT_MAGENTA = "\033[1;95m"
    BRIGHT_CYAN = "\033[1;96m"
    
    # Backgrounds
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"
    BG_GHOST = "\033[48;5;236m"
    
    @classmethod
    def ghost_banner(cls, text: str) -> str:
        """Create ghost-themed banner text"""
        return f"{cls.GHOST_CYAN}{cls.BOLD}{text}{cls.RESET}"
    
    @classmethod
    def success(cls, text: str) -> str:
        """Success message"""
        return f"{cls.GREEN}{text}{cls.RESET}"
    
    @classmethod
    def error(cls, text: str) -> str:
        """Error message"""
        return f"{cls.RED}{text}{cls.RESET}"
    
    @classmethod
    def warning(cls, text: str) -> str:
        """Warning message"""
        return f"{cls.YELLOW}{text}{cls.RESET}"
    
    @classmethod
    def info(cls, text: str) -> str:
        """Info message"""
        return f"{cls.CYAN}{text}{cls.RESET}"

# Global alias
C = Colors