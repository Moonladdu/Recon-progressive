"""
ANSI color codes for terminal output.
"""

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def colorize(text, color, bold=False):
    """Return text wrapped in color codes."""
    if bold:
        return f"{Colors.BOLD}{color}{text}{Colors.RESET}"
    return f"{color}{text}{Colors.RESET}"

def stdout(text):
    """Format standard output text (normal)."""
    return colorize(text, Colors.RESET)

def stderr(text):
    """Format error text."""
    return colorize(text, Colors.RED, bold=True)

def parsed_key(text):
    """Format parsed intelligence keys."""
    return colorize(text, Colors.CYAN, bold=True)

def parsed_value(text):
    """Format parsed intelligence values."""
    return colorize(text, Colors.GREEN)

def box_title(text):
    """Format box titles."""
    return colorize(text, Colors.MAGENTA, bold=True)

def banner(text):
    """Format banner text."""
    return colorize(text, Colors.BLUE, bold=True)

def warning(text):
    """Format warning text."""
    return colorize(text, Colors.YELLOW, bold=True)