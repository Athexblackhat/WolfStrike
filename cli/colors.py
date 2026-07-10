# cli/colors.py

"""
Color Theme Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages color themes for terminal output with support
for severity-based coloring and custom themes.
"""

from typing import Dict, Optional, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for color coding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    DEBUG = "debug"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class ColorTheme:
    """
    Terminal color theme manager.
    
    Provides consistent color coding for different severity
    levels and message types across the application.
    """
    
    ANSI_CODES = {
        'reset': '\033[0m',
        'bold': '\033[1m',
        'dim': '\033[2m',
        'underline': '\033[4m',
        'blink': '\033[5m',
        'reverse': '\033[7m',
        'hidden': '\033[8m',
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'bg_black': '\033[40m',
        'bg_red': '\033[41m',
        'bg_green': '\033[42m',
        'bg_yellow': '\033[43m',
        'bg_blue': '\033[44m',
        'bg_magenta': '\033[45m',
        'bg_cyan': '\033[46m',
        'bg_white': '\033[47m',
        'bright_black': '\033[90m',
        'bright_red': '\033[91m',
        'bright_green': '\033[92m',
        'bright_yellow': '\033[93m',
        'bright_blue': '\033[94m',
        'bright_magenta': '\033[95m',
        'bright_cyan': '\033[96m',
        'bright_white': '\033[97m',
    }
    
    DEFAULT_THEME = {
        Severity.CRITICAL: {
            'foreground': 'bright_red',
            'background': None,
            'style': ['bold'],
            'prefix': '[CRITICAL]',
        },
        Severity.HIGH: {
            'foreground': 'red',
            'background': None,
            'style': ['bold'],
            'prefix': '[HIGH]',
        },
        Severity.MEDIUM: {
            'foreground': 'yellow',
            'background': None,
            'style': [],
            'prefix': '[MEDIUM]',
        },
        Severity.LOW: {
            'foreground': 'green',
            'background': None,
            'style': [],
            'prefix': '[LOW]',
        },
        Severity.INFO: {
            'foreground': 'blue',
            'background': None,
            'style': [],
            'prefix': '[*]',
        },
        Severity.DEBUG: {
            'foreground': 'bright_black',
            'background': None,
            'style': ['dim'],
            'prefix': '[DEBUG]',
        },
        Severity.SUCCESS: {
            'foreground': 'bright_green',
            'background': None,
            'style': ['bold'],
            'prefix': '[+]',
        },
        Severity.WARNING: {
            'foreground': 'bright_yellow',
            'background': None,
            'style': ['bold'],
            'prefix': '[!]',
        },
        Severity.ERROR: {
            'foreground': 'bright_red',
            'background': None,
            'style': ['bold'],
            'prefix': '[-]',
        },
    }
    
    def __init__(
        self,
        theme: Optional[Dict[Severity, Dict[str, Any]]] = None,
        no_color: bool = False
    ):
        """
        Initialize the color theme.
        
        Args:
            theme: Custom theme dictionary
            no_color: Disable all colors
        """
        self.no_color = no_color
        self.theme = theme or self.DEFAULT_THEME.copy()
    
    def _apply_styles(self, text: str, config: Dict[str, Any]) -> str:
        """
        Apply ANSI styles to text.
        
        Args:
            text: Text to style
            config: Style configuration
            
        Returns:
            Styled text string
        """
        if self.no_color:
            return text
        
        codes = []
        
        for style in config.get('style', []):
            if style in self.ANSI_CODES:
                codes.append(self.ANSI_CODES[style])
        
        foreground = config.get('foreground')
        if foreground and foreground in self.ANSI_CODES:
            codes.append(self.ANSI_CODES[foreground])
        
        background = config.get('background')
        if background and background in self.ANSI_CODES:
            codes.append(self.ANSI_CODES[background])
        
        if not codes:
            return text
        
        styled = ''.join(codes) + text + self.ANSI_CODES['reset']
        return styled
    
    def colorize(self, text: str, severity: Severity) -> str:
        """
        Apply color based on severity.
        
        Args:
            text: Text to colorize
            severity: Severity level
            
        Returns:
            Colorized text
        """
        config = self.theme.get(severity, {})
        return self._apply_styles(text, config)
    
    def format_message(self, message: str, severity: Severity) -> str:
        """
        Format a message with severity prefix and color.
        
        Args:
            message: Message text
            severity: Severity level
            
        Returns:
            Formatted message string
        """
        config = self.theme.get(severity, {})
        prefix = config.get('prefix', '')
        
        if prefix:
            formatted = f"{prefix} {message}"
        else:
            formatted = message
        
        return self._apply_styles(formatted, config)
    
    def critical(self, text: str) -> str:
        """Format critical message."""
        return self.format_message(text, Severity.CRITICAL)
    
    def high(self, text: str) -> str:
        """Format high severity message."""
        return self.format_message(text, Severity.HIGH)
    
    def medium(self, text: str) -> str:
        """Format medium severity message."""
        return self.format_message(text, Severity.MEDIUM)
    
    def low(self, text: str) -> str:
        """Format low severity message."""
        return self.format_message(text, Severity.LOW)
    
    def info(self, text: str) -> str:
        """Format info message."""
        return self.format_message(text, Severity.INFO)
    
    def debug(self, text: str) -> str:
        """Format debug message."""
        return self.format_message(text, Severity.DEBUG)
    
    def success(self, text: str) -> str:
        """Format success message."""
        return self.format_message(text, Severity.SUCCESS)
    
    def warning(self, text: str) -> str:
        """Format warning message."""
        return self.format_message(text, Severity.WARNING)
    
    def error(self, text: str) -> str:
        """Format error message."""
        return self.format_message(text, Severity.ERROR)
    
    def bold(self, text: str) -> str:
        """Apply bold style."""
        return self._apply_styles(text, {'style': ['bold']})
    
    def dim(self, text: str) -> str:
        """Apply dim style."""
        return self._apply_styles(text, {'style': ['dim']})
    
    def underline(self, text: str) -> str:
        """Apply underline style."""
        return self._apply_styles(text, {'style': ['underline']})
    
    def custom(
        self,
        text: str,
        foreground: Optional[str] = None,
        background: Optional[str] = None,
        styles: Optional[list] = None
    ) -> str:
        """
        Apply custom styling.
        
        Args:
            text: Text to style
            foreground: Foreground color name
            background: Background color name
            styles: List of style names
            
        Returns:
            Styled text
        """
        config = {}
        if foreground:
            config['foreground'] = foreground
        if background:
            config['background'] = background
        if styles:
            config['style'] = styles
        
        return self._apply_styles(text, config)
    
    def set_custom_theme(self, theme: Dict[Severity, Dict[str, Any]]) -> None:
        """
        Set a custom color theme.
        
        Args:
            theme: Custom theme dictionary
        """
        self.theme = theme.copy()
    
    def reset_theme(self) -> None:
        """Reset to default theme."""
        self.theme = self.DEFAULT_THEME.copy()
    
    def strip_colors(self, text: str) -> str:
        """
        Remove ANSI color codes from text.
        
        Args:
            text: Text with ANSI codes
            
        Returns:
            Plain text without colors
        """
        import re
        ansi_escape = re.compile(r'\033\[[0-9;]*m')
        return ansi_escape.sub('', text)
    
    def get_available_colors(self) -> Dict[str, str]:
        """
        Get all available ANSI color codes.
        
        Returns:
            Dictionary of color names to ANSI codes
        """
        return self.ANSI_CODES.copy()
    
    def print_colors(self) -> None:
        """Display all available colors."""
        print("\nAvailable Colors:")
        print("=" * 40)
        
        for name, code in self.ANSI_CODES.items():
            if name.startswith('bg_'):
                continue
            sample = f"{code}Sample Text{self.ANSI_CODES['reset']}"
            print(f"  {name:<20} {sample}")
        
        print()