# termux/__init__.py

"""
WOLFSTRIKE Termux Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Termux-specific components for Android compatibility
with optimized performance and reduced resource usage.
"""

from termux.termux_handler import TermuxHandler
from termux.termux_banner import TermuxBanner

__all__ = [
    'TermuxHandler',
    'TermuxBanner',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'