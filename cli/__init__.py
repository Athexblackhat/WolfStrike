# cli/__init__.py

"""
WOLFSTRIKE Command Line Interface Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides all command-line interface components including
argument parsing, interactive menus, progress display,
and help system.
"""

from cli.main_menu import MainMenu
from cli.arg_parser import ArgumentParser
from cli.progress_bars import ProgressManager
from cli.tables import TableFormatter
from cli.colors import ColorTheme
from cli.prompts import PromptHandler
from cli.help_system import HelpSystem

__all__ = [
    'MainMenu',
    'ArgumentParser',
    'ProgressManager',
    'TableFormatter',
    'ColorTheme',
    'PromptHandler',
    'HelpSystem',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'