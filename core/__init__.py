# core/__init__.py

"""
WOLFSTRIKE Core Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Core engine and foundational components for the WOLFSTRIKE toolkit.
Provides configuration management, logging, database operations,
platform detection, and the main scanning engine.
"""

from core.engine import ScanEngine
from core.config import ConfigManager
from core.logger import Logger
from core.database import DatabaseManager
from core.cache import CacheManager
from core.exceptions import (
    WolfStrikeException,
    ConfigurationError,
    ScanError,
    ModuleError,
    NetworkError,
    AuthenticationError,
    PayloadError,
    DatabaseError,
    CacheError,
)
from core.platform_checker import PlatformChecker
from core.banner import Banner
from core.updater import UpdateManager

__all__ = [
    'ScanEngine',
    'ConfigManager',
    'Logger',
    'DatabaseManager',
    'CacheManager',
    'WolfStrikeException',
    'ConfigurationError',
    'ScanError',
    'ModuleError',
    'NetworkError',
    'AuthenticationError',
    'PayloadError',
    'DatabaseError',
    'CacheError',
    'PlatformChecker',
    'Banner',
    'UpdateManager',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'