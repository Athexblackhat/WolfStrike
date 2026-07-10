# database/__init__.py

"""
WOLFSTRIKE Database Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Database models and migration management for persistent
storage of scan results, vulnerabilities, and session data.
"""

from database.models import (
    Scan,
    Vulnerability,
    ModuleResult,
    ScanError,
    SessionData,
    init_database,
    get_session,
    close_session,
)

__all__ = [
    'Scan',
    'Vulnerability',
    'ModuleResult',
    'ScanError',
    'SessionData',
    'init_database',
    'get_session',
    'close_session',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'