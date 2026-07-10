# modules/scanner/__init__.py

"""
WOLFSTRIKE Scanner Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Network and web scanning modules for port scanning,
service detection, OS fingerprinting, and web analysis.
"""

from modules.scanner.port_scanner import PortScanner
from modules.scanner.service_detect import ServiceDetector
from modules.scanner.os_fingerprint import OSFingerprint
from modules.scanner.http_methods import HTTPMethods
from modules.scanner.header_analyzer import HeaderAnalyzer
from modules.scanner.cookie_analyzer import CookieAnalyzer
from modules.scanner.js_analyzer import JSAnalyzer
from modules.scanner.hidden_forms import HiddenForms
from modules.scanner.api_discovery import APIDiscovery
from modules.scanner.backup_finder import BackupFinder

__all__ = [
    'PortScanner',
    'ServiceDetector',
    'OSFingerprint',
    'HTTPMethods',
    'HeaderAnalyzer',
    'CookieAnalyzer',
    'JSAnalyzer',
    'HiddenForms',
    'APIDiscovery',
    'BackupFinder',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'