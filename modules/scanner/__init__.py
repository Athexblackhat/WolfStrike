# modules/scanner/__init__.py

"""
WOLFSTRIKE Scanner Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Network and web scanning modules for port scanning,
service detection, OS fingerprinting, and web analysis.
"""

from typing import Dict, List, Any, Optional

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


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all scanner modules.
    
    Args:
        target: Target URL or domain
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    scanner_modules = [
        ('port_scanner', PortScanner),
        ('service_detect', ServiceDetector),
        ('os_fingerprint', OSFingerprint),
        ('http_methods', HTTPMethods),
        ('header_analyzer', HeaderAnalyzer),
        ('cookie_analyzer', CookieAnalyzer),
        ('js_analyzer', JSAnalyzer),
        ('hidden_forms', HiddenForms),
        ('api_discovery', APIDiscovery),
        ('backup_finder', BackupFinder),
    ]
    
    for name, module_class in scanner_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in scanner/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }