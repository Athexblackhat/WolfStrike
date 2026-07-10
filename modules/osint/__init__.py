# modules/osint/__init__.py

"""
WOLFSTRIKE OSINT Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Open Source Intelligence gathering module for passive
reconnaissance using external APIs and public data sources.
"""

from typing import Dict, List, Any, Optional

from modules.osint.shodan_api import ShodanAPI
from modules.osint.censys_api import CensysAPI
from modules.osint.securitytrails import SecurityTrails
from modules.osint.cert_logs import CertLogs
from modules.osint.github_dorks import GitHubDorks
from modules.osint.pastebin_monitor import PastebinMonitor
from modules.osint.breach_check import BreachCheck

__all__ = [
    'ShodanAPI',
    'CensysAPI',
    'SecurityTrails',
    'CertLogs',
    'GitHubDorks',
    'PastebinMonitor',
    'BreachCheck',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all OSINT modules.
    
    Args:
        target: Target domain
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    osint_modules = [
        ('shodan_api', ShodanAPI),
        ('censys_api', CensysAPI),
        ('securitytrails', SecurityTrails),
        ('cert_logs', CertLogs),
        ('github_dorks', GitHubDorks),
        ('pastebin_monitor', PastebinMonitor),
        ('breach_check', BreachCheck),
    ]
    
    for name, module_class in osint_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in osint/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }