# modules/attacks/__init__.py

"""
WOLFSTRIKE Attack Modules Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced exploitation modules for confirmed vulnerabilities
including SQL injection, XSS, JWT attacks, deserialization,
and other active attack vectors.
"""

from typing import Dict, List, Any, Optional

from modules.attacks.sqli_exploit import SQLiExploit
from modules.attacks.xss_exploit import XSSExploit
from modules.attacks.jwt_attacks import JWTAttacker
from modules.attacks.deserialization import DeserializationAttacker
from modules.attacks.race_condition import RaceConditionTester
from modules.attacks.host_header import HostHeaderAttacker
from modules.attacks.crlf_injection import CRLFInjection
from modules.attacks.cache_poison import CachePoison
from modules.attacks.prototype_pollution import PrototypePollution
from modules.attacks.css_injection import CSSInjection

__all__ = [
    'SQLiExploit',
    'XSSExploit',
    'JWTAttacker',
    'DeserializationAttacker',
    'RaceConditionTester',
    'HostHeaderAttacker',
    'CRLFInjection',
    'CachePoison',
    'PrototypePollution',
    'CSSInjection',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all attack modules.
    
    Args:
        target: Target URL
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    attack_modules = [
        ('sqli_exploit', SQLiExploit),
        ('xss_exploit', XSSExploit),
        ('jwt_attacks', JWTAttacker),
        ('deserialization', DeserializationAttacker),
        ('race_condition', RaceConditionTester),
        ('host_header', HostHeaderAttacker),
        ('crlf_injection', CRLFInjection),
        ('cache_poison', CachePoison),
        ('prototype_pollution', PrototypePollution),
        ('css_injection', CSSInjection),
    ]
    
    for name, module_class in attack_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in attacks/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }