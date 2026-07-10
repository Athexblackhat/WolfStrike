# modules/auth_tester/__init__.py

"""
WOLFSTRIKE Authentication Testing Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests authentication mechanisms for vulnerabilities including
brute force, weak password policies, session management flaws,
JWT misconfigurations, OAuth issues, and MFA bypasses.
"""

from typing import Dict, List, Any, Optional

from modules.auth_tester.brute_force import BruteForceTester
from modules.auth_tester.password_policy import PasswordPolicyTester
from modules.auth_tester.session_tester import SessionTester
from modules.auth_tester.jwt_analyzer import JWTAnalyzer
from modules.auth_tester.oauth_tester import OAuthTester
from modules.auth_tester.mfa_tester import MFATester

__all__ = [
    'BruteForceTester',
    'PasswordPolicyTester',
    'SessionTester',
    'JWTAnalyzer',
    'OAuthTester',
    'MFATester',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all authentication testing modules.
    
    Args:
        target: Target URL
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    auth_modules = [
        ('brute_force', BruteForceTester),
        ('password_policy', PasswordPolicyTester),
        ('session_tester', SessionTester),
        ('jwt_analyzer', JWTAnalyzer),
        ('oauth_tester', OAuthTester),
        ('mfa_tester', MFATester),
    ]
    
    for name, module_class in auth_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in auth_tester/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }