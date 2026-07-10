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