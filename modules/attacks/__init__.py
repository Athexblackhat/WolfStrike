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