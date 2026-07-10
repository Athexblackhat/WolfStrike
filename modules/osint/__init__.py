# modules/osint/__init__.py

"""
WOLFSTRIKE OSINT Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Open Source Intelligence gathering module for passive
reconnaissance using external APIs and public data sources.
"""

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