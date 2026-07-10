# stealth/__init__.py

"""
WOLFSTRIKE Stealth Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Stealth and evasion module for anonymous scanning,
proxy rotation, rate limiting, and detection avoidance.
"""

from stealth.proxy_manager import ProxyManager
from stealth.user_agents import UserAgentManager
from stealth.rate_limiter import RateLimiter
from stealth.captcha_solver import CaptchaSolver
from stealth.request_randomizer import RequestRandomizer
from stealth.tor_handler import TorHandler

__all__ = [
    'ProxyManager',
    'UserAgentManager',
    'RateLimiter',
    'CaptchaSolver',
    'RequestRandomizer',
    'TorHandler',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'