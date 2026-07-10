# modules/network/__init__.py

"""
WOLFSTRIKE Network Security Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Network-level security testing including email security,
DNSSEC validation, zone transfer testing, ASN lookups,
and BGP information gathering.
"""

from modules.network.email_security import EmailSecurity
from modules.network.dnssec_check import DNSSECCheck
from modules.network.zone_transfer import ZoneTransfer
from modules.network.asn_lookup import ASNLookup
from modules.network.bgp_info import BGPInfo

__all__ = [
    'EmailSecurity',
    'DNSSECCheck',
    'ZoneTransfer',
    'ASNLookup',
    'BGPInfo',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'