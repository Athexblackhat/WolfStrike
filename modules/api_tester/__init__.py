# modules/api_tester/__init__.py

"""
WOLFSTRIKE API Testing Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests REST, GraphQL, and SOAP APIs for common vulnerabilities
including authentication issues, rate limiting, and access control.
"""

from modules.api_tester.rest_tester import RESTTester
from modules.api_tester.graphql_tester import GraphQLTester
from modules.api_tester.soap_tester import SOAPTester
from modules.api_tester.rate_limit import RateLimitTester
from modules.api_tester.mass_assignment import MassAssignmentTester
from modules.api_tester.bola_tester import BOLATester
from modules.api_tester.bfla_tester import BFLATester

__all__ = [
    'RESTTester',
    'GraphQLTester',
    'SOAPTester',
    'RateLimitTester',
    'MassAssignmentTester',
    'BOLATester',
    'BFLATester',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'