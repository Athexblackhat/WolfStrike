# modules/api_tester/__init__.py

"""
WOLFSTRIKE API Testing Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests REST, GraphQL, and SOAP APIs for common vulnerabilities
including authentication issues, rate limiting, and access control.
"""

from typing import Dict, List, Any, Optional

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


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all API testing modules.
    
    Args:
        target: Target URL
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    api_modules = [
        ('rest_tester', RESTTester),
        ('graphql_tester', GraphQLTester),
        ('soap_tester', SOAPTester),
        ('rate_limit', RateLimitTester),
        ('mass_assignment', MassAssignmentTester),
        ('bola_tester', BOLATester),
        ('bfla_tester', BFLATester),
    ]
    
    for name, module_class in api_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in api_tester/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }