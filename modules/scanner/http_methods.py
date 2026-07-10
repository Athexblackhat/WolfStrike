# modules/scanner/http_methods.py

"""
HTTP Methods Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests allowed HTTP methods and identifies dangerous
methods that could be exploited.
"""

from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class HTTPMethods:
    """
    HTTP methods security tester.
    
    Enumerates allowed HTTP methods and identifies
    potentially dangerous configurations.
    """
    
    HTTP_METHODS = [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
        'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'DEBUG',
    ]
    
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'DEBUG']
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the HTTP methods tester.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.allowed_methods: List[str] = []
        self.errors: List[str] = []
    
    def test_method(self, method: str) -> Dict[str, Any]:
        """
        Test if an HTTP method is allowed.
        
        Args:
            method: HTTP method to test
            
        Returns:
            Dictionary with test result
        """
        try:
            response = self.session.request(
                method,
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            allowed = response.status_code not in [405, 501]
            
            return {
                'method': method,
                'status_code': response.status_code,
                'allowed': allowed,
                'headers': dict(response.headers),
            }
            
        except RequestException as e:
            return {
                'method': method,
                'status_code': 0,
                'allowed': False,
                'error': str(e),
            }
    
    def test_options(self) -> List[str]:
        """
        Test OPTIONS method for allowed methods.
        
        Returns:
            List of allowed HTTP methods from Allow header
        """
        try:
            response = self.session.options(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            allow_header = response.headers.get('Allow', '')
            
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(',')]
                return methods
            
            return []
            
        except RequestException:
            return []
    
    def run(self) -> Dict[str, Any]:
        """
        Run HTTP methods testing.
        
        Returns:
            Dictionary with test results
        """
        options_methods = self.test_options()
        
        if options_methods:
            self.allowed_methods = options_methods
        else:
            for method in self.HTTP_METHODS:
                result = self.test_method(method)
                
                if result.get('allowed'):
                    self.allowed_methods.append(method)
        
        dangerous_allowed = [
            method for method in self.allowed_methods
            if method in self.DANGEROUS_METHODS
        ]
        
        findings = []
        
        if dangerous_allowed:
            findings.append({
                'type': 'Dangerous HTTP Methods Allowed',
                'severity': 'medium',
                'target': self.target,
                'description': f'Dangerous HTTP methods enabled: {", ".join(dangerous_allowed)}',
                'evidence': dangerous_allowed,
                'remediation': 'Disable unnecessary HTTP methods. Only allow GET, POST, HEAD, and OPTIONS.',
            })
        
        if self.allowed_methods:
            findings.append({
                'type': 'HTTP Methods Enumerated',
                'severity': 'info',
                'target': self.target,
                'description': f'Allowed methods: {", ".join(self.allowed_methods)}',
                'evidence': self.allowed_methods,
                'remediation': 'Review allowed HTTP methods for security',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'allowed_methods': self.allowed_methods,
            'dangerous_methods': dangerous_allowed,
        }