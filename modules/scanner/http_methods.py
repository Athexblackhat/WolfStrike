# modules/scanner/http_methods.py

"""
HTTP Methods Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests allowed HTTP methods and identifies dangerous
methods that could be exploited.
"""

from typing import Dict, List, Any, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


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
    
    SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS']
    
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
        self.target = target.rstrip('/') if target else ''
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_methods = self.config.get('max_methods', 15)
        
        self.allowed_methods: List[str] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self._tested_methods: List[str] = []
    
    def _validate_target(self) -> Tuple[bool, str]:
        """
        Validate target before testing.
        
        Args:
            target: Target URL
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.target:
            return False, "Target is empty"
        
        if not self.target.startswith(('http://', 'https://')):
            return False, f"Invalid URL scheme: {self.target}"
        
        return True, ""
    
    def _normalize_method(self, method: str) -> str:
        """
        Normalize HTTP method name.
        
        Args:
            method: Method string
            
        Returns:
            Uppercase method name
        """
        return method.strip().upper()
    
    def _is_valid_response(self, response: Optional[requests.Response]) -> bool:
        """
        Check if response is valid.
        
        Args:
            response: HTTP response
            
        Returns:
            True if response is valid
        """
        if response is None:
            return False
        if not hasattr(response, 'status_code'):
            return False
        return True
    
    def _parse_allow_header(self, allow_header: str) -> List[str]:
        """
        Safely parse Allow header.
        
        Args:
            allow_header: Allow header value
            
        Returns:
            List of allowed methods
        """
        if not allow_header:
            return []
        
        methods = []
        for method in allow_header.split(','):
            method = self._normalize_method(method)
            if method:
                methods.append(method)
        
        return methods
    
    def _is_method_allowed(self, response: requests.Response) -> bool:
        """
        Check if response indicates method is allowed.
        
        Args:
            response: HTTP response
            
        Returns:
            True if method is allowed
        """
        if not self._is_valid_response(response):
            return False
        
        # 405 = Method Not Allowed
        # 501 = Not Implemented
        if response.status_code in [405, 501]:
            return False
        
        # Any other status code means method was processed
        return True
    
    def _get_methods_to_test(self) -> List[str]:
        """
        Get prioritized list of methods to test.
        
        Returns:
            List of HTTP methods
        """
        # Test safe methods first
        methods = []
        
        # Add safe methods
        for method in self.SAFE_METHODS:
            if method not in methods:
                methods.append(method)
        
        # Add other common methods
        for method in self.HTTP_METHODS:
            if method not in methods:
                methods.append(method)
        
        # Add additional methods if needed
        additional = ['PROPFIND', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
        for method in additional:
            if method not in methods and len(methods) < self.max_methods:
                methods.append(method)
        
        return methods[:self.max_methods]
    
    def _safe_request(self, method: str) -> Optional[requests.Response]:
        """
        Safely send HTTP request.
        
        Args:
            method: HTTP method to test
            
        Returns:
            HTTP response or None
        """
        try:
            response = self.session.request(
                method,
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            return response
            
        except Timeout:
            self.errors.append(f"Timeout testing method {method}")
            return None
        except ConnectionError:
            self.errors.append(f"Connection error testing method {method}")
            return None
        except RequestException as e:
            self.errors.append(f"Request error testing method {method}: {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"Unexpected error testing method {method}: {str(e)}")
            return None
    
    def test_method(self, method: str) -> Dict[str, Any]:
        """
        Test if an HTTP method is allowed.
        
        Args:
            method: HTTP method to test
            
        Returns:
            Dictionary with test result
        """
        normalized_method = self._normalize_method(method)
        self._tested_methods.append(normalized_method)
        
        response = self._safe_request(normalized_method)
        
        if response is None:
            return {
                'method': normalized_method,
                'status_code': 0,
                'allowed': False,
                'error': 'Request failed',
                'headers': {},
            }
        
        allowed = self._is_method_allowed(response)
        
        return {
            'method': normalized_method,
            'status_code': response.status_code,
            'allowed': allowed,
            'headers': dict(response.headers),
            'content_length': len(response.content) if response.content else 0,
        }
    
    def test_options(self) -> List[str]:
        """
        Test OPTIONS method for allowed methods.
        
        Returns:
            List of allowed HTTP methods from Allow header
        """
        response = self._safe_request('OPTIONS')
        
        if not self._is_valid_response(response):
            return []
        
        allow_header = response.headers.get('Allow', '')
        
        if allow_header:
            return self._parse_allow_header(allow_header)
        
        return []
    
    def _check_options_fallback(self) -> List[str]:
        """
        Fallback method when OPTIONS doesn't return Allow header.
        
        Returns:
            List of allowed methods
        """
        allowed = []
        
        for method in self._get_methods_to_test():
            result = self.test_method(method)
            
            if result.get('allowed', False):
                allowed.append(method)
        
        return allowed
    
    def run(self) -> Dict[str, Any]:
        """
        Run HTTP methods testing.
        
        Returns:
            Dictionary with test results
        """
        # Reset state
        self.allowed_methods.clear()
        self.errors.clear()
        self._tested_methods.clear()
        self.scan_status = 'running'
        
        # Validate target
        valid, error = self._validate_target()
        if not valid:
            self.errors.append(error)
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'target': self.target,
                'allowed_methods': [],
                'dangerous_methods': [],
                'scan_status': 'failed',
                'error': error,
            }
        
        # Try OPTIONS method first
        options_methods = self.test_options()
        
        if options_methods:
            self.allowed_methods = options_methods
        else:
            # Fallback to testing each method individually
            self.allowed_methods = self._check_options_fallback()
        
        # Remove duplicates while preserving order
        seen = set()
        unique_methods = []
        for method in self.allowed_methods:
            if method not in seen:
                seen.add(method)
                unique_methods.append(method)
        self.allowed_methods = unique_methods
        
        # Identify dangerous methods
        dangerous_allowed = [
            method for method in self.allowed_methods
            if method in self.DANGEROUS_METHODS
        ]
        
        # Identify missing safe methods
        missing_safe = [
            method for method in self.SAFE_METHODS
            if method not in self.allowed_methods
        ]
        
        self.scan_status = 'completed'
        
        findings = []
        
        if dangerous_allowed:
            findings.append({
                'type': 'Dangerous HTTP Methods Allowed',
                'severity': 'medium',
                'target': self.target,
                'description': f'Dangerous HTTP methods enabled: {", ".join(dangerous_allowed)}',
                'evidence': {
                    'dangerous_methods': dangerous_allowed,
                    'all_allowed': self.allowed_methods,
                },
                'remediation': 'Disable unnecessary HTTP methods. Only allow GET, POST, HEAD, and OPTIONS.',
            })
        
        if self.allowed_methods:
            findings.append({
                'type': 'HTTP Methods Enumerated',
                'severity': 'info',
                'target': self.target,
                'description': f'Allowed methods: {", ".join(self.allowed_methods)}',
                'evidence': {
                    'allowed_methods': self.allowed_methods,
                    'tested_methods': self._tested_methods,
                },
                'remediation': 'Review allowed HTTP methods for security implications.',
            })
        
        if missing_safe:
            findings.append({
                'type': 'Missing Standard HTTP Methods',
                'severity': 'low',
                'target': self.target,
                'description': f'Standard methods not allowed: {", ".join(missing_safe)}',
                'evidence': missing_safe,
                'remediation': 'Ensure standard methods are properly implemented.',
            })
        
        if not self.allowed_methods:
            findings.append({
                'type': 'No HTTP Methods Allowed',
                'severity': 'info',
                'target': self.target,
                'description': 'No HTTP methods appear to be allowed. Target may be unreachable.',
                'evidence': {'tested_methods': self._tested_methods[:10]},
                'remediation': 'Verify target is accessible and responds to HTTP requests.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'allowed_methods': self.allowed_methods,
            'dangerous_methods': dangerous_allowed,
            'missing_safe_methods': missing_safe,
            'scan_status': self.scan_status,
            'tested_methods': self._tested_methods,
        }
