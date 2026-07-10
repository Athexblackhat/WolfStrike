# modules/api_tester/bfla_tester.py

"""
Broken Function Level Authorization Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests API endpoints for BFLA vulnerabilities by
attempting to access administrative or privileged
functions with regular user credentials.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class BFLAResult:
    """Represents a BFLA test result."""
    endpoint: str
    method: str
    user_role: str
    status_code: int
    access_granted: bool
    response_summary: str
    sensitive_data_exposed: bool


class BFLATester:
    """
    Broken Function Level Authorization tester.
    
    Tests for improper access control where regular users
    can access administrative or privileged API functions.
    """
    
    ADMIN_ENDPOINTS = [
        '/api/admin/users',
        '/api/admin/settings',
        '/api/admin/config',
        '/api/admin/logs',
        '/api/admin/system',
        '/api/users/all',
        '/api/users/list',
        '/api/accounts/all',
        '/admin/api/users',
        '/api/internal/users',
        '/api/management/users',
        '/api/dashboard/admin',
        '/api/reports/all',
        '/api/audit/logs',
        '/api/system/info',
        '/api/system/status',
        '/api/system/config',
        '/api/backup/list',
        '/api/export/all',
    ]
    
    ADMIN_METHODS = ['GET', 'POST', 'PUT', 'DELETE']
    
    SENSITIVE_KEYWORDS = [
        'admin', 'root', 'system', 'config',
        'password', 'secret', 'token', 'key',
        'all_users', 'user_list', 'credentials',
        'internal', 'private', 'restricted',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the BFLA tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-BFLA-Tester/1.0',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.results: List[BFLAResult] = []
        self.errors: List[str] = []
        self.auth_token: Optional[str] = self.config.get('auth_token')
        self.user_role: str = self.config.get('user_role', 'regular_user')
        
        if self.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def test_endpoint(
        self,
        endpoint: str,
        method: str = 'GET'
    ) -> BFLAResult:
        """
        Test an endpoint for BFLA vulnerability.
        
        Args:
            endpoint: Target endpoint URL
            method: HTTP method to use
            
        Returns:
            BFLAResult object
        """
        full_url = f"{self.target}{endpoint}"
        
        try:
            response = self.session.request(
                method,
                full_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            status_code = response.status_code
            
            access_granted = status_code in [200, 201, 202]
            
            response_summary = f"Status: {status_code}"
            sensitive_data_exposed = False
            
            if access_granted:
                content_type = response.headers.get('Content-Type', '')
                content_length = len(response.content)
                
                response_summary += f", Size: {content_length} bytes"
                
                if 'application/json' in content_type:
                    try:
                        data = response.json()
                        response_summary += f", JSON data returned"
                        
                        sensitive_data_exposed = self._check_sensitive_data(data)
                        
                        if sensitive_data_exposed:
                            response_summary += ", SENSITIVE DATA EXPOSED"
                    except (ValueError, json.JSONDecodeError):
                        response_summary += ", Non-JSON response"
                
                elif content_length > 100:
                    sensitive_data_exposed = True
                    response_summary += ", Substantial data returned"
            
            result = BFLAResult(
                endpoint=full_url,
                method=method,
                user_role=self.user_role,
                status_code=status_code,
                access_granted=access_granted,
                response_summary=response_summary,
                sensitive_data_exposed=sensitive_data_exposed,
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Request failed for {full_url}: {str(e)}")
            
            return BFLAResult(
                endpoint=full_url,
                method=method,
                user_role=self.user_role,
                status_code=0,
                access_granted=False,
                response_summary=f"Error: {str(e)}",
                sensitive_data_exposed=False,
            )
    
    def _check_sensitive_data(self, data: Any, depth: int = 0) -> bool:
        """
        Check if response contains sensitive data.
        
        Args:
            data: Response data
            depth: Current recursion depth
            
        Returns:
            True if sensitive data found
        """
        if depth > 5:
            return False
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()
                for keyword in self.SENSITIVE_KEYWORDS:
                    if keyword in key_lower:
                        return True
                
                if isinstance(value, (dict, list)):
                    if self._check_sensitive_data(value, depth + 1):
                        return True
                
                if isinstance(value, str) and len(value) > 32:
                    if any(kw in value.lower() for kw in self.SENSITIVE_KEYWORDS):
                        return True
        
        elif isinstance(data, list):
            if len(data) > 10:
                return True
            
            for item in data[:5]:
                if isinstance(item, (dict, list)):
                    if self._check_sensitive_data(item, depth + 1):
                        return True
        
        return False
    
    def test_method_variations(
        self,
        endpoint: str
    ) -> List[BFLAResult]:
        """
        Test endpoint with different HTTP methods.
        
        Args:
            endpoint: Target endpoint URL
            
        Returns:
            List of BFLAResult objects
        """
        results = []
        
        for method in self.ADMIN_METHODS:
            result = self.test_endpoint(endpoint, method)
            results.append(result)
        
        return results
    
    def analyze_results(self) -> List[Dict[str, Any]]:
        """
        Analyze BFLA test results.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        for result in self.results:
            if result.access_granted:
                severity = 'high'
                
                if result.sensitive_data_exposed:
                    severity = 'critical'
                
                vulnerabilities.append({
                    'type': 'Broken Function Level Authorization',
                    'severity': severity,
                    'endpoint': result.endpoint,
                    'description': f'User with role "{result.user_role}" can access '
                                   f'administrative function via {result.method}. '
                                   f'Status: {result.status_code}',
                    'evidence': result.response_summary,
                    'remediation': 'Implement proper role-based access control (RBAC). '
                                   'Deny access by default for all administrative functions.',
                    'sensitive_data_exposed': result.sensitive_data_exposed,
                })
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all BFLA tests.
        
        Returns:
            Dictionary with findings and errors
        """
        for endpoint in self.ADMIN_ENDPOINTS:
            self.test_method_variations(endpoint)
        
        vulnerabilities = self.analyze_results()
        
        findings = []
        for vuln in vulnerabilities:
            findings.append(vuln)
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(self.ADMIN_ENDPOINTS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(vulnerabilities),
        }