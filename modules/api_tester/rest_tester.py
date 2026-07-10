# modules/api_tester/rest_tester.py

"""
REST API Security Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Comprehensive REST API security testing including
authentication, authorization, input validation,
and HTTP method analysis.
"""

import json
import re
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    url: str
    method: str
    parameters: List[Dict[str, Any]]
    headers: Dict[str, str]
    authentication_required: bool
    response_codes: Dict[int, int]
    content_type: str


@dataclass
class APIVulnerability:
    """Represents a discovered API vulnerability."""
    endpoint: str
    method: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    remediation: str


class RESTTester:
    """
    REST API security testing engine.
    
    Tests REST APIs for common vulnerabilities including
    broken authentication, excessive data exposure,
    lack of rate limiting, and input validation issues.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the REST API tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-API-Tester/1.0',
            'Accept': 'application/json',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.allow_redirects = self.config.get('allow_redirects', True)
        
        self.discovered_endpoints: List[APIEndpoint] = []
        self.vulnerabilities: List[APIVulnerability] = []
        self.errors: List[str] = []
        
        self.common_api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/v1/', '/v2/',
            '/rest/', '/rest/v1/', '/services/', '/endpoints/',
            '/swagger.json', '/openapi.json', '/api-docs',
            '/api/docs', '/swagger-ui.html', '/docs',
        ]
        
        self.sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'auth',
            'credential', 'private', 'ssn', 'credit', 'card',
            'cvv', 'pin', 'security', 'answer', 'hash',
        ]
    
    def discover_endpoints(self) -> List[APIEndpoint]:
        """
        Discover API endpoints from common paths and documentation.
        
        Returns:
            List of discovered APIEndpoint objects
        """
        for path in self.common_api_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=self.allow_redirects
                )
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'application/json' in content_type:
                        endpoints = self._parse_json_endpoints(response.json())
                        self.discovered_endpoints.extend(endpoints)
                    elif 'text/html' in content_type and 'swagger' in response.text.lower():
                        endpoints = self._parse_swagger_endpoints(url, response.text)
                        self.discovered_endpoints.extend(endpoints)
                        
            except RequestException:
                continue
            except json.JSONDecodeError:
                continue
        
        return self.discovered_endpoints
    
    def _parse_json_endpoints(self, data: Any, base_path: str = '') -> List[APIEndpoint]:
        """
        Parse JSON response for API endpoints.
        
        Args:
            data: JSON data
            base_path: Base path for endpoints
            
        Returns:
            List of APIEndpoint objects
        """
        endpoints = []
        
        if isinstance(data, dict):
            if 'paths' in data:
                for path, methods in data['paths'].items():
                    if isinstance(methods, dict):
                        for method in methods:
                            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                                endpoint = APIEndpoint(
                                    url=urljoin(self.target, path),
                                    method=method.upper(),
                                    parameters=[],
                                    headers={},
                                    authentication_required=False,
                                    response_codes={},
                                    content_type='application/json'
                                )
                                endpoints.append(endpoint)
            
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    endpoints.extend(self._parse_json_endpoints(value, base_path))
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    endpoints.extend(self._parse_json_endpoints(item, base_path))
        
        return endpoints
    
    def _parse_swagger_endpoints(self, url: str, html: str) -> List[APIEndpoint]:
        """
        Parse Swagger UI HTML for API documentation URL.
        
        Args:
            url: Swagger UI URL
            html: HTML content
            
        Returns:
            List of APIEndpoint objects
        """
        endpoints = []
        
        swagger_json_patterns = [
            r'"swaggerJson"\s*:\s*"([^"]+)"',
            r'url:\s*"([^"]+\.json)"',
            r'spec:\s*"([^"]+)"',
        ]
        
        for pattern in swagger_json_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith('http'):
                    json_url = match
                else:
                    json_url = urljoin(self.target, match)
                
                try:
                    response = self.session.get(json_url, timeout=self.timeout)
                    if response.status_code == 200:
                        endpoints.extend(self._parse_json_endpoints(response.json()))
                except (RequestException, json.JSONDecodeError):
                    continue
        
        return endpoints
    
    def test_authentication(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        """
        Test endpoints for authentication issues.
        
        Args:
            endpoints: List of APIEndpoint objects
            
        Returns:
            List of APIVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in endpoints:
            try:
                response = self.session.request(
                    endpoint.method,
                    endpoint.url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    vulnerabilities.append(APIVulnerability(
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        vulnerability_type='Missing Authentication',
                        severity='high',
                        description=f'Endpoint accessible without authentication',
                        evidence=f'Status: {response.status_code}, Response size: {len(response.content)} bytes',
                        remediation='Implement authentication and authorization for all API endpoints'
                    ))
                elif response.status_code == 401:
                    self._test_weak_authentication(endpoint, vulnerabilities)
                elif response.status_code == 403:
                    self._test_authorization_bypass(endpoint, vulnerabilities)
                    
            except RequestException:
                continue
        
        return vulnerabilities
    
    def _test_weak_authentication(
        self,
        endpoint: APIEndpoint,
        vulnerabilities: List[APIVulnerability]
    ) -> None:
        """
        Test for weak authentication mechanisms.
        
        Args:
            endpoint: API endpoint to test
            vulnerabilities: List to append findings
        """
        weak_tokens = [
            'Bearer null',
            'Bearer undefined',
            'Bearer test',
            'Bearer admin',
            'Basic YWRtaW46YWRtaW4=',
            'Basic dGVzdDp0ZXN0',
        ]
        
        for token in weak_tokens:
            headers = {'Authorization': token}
            try:
                response = self.session.request(
                    endpoint.method,
                    endpoint.url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    vulnerabilities.append(APIVulnerability(
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        vulnerability_type='Weak Authentication',
                        severity='high',
                        description=f'Endpoint accepts weak/easily guessable token: {token[:30]}',
                        evidence=f'Status: {response.status_code}',
                        remediation='Implement strong token-based authentication with proper validation'
                    ))
                    break
                    
            except RequestException:
                continue
    
    def _test_authorization_bypass(
        self,
        endpoint: APIEndpoint,
        vulnerabilities: List[APIVulnerability]
    ) -> None:
        """
        Test for authorization bypass techniques.
        
        Args:
            endpoint: API endpoint to test
            vulnerabilities: List to append findings
        """
        bypass_headers = [
            {'X-Original-URL': endpoint.url},
            {'X-Rewrite-URL': endpoint.url},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': '127.0.0.1'},
            {'X-HTTP-Method-Override': 'GET'},
            {'X-HTTP-Method': 'GET'},
        ]
        
        for headers in bypass_headers:
            try:
                response = self.session.request(
                    endpoint.method,
                    endpoint.url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    vulnerabilities.append(APIVulnerability(
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        vulnerability_type='Authorization Bypass',
                        severity='critical',
                        description=f'Authorization bypassed using header: {list(headers.keys())[0]}',
                        evidence=f'Status: {response.status_code}',
                        remediation='Implement proper server-side authorization checks'
                    ))
                    break
                    
            except RequestException:
                continue
    
    def test_input_validation(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        """
        Test endpoints for input validation issues.
        
        Args:
            endpoints: List of APIEndpoint objects
            
        Returns:
            List of APIVulnerability objects
        """
        vulnerabilities = []
        
        test_payloads = {
            'SQL Injection': [
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "' UNION SELECT NULL--",
            ],
            'XSS': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
            ],
            'Command Injection': [
                '; ls -la',
                '| cat /etc/passwd',
                '$(whoami)',
            ],
        }
        
        for endpoint in endpoints:
            if endpoint.method in ['POST', 'PUT', 'PATCH']:
                for vuln_type, payloads in test_payloads.items():
                    for payload in payloads:
                        try:
                            data = {'test': payload}
                            response = self.session.request(
                                endpoint.method,
                                endpoint.url,
                                json=data,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                            
                            if self._check_reflection(response, payload):
                                vulnerabilities.append(APIVulnerability(
                                    endpoint=endpoint.url,
                                    method=endpoint.method,
                                    vulnerability_type=vuln_type,
                                    severity='high',
                                    description=f'Possible {vuln_type} vulnerability detected',
                                    evidence=f'Payload reflected in response',
                                    remediation='Implement proper input validation and output encoding'
                                ))
                                break
                                
                        except RequestException:
                            continue
        
        return vulnerabilities
    
    def _check_reflection(self, response: requests.Response, payload: str) -> bool:
        """
        Check if payload is reflected in response.
        
        Args:
            response: HTTP response object
            payload: Test payload
            
        Returns:
            True if payload reflected
        """
        try:
            response_text = response.text
            if payload in response_text:
                return True
            if payload.lower() in response_text.lower():
                return True
        except Exception:
            pass
        
        return False
    
    def test_data_exposure(self, endpoints: List[APIEndpoint]) -> List[APIVulnerability]:
        """
        Test endpoints for excessive data exposure.
        
        Args:
            endpoints: List of APIEndpoint objects
            
        Returns:
            List of APIVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in endpoints:
            if endpoint.method == 'GET':
                try:
                    response = self.session.get(
                        endpoint.url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        if 'application/json' in content_type:
                            try:
                                data = response.json()
                                exposed_fields = self._find_sensitive_fields(data)
                                
                                if exposed_fields:
                                    vulnerabilities.append(APIVulnerability(
                                        endpoint=endpoint.url,
                                        method=endpoint.method,
                                        vulnerability_type='Excessive Data Exposure',
                                        severity='medium',
                                        description=f'API exposes sensitive fields: {", ".join(exposed_fields)}',
                                        evidence=f'Sensitive fields found in response',
                                        remediation='Implement response filtering to exclude sensitive fields'
                                    ))
                            except json.JSONDecodeError:
                                pass
                                
                except RequestException:
                    continue
        
        return vulnerabilities
    
    def _find_sensitive_fields(self, data: Any, depth: int = 0) -> Set[str]:
        """
        Find sensitive fields in response data.
        
        Args:
            data: Response data
            depth: Current recursion depth
            
        Returns:
            Set of sensitive field names
        """
        if depth > 5:
            return set()
        
        sensitive_fields = set()
        
        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()
                for keyword in self.sensitive_keywords:
                    if keyword in key_lower:
                        sensitive_fields.add(key)
                        break
                
                if isinstance(value, (dict, list)):
                    sensitive_fields.update(self._find_sensitive_fields(value, depth + 1))
        
        elif isinstance(data, list):
            for item in data[:5]:
                if isinstance(item, (dict, list)):
                    sensitive_fields.update(self._find_sensitive_fields(item, depth + 1))
        
        return sensitive_fields
    
    def run(self) -> Dict[str, Any]:
        """
        Run all REST API tests.
        
        Returns:
            Dictionary with findings and errors
        """
        endpoints = self.discover_endpoints()
        
        auth_vulns = self.test_authentication(endpoints)
        self.vulnerabilities.extend(auth_vulns)
        
        input_vulns = self.test_input_validation(endpoints)
        self.vulnerabilities.extend(input_vulns)
        
        exposure_vulns = self.test_data_exposure(endpoints)
        self.vulnerabilities.extend(exposure_vulns)
        
        findings = []
        for vuln in self.vulnerabilities:
            findings.append({
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'endpoint': vuln.endpoint,
                'method': vuln.method,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_discovered': len(self.discovered_endpoints),
            'vulnerabilities_found': len(self.vulnerabilities),
        }