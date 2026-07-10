# modules/api_tester/bola_tester.py

"""
Broken Object Level Authorization Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests API endpoints for BOLA vulnerabilities by
attempting to access resources belonging to other users
through ID enumeration and manipulation.
"""

import re
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class BOLAResult:
    """Represents a BOLA test result."""
    endpoint: str
    original_id: str
    tested_id: str
    original_status: int
    tested_status: int
    vulnerability_found: bool
    response_difference: str
    data_leaked: bool


class BOLATester:
    """
    Broken Object Level Authorization tester.
    
    Tests for insecure direct object references where
    users can access resources belonging to other users
    by manipulating object IDs.
    """
    
    ID_PATTERNS = [
        r'/users/(\d+)',
        r'/accounts/(\d+)',
        r'/orders/(\d+)',
        r'/invoices/(\d+)',
        r'/profiles/(\d+)',
        r'/posts/(\d+)',
        r'/comments/(\d+)',
        r'/messages/(\d+)',
        r'/transactions/(\d+)',
        r'/documents/(\d+)',
        r'/files/(\d+)',
        r'/[a-z]+/([a-f0-9-]{36})',
        r'/([a-f0-9]{24})',
    ]
    
    ID_INCREMENT_VALUES = [1, 2, 3, 100, 1000, -1, 0]
    
    UUID_TEST_VALUES = [
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000002',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the BOLA tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-BOLA-Tester/1.0',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.results: List[BOLAResult] = []
        self.errors: List[str] = []
        self.auth_token: Optional[str] = self.config.get('auth_token')
        
        if self.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def extract_ids_from_url(self, url: str) -> List[Tuple[str, str]]:
        """
        Extract potential object IDs from URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            List of (pattern, id_value) tuples
        """
        extracted = []
        
        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                extracted.append((pattern, match))
        
        return extracted
    
    def test_endpoint(
        self,
        endpoint: str,
        original_id: str,
        test_id: str
    ) -> BOLAResult:
        """
        Test an endpoint for BOLA vulnerability.
        
        Args:
            endpoint: API endpoint with original ID
            original_id: Original object ID
            test_id: ID to test for unauthorized access
            
        Returns:
            BOLAResult object
        """
        original_url = endpoint.replace(original_id, str(original_id))
        test_url = endpoint.replace(original_id, str(test_id))
        
        try:
            original_response = self.session.get(
                original_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            original_status = original_response.status_code
            
            time.sleep(0.1)
            
            test_response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            tested_status = test_response.status_code
            
            vulnerability_found = False
            data_leaked = False
            response_difference = "No difference"
            
            if tested_status == 200:
                if original_status == 200:
                    original_length = len(original_response.content)
                    test_length = len(test_response.content)
                    
                    if abs(original_length - test_length) < 100:
                        response_difference = f"Similar response size ({original_length} vs {test_length})"
                    else:
                        response_difference = f"Different response size ({original_length} vs {test_length})"
                        data_leaked = True
                    
                    original_content_type = original_response.headers.get('Content-Type', '')
                    test_content_type = test_response.headers.get('Content-Type', '')
                    
                    if 'application/json' in original_content_type and \
                       'application/json' in test_content_type:
                        try:
                            original_json = original_response.json()
                            test_json = test_response.json()
                            
                            if isinstance(test_json, dict) and test_json:
                                vulnerability_found = True
                                data_leaked = True
                                response_difference = "JSON data returned for different ID"
                            elif isinstance(test_json, list) and test_json:
                                vulnerability_found = True
                                data_leaked = True
                                response_difference = "JSON array returned for different ID"
                        except (ValueError, json.JSONDecodeError):
                            pass
                    else:
                        if test_length > 100:
                            vulnerability_found = True
                            data_leaked = True
                else:
                    vulnerability_found = True
                    data_leaked = True
                    response_difference = f"Access granted to resource {test_id}"
            
            result = BOLAResult(
                endpoint=endpoint,
                original_id=original_id,
                tested_id=test_id,
                original_status=original_status,
                tested_status=tested_status,
                vulnerability_found=vulnerability_found,
                response_difference=response_difference,
                data_leaked=data_leaked,
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Request failed: {str(e)}")
            
            return BOLAResult(
                endpoint=endpoint,
                original_id=original_id,
                tested_id=test_id,
                original_status=0,
                tested_status=0,
                vulnerability_found=False,
                response_difference=f"Error: {str(e)}",
                data_leaked=False,
            )
    
    def test_endpoint_with_increments(
        self,
        endpoint: str,
        original_id: str
    ) -> List[BOLAResult]:
        """
        Test endpoint with multiple ID increment values.
        
        Args:
            endpoint: API endpoint with original ID
            original_id: Original object ID
            
        Returns:
            List of BOLAResult objects
        """
        results = []
        
        try:
            numeric_id = int(original_id)
            
            for increment in self.ID_INCREMENT_VALUES:
                if increment < 0:
                    test_id = str(numeric_id + increment)
                    if int(test_id) > 0:
                        result = self.test_endpoint(endpoint, original_id, test_id)
                        results.append(result)
                else:
                    test_id = str(numeric_id + increment)
                    result = self.test_endpoint(endpoint, original_id, test_id)
                    results.append(result)
                    
        except ValueError:
            for test_id in self.UUID_TEST_VALUES:
                result = self.test_endpoint(endpoint, original_id, test_id)
                results.append(result)
        
        return results
    
    def analyze_results(self) -> List[Dict[str, Any]]:
        """
        Analyze BOLA test results.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        for result in self.results:
            if result.vulnerability_found:
                vulnerabilities.append({
                    'type': 'Broken Object Level Authorization',
                    'severity': 'high',
                    'endpoint': result.endpoint,
                    'description': f'BOLA vulnerability allows access to resources of other users. '
                                   f'Original ID {result.original_id}, tested ID {result.tested_id} '
                                   f'returned status {result.tested_status}',
                    'evidence': result.response_difference,
                    'remediation': 'Implement proper authorization checks for all object access. '
                                   'Use indirect reference maps and verify user ownership.',
                    'data_leaked': result.data_leaked,
                })
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all BOLA tests.
        
        Returns:
            Dictionary with findings and errors
        """
        test_endpoints = [
            f"{self.target}/api/users/1",
            f"{self.target}/api/accounts/1",
            f"{self.target}/api/orders/1",
            f"{self.target}/api/profiles/1",
        ]
        
        for endpoint in test_endpoints:
            extracted = self.extract_ids_from_url(endpoint)
            
            for pattern, original_id in extracted:
                self.test_endpoint_with_increments(endpoint, original_id)
        
        vulnerabilities = self.analyze_results()
        
        findings = []
        for vuln in vulnerabilities:
            findings.append(vuln)
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(test_endpoints),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(vulnerabilities),
        }