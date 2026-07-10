# modules/api_tester/mass_assignment.py

"""
Mass Assignment Vulnerability Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests API endpoints for mass assignment vulnerabilities
by attempting to modify protected fields through
parameter injection in request bodies.
"""

import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class MassAssignmentResult:
    """Represents a mass assignment test result."""
    endpoint: str
    parameter: str
    original_value: Any
    injected_value: Any
    success: bool
    response_status: int
    response_data: Dict[str, Any]


class MassAssignmentTester:
    """
    Mass assignment vulnerability tester.
    
    Tests API endpoints for improper access control on
    object properties during create/update operations.
    """
    
    PRIVILEGED_FIELDS = [
        'role', 'is_admin', 'is_superuser', 'is_staff',
        'admin', 'superuser', 'permissions', 'access_level',
        'account_type', 'subscription', 'plan', 'tier',
        'credit', 'balance', 'amount', 'price',
        'verified', 'is_verified', 'email_verified',
        'active', 'is_active', 'enabled', 'disabled',
        'approved', 'is_approved', 'moderator',
        'owner_id', 'user_id', 'company_id', 'org_id',
        'api_key', 'secret', 'token', 'password_hash',
    ]
    
    TEST_VALUES = {
        'boolean': True,
        'integer': 999999,
        'string': 'INJECTED_VALUE',
        'array': ['test'],
        'object': {'test': 'value'},
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the mass assignment tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-MassAssign-Tester/1.0',
            'Content-Type': 'application/json',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.results: List[MassAssignmentResult] = []
        self.errors: List[str] = []
        self.auth_token: Optional[str] = self.config.get('auth_token')
        
        if self.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def test_endpoint(
        self,
        endpoint: str,
        method: str = 'POST',
        base_body: Optional[Dict[str, Any]] = None
    ) -> List[MassAssignmentResult]:
        """
        Test an endpoint for mass assignment vulnerabilities.
        
        Args:
            endpoint: Target endpoint URL
            method: HTTP method
            base_body: Base request body
            
        Returns:
            List of MassAssignmentResult objects
        """
        results = []
        
        if base_body is None:
            base_body = {
                'name': 'test_user',
                'email': 'test@example.com',
                'password': 'TestPassword123!',
            }
        
        for field in self.PRIVILEGED_FIELDS:
            for value_type, test_value in self.TEST_VALUES.items():
                test_body = base_body.copy()
                test_body[field] = test_value
                
                try:
                    response = self.session.request(
                        method,
                        endpoint,
                        json=test_body,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    response_data = {}
                    try:
                        response_data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        response_data = {'raw': response.text[:500]}
                    
                    success = self._check_exploitation(
                        response_data, field, test_value
                    )
                    
                    result = MassAssignmentResult(
                        endpoint=endpoint,
                        parameter=field,
                        original_value=None,
                        injected_value=test_value,
                        success=success,
                        response_status=response.status_code,
                        response_data=response_data,
                    )
                    
                    results.append(result)
                    
                    if success:
                        break
                        
                except RequestException as e:
                    self.errors.append(f"Request failed for {field}: {str(e)}")
                    continue
        
        self.results.extend(results)
        return results
    
    def _check_exploitation(
        self,
        response_data: Dict[str, Any],
        field: str,
        injected_value: Any
    ) -> bool:
        """
        Check if mass assignment was successful.
        
        Args:
            response_data: API response data
            field: Injected field name
            injected_value: Injected value
            
        Returns:
            True if exploitation successful
        """
        if field in response_data:
            if response_data[field] == injected_value:
                return True
        
        for key, value in response_data.items():
            if isinstance(value, dict):
                if field in value and value[field] == injected_value:
                    return True
            elif key.lower() == field.lower() and value == injected_value:
                return True
        
        return False
    
    def test_update_endpoint(
        self,
        endpoint: str,
        item_id: str,
        base_body: Optional[Dict[str, Any]] = None
    ) -> List[MassAssignmentResult]:
        """
        Test an update endpoint for mass assignment.
        
        Args:
            endpoint: Target endpoint URL (with ID placeholder)
            item_id: Item ID to update
            base_body: Base request body
            
        Returns:
            List of MassAssignmentResult objects
        """
        update_url = endpoint.rstrip('/') + f'/{item_id}'
        return self.test_endpoint(update_url, method='PUT', base_body=base_body)
    
    def test_patch_endpoint(
        self,
        endpoint: str,
        item_id: str,
        base_body: Optional[Dict[str, Any]] = None
    ) -> List[MassAssignmentResult]:
        """
        Test a PATCH endpoint for mass assignment.
        
        Args:
            endpoint: Target endpoint URL (with ID placeholder)
            item_id: Item ID to patch
            base_body: Base request body
            
        Returns:
            List of MassAssignmentResult objects
        """
        update_url = endpoint.rstrip('/') + f'/{item_id}'
        return self.test_endpoint(update_url, method='PATCH', base_body=base_body)
    
    def analyze_results(self) -> List[Dict[str, Any]]:
        """
        Analyze mass assignment test results.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        successful_injections: Dict[str, List[str]] = {}
        
        for result in self.results:
            if result.success:
                if result.endpoint not in successful_injections:
                    successful_injections[result.endpoint] = []
                successful_injections[result.endpoint].append(result.parameter)
        
        for endpoint, params in successful_injections.items():
            vulnerabilities.append({
                'type': 'Mass Assignment',
                'severity': 'high',
                'endpoint': endpoint,
                'description': f'Mass assignment vulnerability allows modification of '
                               f'privileged fields: {", ".join(params)}',
                'evidence': f'Successfully injected {len(params)} privileged parameters',
                'remediation': 'Implement whitelist-based property binding and '
                               'explicit field assignment',
                'affected_parameters': params,
            })
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all mass assignment tests.
        
        Returns:
            Dictionary with findings and errors
        """
        common_endpoints = [
            f"{self.target}/api/users",
            f"{self.target}/api/register",
            f"{self.target}/api/accounts",
            f"{self.target}/api/v1/users",
        ]
        
        for endpoint in common_endpoints:
            self.test_endpoint(endpoint)
        
        vulnerabilities = self.analyze_results()
        
        findings = []
        for vuln in vulnerabilities:
            findings.append(vuln)
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(common_endpoints),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(vulnerabilities),
        }