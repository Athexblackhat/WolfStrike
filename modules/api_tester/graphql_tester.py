# modules/api_tester/graphql_tester.py

"""
GraphQL API Security Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests GraphQL APIs for introspection, query depth,
injection, and authorization vulnerabilities.
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


@dataclass
class GraphQLVulnerability:
    """Represents a GraphQL vulnerability."""
    endpoint: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    remediation: str


class GraphQLTester:
    """
    GraphQL API security testing engine.
    
    Tests GraphQL endpoints for common vulnerabilities
    including introspection, depth attacks, injection,
    and authorization bypasses.
    """
    
    INTROSPECTION_QUERY = """
    query {
        __schema {
            types {
                name
                fields {
                    name
                    type {
                        name
                        kind
                        ofType {
                            name
                            kind
                        }
                    }
                }
            }
        }
    }
    """
    
    DEPTH_ATTACK_QUERY = """
    query {
        __typename
        %s
    }
    """
    
    SQL_ERROR_INDICATORS = [
        'sql', 'mysql', 'postgresql', 'syntax error',
        'unclosed quotation', 'ora-', 'sqlite',
        'database error', 'SQL syntax', 'SQLException',
        'syntax error', 'unclosed string',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the GraphQL tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/') if target else ''
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-GraphQL-Tester/1.0',
            'Content-Type': 'application/json',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_endpoints = self.config.get('max_endpoints', 20)
        
        self.graphql_endpoints: List[str] = []
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        
        self.common_graphql_paths = [
            '/graphql', '/graphql/api', '/graphql/v1',
            '/gql', '/query', '/api/graphql',
            '/v1/graphql', '/v2/graphql', '/graphiql',
            '/playground', '/api/graphql/v1',
        ]
    
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
    
    def _safe_post_request(self, url: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        """
        Safely send POST request.
        
        Args:
            url: Target URL
            data: Request data
            
        Returns:
            HTTP response or None
        """
        try:
            return self.session.post(
                url,
                json=data,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
        except (Timeout, ConnectionError) as e:
            self.errors.append(f"Request timeout/connection error: {str(e)}")
            return None
        except RequestException as e:
            self.errors.append(f"Request failed: {str(e)}")
            return None
    
    def _safe_json_parse(self, response: requests.Response) -> Optional[Dict[str, Any]]:
        """
        Safely parse JSON response.
        
        Args:
            response: HTTP response
            
        Returns:
            Parsed JSON or None
        """
        if not response.text:
            return None
        
        try:
            return response.json()
        except json.JSONDecodeError:
            return None
    
    def _validate_endpoint(self, endpoint: str) -> bool:
        """
        Validate endpoint URL.
        
        Args:
            endpoint: Endpoint URL
            
        Returns:
            True if endpoint is valid
        """
        if not endpoint:
            return False
        
        if not endpoint.startswith(('http://', 'https://')):
            return False
        
        return True
    
    def _check_response_for_errors(self, response_text: str, indicators: List[str]) -> bool:
        """
        Check response for error indicators.
        
        Args:
            response_text: HTTP response text
            indicators: List of indicator strings
            
        Returns:
            True if any indicator found
        """
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True
        
        return False
    
    def _discover_endpoints_safe(self) -> List[str]:
        """
        Safely discover GraphQL endpoints.
        
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        for path in self.common_graphql_paths:
            if len(endpoints) >= self.max_endpoints:
                break
            
            url = f"{self.target}{path}"
            
            if not self._validate_endpoint(url):
                continue
            
            response = self._safe_post_request(url, {'query': '{__typename}'})
            
            if not self._is_valid_response(response):
                continue
            
            if response.status_code != 200:
                continue
            
            parsed_data = self._safe_json_parse(response)
            
            if parsed_data:
                if 'data' in parsed_data and '__typename' in str(parsed_data['data']):
                    endpoints.append(url)
                    continue
            
            # Check if response contains GraphQL-related text
            if response.text and 'graphql' in response.text.lower():
                endpoints.append(url)
        
        return endpoints
    
    def discover_endpoints(self) -> List[str]:
        """
        Discover GraphQL endpoints.
        
        Returns:
            List of discovered endpoint URLs
        """
        self.graphql_endpoints = self._discover_endpoints_safe()
        return self.graphql_endpoints
    
    def _test_introspection_safe(self, endpoint: str) -> Optional[GraphQLVulnerability]:
        """
        Safely test introspection on a single endpoint.
        
        Args:
            endpoint: GraphQL endpoint
            
        Returns:
            GraphQLVulnerability or None
        """
        response = self._safe_post_request(endpoint, {'query': self.INTROSPECTION_QUERY})
        
        if not self._is_valid_response(response):
            return None
        
        if response.status_code != 200:
            return None
        
        parsed_data = self._safe_json_parse(response)
        
        if not parsed_data:
            return None
        
        if 'data' in parsed_data and '__schema' in parsed_data['data']:
            schema = parsed_data['data']['__schema']
            types_count = len(schema.get('types', []))
            
            return GraphQLVulnerability(
                endpoint=endpoint,
                vulnerability_type='Introspection Enabled',
                severity='medium',
                description=f'GraphQL introspection query returns schema with {types_count} types',
                evidence=f'Schema types exposed: {types_count}',
                remediation='Disable introspection in production environments'
            )
        
        return None
    
    def test_introspection(self) -> List[GraphQLVulnerability]:
        """
        Test if GraphQL introspection is enabled.
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in self.graphql_endpoints:
            try:
                result = self._test_introspection_safe(endpoint)
                if result:
                    vulnerabilities.append(result)
            except Exception as e:
                self.errors.append(f"Introspection test failed for {endpoint}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def _generate_deep_query(self, depth: int) -> str:
        """
        Generate a deeply nested GraphQL query.
        
        Args:
            depth: Nesting depth
            
        Returns:
            Deep query string
        """
        base = "__typename"
        for _ in range(depth):
            base = f"q {{ {base} }}"
        
        return f"query {base}"
    
    def _test_depth_attack_safe(self, endpoint: str, depth: int = 10) -> Optional[GraphQLVulnerability]:
        """
        Safely test depth attack on a single endpoint.
        
        Args:
            endpoint: GraphQL endpoint
            depth: Query depth
            
        Returns:
            GraphQLVulnerability or None
        """
        depth_query = self._generate_deep_query(depth)
        
        try:
            # Use extended timeout for deep query
            response = self.session.post(
                endpoint,
                json={'query': depth_query},
                timeout=self.timeout * 2,
                verify=self.verify_ssl
            )
        except (Timeout, ConnectionError):
            return GraphQLVulnerability(
                endpoint=endpoint,
                vulnerability_type='Depth Attack Timeout',
                severity='info',
                description='Deep query caused timeout - may indicate depth limiting',
                evidence='Request timed out on deep query',
                remediation='Verify that depth limiting is properly configured'
            )
        except RequestException:
            return None
        
        if not self._is_valid_response(response):
            return None
        
        if response.status_code == 200:
            return GraphQLVulnerability(
                endpoint=endpoint,
                vulnerability_type='Deep Query Accepted',
                severity='medium',
                description='Server accepts deeply nested queries without depth limiting',
                evidence=f'Deep query returned status {response.status_code}',
                remediation='Implement maximum query depth limits'
            )
        elif response.status_code == 400:
            # 400 may indicate query was rejected (good)
            pass
        
        return None
    
    def test_depth_attack(self) -> List[GraphQLVulnerability]:
        """
        Test for query depth attacks.
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in self.graphql_endpoints:
            try:
                result = self._test_depth_attack_safe(endpoint, depth=10)
                if result:
                    vulnerabilities.append(result)
            except Exception as e:
                self.errors.append(f"Depth attack test failed for {endpoint}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def _test_sql_injection_safe(self, endpoint: str) -> List[GraphQLVulnerability]:
        """
        Safely test SQL injection on a single endpoint.
        
        Args:
            endpoint: GraphQL endpoint
            
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "admin' --",
        ]
        
        for payload in sqli_payloads:
            query = f'query {{ search(q: "{payload}") {{ id name }} }}'
            
            response = self._safe_post_request(endpoint, {'query': query})
            
            if not self._is_valid_response(response):
                continue
            
            if response.status_code != 200:
                continue
            
            response_text = self._safe_json_parse(response)
            
            if response_text and isinstance(response_text, dict):
                # Check for errors in response
                if 'errors' in response_text:
                    error_text = str(response_text['errors'])
                    if self._check_response_for_errors(error_text, self.SQL_ERROR_INDICATORS):
                        vulnerabilities.append(GraphQLVulnerability(
                            endpoint=endpoint,
                            vulnerability_type='SQL Injection',
                            severity='critical',
                            description=f'SQL injection via GraphQL argument with payload: {payload}',
                            evidence=f'SQL error detected in response',
                            remediation='Implement parameterized queries and input validation'
                        ))
                        break
                
                # Also check response data
                response_data = response_text.get('data', {})
                if isinstance(response_data, dict):
                    data_str = str(response_data)
                    if self._check_response_for_errors(data_str, self.SQL_ERROR_INDICATORS):
                        vulnerabilities.append(GraphQLVulnerability(
                            endpoint=endpoint,
                            vulnerability_type='SQL Injection',
                            severity='critical',
                            description=f'SQL injection via GraphQL argument with payload: {payload}',
                            evidence=f'SQL error detected in response data',
                            remediation='Implement parameterized queries and input validation'
                        ))
                        break
        
        return vulnerabilities
    
    def test_sql_injection(self) -> List[GraphQLVulnerability]:
        """
        Test for SQL injection in GraphQL arguments.
        
        Returns:
            List of GraphQLVulnerability objects
        """
        all_vulnerabilities = []
        
        for endpoint in self.graphql_endpoints:
            try:
                vulns = self._test_sql_injection_safe(endpoint)
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                self.errors.append(f"SQL injection test failed for {endpoint}: {str(e)}")
                continue
        
        return all_vulnerabilities
    
    def _test_batching_attack_safe(self, endpoint: str) -> Optional[GraphQLVulnerability]:
        """
        Safely test batching attack on a single endpoint.
        
        Args:
            endpoint: GraphQL endpoint
            
        Returns:
            GraphQLVulnerability or None
        """
        batch_query = [
            {'query': '{__typename}'} for _ in range(10)
        ]
        
        response = self._safe_post_request(endpoint, batch_query)
        
        if not self._is_valid_response(response):
            return None
        
        if response.status_code != 200:
            return None
        
        parsed_data = self._safe_json_parse(response)
        
        if not parsed_data:
            return None
        
        if isinstance(parsed_data, list) and len(parsed_data) == 10:
            return GraphQLVulnerability(
                endpoint=endpoint,
                vulnerability_type='Batch Query Accepted',
                severity='low',
                description='Server accepts batched queries, bypassing rate limits',
                evidence=f'10 batched queries processed successfully',
                remediation='Disable query batching or implement per-query rate limiting'
            )
        
        return None
    
    def test_batching_attack(self) -> List[GraphQLVulnerability]:
        """
        Test for query batching attacks (bypass rate limiting).
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in self.graphql_endpoints:
            try:
                result = self._test_batching_attack_safe(endpoint)
                if result:
                    vulnerabilities.append(result)
            except Exception as e:
                self.errors.append(f"Batching attack test failed for {endpoint}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all GraphQL tests.
        
        Returns:
            Dictionary with findings and errors
        """
        # Reset state
        self.graphql_endpoints.clear()
        self.vulnerabilities.clear()
        self.errors.clear()
        self.scan_status = 'running'
        
        # Validate target
        if not self.target:
            self.errors.append("Target is empty")
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'endpoints_discovered': 0,
                'vulnerabilities_found': 0,
                'scan_status': 'failed',
                'error': 'Target is empty',
            }
        
        # Discover endpoints
        self.discover_endpoints()
        
        if not self.graphql_endpoints:
            self.scan_status = 'completed'
            return {
                'findings': [],
                'errors': self.errors,
                'endpoints_discovered': 0,
                'vulnerabilities_found': 0,
                'scan_status': 'completed',
                'message': 'No GraphQL endpoints discovered',
            }
        
        # Run tests
        introspection_vulns = self.test_introspection()
        self.vulnerabilities.extend(introspection_vulns)
        
        depth_vulns = self.test_depth_attack()
        self.vulnerabilities.extend(depth_vulns)
        
        sqli_vulns = self.test_sql_injection()
        self.vulnerabilities.extend(sqli_vulns)
        
        batch_vulns = self.test_batching_attack()
        self.vulnerabilities.extend(batch_vulns)
        
        self.scan_status = 'completed'
        
        findings = []
        for vuln in self.vulnerabilities:
            findings.append({
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'endpoint': vuln.endpoint,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_discovered': len(self.graphql_endpoints),
            'vulnerabilities_found': len(self.vulnerabilities),
            'scan_status': self.scan_status,
            'endpoints': self.graphql_endpoints,
        }
