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
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


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
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-GraphQL-Tester/1.0',
            'Content-Type': 'application/json',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.graphql_endpoints: List[str] = []
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.errors: List[str] = []
        
        self.common_graphql_paths = [
            '/graphql', '/graphql/api', '/graphql/v1',
            '/gql', '/query', '/api/graphql',
            '/v1/graphql', '/v2/graphql', '/graphiql',
            '/playground', '/api/graphql/v1',
        ]
    
    def discover_endpoints(self) -> List[str]:
        """
        Discover GraphQL endpoints.
        
        Returns:
            List of discovered endpoint URLs
        """
        for path in self.common_graphql_paths:
            url = f"{self.target}{path}"
            try:
                response = self.session.post(
                    url,
                    json={'query': '{__typename}'},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__typename' in str(data['data']):
                            self.graphql_endpoints.append(url)
                    except json.JSONDecodeError:
                        if 'graphql' in response.text.lower():
                            self.graphql_endpoints.append(url)
                            
            except RequestException:
                continue
        
        return self.graphql_endpoints
    
    def test_introspection(self) -> List[GraphQLVulnerability]:
        """
        Test if GraphQL introspection is enabled.
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in self.graphql_endpoints:
            try:
                response = self.session.post(
                    endpoint,
                    json={'query': self.INTROSPECTION_QUERY},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            schema = data['data']['__schema']
                            types_count = len(schema.get('types', []))
                            
                            vulnerabilities.append(GraphQLVulnerability(
                                endpoint=endpoint,
                                vulnerability_type='Introspection Enabled',
                                severity='medium',
                                description=f'GraphQL introspection query returns schema with {types_count} types',
                                evidence=f'Schema types exposed: {types_count}',
                                remediation='Disable introspection in production environments'
                            ))
                    except (json.JSONDecodeError, KeyError):
                        pass
                        
            except RequestException:
                continue
        
        return vulnerabilities
    
    def test_depth_attack(self) -> List[GraphQLVulnerability]:
        """
        Test for query depth attacks.
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        depth_query = self._generate_deep_query(depth=10)
        
        for endpoint in self.graphql_endpoints:
            try:
                response = self.session.post(
                    endpoint,
                    json={'query': depth_query},
                    timeout=self.timeout * 2,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    vulnerabilities.append(GraphQLVulnerability(
                        endpoint=endpoint,
                        vulnerability_type='Deep Query Accepted',
                        severity='medium',
                        description='Server accepts deeply nested queries without depth limiting',
                        evidence=f'Deep query returned status {response.status_code}',
                        remediation='Implement maximum query depth limits'
                    ))
                elif response.status_code == 400:
                    pass
                    
            except RequestException:
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
    
    def test_sql_injection(self) -> List[GraphQLVulnerability]:
        """
        Test for SQL injection in GraphQL arguments.
        
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
        
        for endpoint in self.graphql_endpoints:
            for payload in sqli_payloads:
                query = f'query {{ search(q: "{payload}") {{ id name }} }}'
                
                try:
                    response = self.session.post(
                        endpoint,
                        json={'query': query},
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        sql_errors = [
                            'sql', 'mysql', 'postgresql', 'syntax error',
                            'unclosed quotation', 'ora-', 'sqlite',
                        ]
                        
                        for error in sql_errors:
                            if error in response_text:
                                vulnerabilities.append(GraphQLVulnerability(
                                    endpoint=endpoint,
                                    vulnerability_type='SQL Injection',
                                    severity='critical',
                                    description=f'SQL injection via GraphQL argument with payload: {payload}',
                                    evidence=f'SQL error detected in response',
                                    remediation='Implement parameterized queries and input validation'
                                ))
                                break
                                
                except RequestException:
                    continue
        
        return vulnerabilities
    
    def test_batching_attack(self) -> List[GraphQLVulnerability]:
        """
        Test for query batching attacks (bypass rate limiting).
        
        Returns:
            List of GraphQLVulnerability objects
        """
        vulnerabilities = []
        
        batch_query = [
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'},
        ]
        
        for endpoint in self.graphql_endpoints:
            try:
                response = self.session.post(
                    endpoint,
                    json=batch_query,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) == 10:
                            vulnerabilities.append(GraphQLVulnerability(
                                endpoint=endpoint,
                                vulnerability_type='Batch Query Accepted',
                                severity='low',
                                description='Server accepts batched queries, bypassing rate limits',
                                evidence=f'10 batched queries processed successfully',
                                remediation='Disable query batching or implement per-query rate limiting'
                            ))
                    except json.JSONDecodeError:
                        pass
                        
            except RequestException:
                continue
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all GraphQL tests.
        
        Returns:
            Dictionary with findings and errors
        """
        self.discover_endpoints()
        
        introspection_vulns = self.test_introspection()
        self.vulnerabilities.extend(introspection_vulns)
        
        depth_vulns = self.test_depth_attack()
        self.vulnerabilities.extend(depth_vulns)
        
        sqli_vulns = self.test_sql_injection()
        self.vulnerabilities.extend(sqli_vulns)
        
        batch_vulns = self.test_batching_attack()
        self.vulnerabilities.extend(batch_vulns)
        
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
        }