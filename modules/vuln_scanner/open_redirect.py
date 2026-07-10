# modules/vuln_scanner/open_redirect.py

"""
Open Redirect Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects open redirect vulnerabilities through
parameter manipulation and redirect analysis.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class OpenRedirectScanner:
    """
    Open redirect vulnerability scanner.
    
    Tests for open redirect vulnerabilities using
    external URLs in redirect parameters.
    """
    
    REDIRECT_PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        'https:evil.com',
        'https://evil.com%40target.com',
        'https://target.com.evil.com',
        'https://target.com@evil.com',
        '\\\\evil.com',
    ]
    
    REDIRECT_PARAMETERS = [
        'redirect', 'url', 'return', 'next', 'goto',
        'returnUrl', 'redirectUrl', 'redirect_uri',
        'callback', 'target', 'r', 'redir', 'destination',
        'continue', 'forward', 'to', 'link', 'ref',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the open redirect scanner.
        
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
        Test a single parameter for open redirect.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.REDIRECT_PAYLOADS[:5]:
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
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if 'evil.com' in location:
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'location': location,
                            'status_code': response.status_code,
                        }
                    
            except RequestException:
                continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run open redirect scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        test_params = [p for p in params if any(rp in p.lower() for rp in self.REDIRECT_PARAMETERS)]
        
        if not test_params:
            test_params = list(params.keys())[:5]
        
        for param_name in test_params:
            result = self.test_parameter(self.target, param_name)
            
            if result:
                self.vulnerabilities.append(result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': 'Open Redirect',
                'severity': 'medium',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"Open redirect via parameter '{vuln['parameter']}' redirects to '{vuln['location']}'",
                'evidence': vuln,
                'remediation': 'Validate redirect URLs against whitelist. Use relative paths. Avoid user-controlled redirects.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }