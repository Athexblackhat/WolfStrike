# modules/vuln_scanner/cors_misconfig.py

"""
CORS Misconfiguration Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects CORS misconfigurations that allow unauthorized
cross-origin access to sensitive resources.
"""

import re
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class CORSMisconfigScanner:
    """
    CORS misconfiguration scanner.
    
    Tests for overly permissive CORS headers that
    allow unauthorized cross-origin requests.
    """
    
    TEST_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'null',
        'https://target.com.evil.com',
        'https://evil.target.com',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CORS scanner.
        
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
    
    def test_origin(self, url: str, origin: str) -> Optional[Dict[str, Any]]:
        """
        Test a CORS origin against target.
        
        Args:
            url: Target URL
            origin: Origin header value
            
        Returns:
            Dictionary with finding or None
        """
        headers = {'Origin': origin}
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao:
                is_vulnerable = False
                vuln_type = ''
                
                if acao == '*':
                    if acac.lower() == 'true':
                        is_vulnerable = True
                        vuln_type = 'wildcard_with_credentials'
                    else:
                        pass
                
                elif origin in acao or acao == 'null':
                    is_vulnerable = True
                    vuln_type = 'reflected_origin'
                
                elif 'evil.com' in acao:
                    is_vulnerable = True
                    vuln_type = 'partial_reflection'
                
                if is_vulnerable:
                    return {
                        'url': url,
                        'origin': origin,
                        'acao_header': acao,
                        'acac_header': acac,
                        'vuln_type': vuln_type,
                    }
            
            return None
            
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run CORS misconfiguration scan.
        
        Returns:
            Dictionary with scan results
        """
        for origin in self.TEST_ORIGINS:
            result = self.test_origin(self.target, origin)
            
            if result:
                self.vulnerabilities.append(result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            severity = 'high' if 'credentials' in vuln.get('vuln_type', '') else 'medium'
            
            findings.append({
                'type': 'CORS Misconfiguration',
                'severity': severity,
                'endpoint': vuln['url'],
                'description': f"CORS allows requests from '{vuln['origin']}' "
                               f"(ACAO: {vuln['acao_header']}, ACAC: {vuln['acac_header']})",
                'evidence': vuln,
                'remediation': 'Use strict CORS policy. Whitelist specific origins. '
                               'Do not use wildcard with credentials.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }