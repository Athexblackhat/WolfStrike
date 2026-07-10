# modules/scanner/header_analyzer.py

"""
HTTP Security Header Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes HTTP response headers for security misconfigurations
and missing security headers.
"""

from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class HeaderAnalyzer:
    """
    HTTP security header analyzer.
    
    Checks for presence and configuration of security
    headers and identifies missing protections.
    """
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'description': 'HTTP Strict Transport Security (HSTS)',
            'recommendation': 'max-age=31536000; includeSubDomains; preload',
        },
        'Content-Security-Policy': {
            'required': True,
            'description': 'Content Security Policy (CSP)',
            'recommendation': "default-src 'self'; script-src 'self'; style-src 'self'",
        },
        'X-Content-Type-Options': {
            'required': True,
            'description': 'Prevents MIME type sniffing',
            'recommendation': 'nosniff',
        },
        'X-Frame-Options': {
            'required': True,
            'description': 'Prevents clickjacking',
            'recommendation': 'DENY or SAMEORIGIN',
        },
        'X-XSS-Protection': {
            'required': False,
            'description': 'Cross-site scripting filter',
            'recommendation': '1; mode=block',
        },
        'Referrer-Policy': {
            'required': True,
            'description': 'Controls referrer information',
            'recommendation': 'strict-origin-when-cross-origin',
        },
        'Permissions-Policy': {
            'required': False,
            'description': 'Controls browser features',
            'recommendation': 'geolocation=(), microphone=(), camera=()',
        },
        'Cache-Control': {
            'required': False,
            'description': 'Caching directives',
            'recommendation': 'no-cache, no-store, must-revalidate',
        },
    }
    
    INFORMATION_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version',
        'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache',
        'X-Drupal-Dynamic-Cache',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the header analyzer.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.errors: List[str] = []
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze HTTP response headers.
        
        Returns:
            Dictionary with analysis results
        """
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            headers = dict(response.headers)
            
            security_analysis = {}
            
            for header_name, config in self.SECURITY_HEADERS.items():
                header_value = ''
                
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        header_value = h_value
                        break
                
                security_analysis[header_name] = {
                    'present': bool(header_value),
                    'value': header_value,
                    'description': config['description'],
                    'recommendation': config['recommendation'],
                    'required': config['required'],
                }
            
            info_disclosure = {}
            
            for header_name in self.INFORMATION_HEADERS:
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        info_disclosure[header_name] = h_value
                        break
            
            return {
                'security_headers': security_analysis,
                'information_disclosure': info_disclosure,
                'all_headers': headers,
            }
            
        except RequestException as e:
            self.errors.append(f"Header analysis failed: {str(e)}")
            return {
                'security_headers': {},
                'information_disclosure': {},
                'all_headers': {},
            }
    
    def run(self) -> Dict[str, Any]:
        """
        Run header analysis.
        
        Returns:
            Dictionary with analysis results
        """
        analysis = self.analyze()
        
        findings = []
        
        missing_headers = []
        for header_name, info in analysis.get('security_headers', {}).items():
            if info['required'] and not info['present']:
                missing_headers.append({
                    'header': header_name,
                    'description': info['description'],
                    'recommendation': info['recommendation'],
                })
        
        if missing_headers:
            findings.append({
                'type': 'Missing Security Headers',
                'severity': 'medium',
                'target': self.target,
                'description': f'Missing {len(missing_headers)} critical security headers',
                'evidence': missing_headers,
                'remediation': 'Implement missing security headers for improved protection',
            })
        
        info_disclosure = analysis.get('information_disclosure', {})
        
        if info_disclosure:
            findings.append({
                'type': 'Server Information Disclosure',
                'severity': 'low',
                'target': self.target,
                'description': f'Server reveals technology information in headers',
                'evidence': info_disclosure,
                'remediation': 'Remove or obfuscate server information headers',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'security_headers': analysis.get('security_headers', {}),
            'information_disclosure': info_disclosure,
        }