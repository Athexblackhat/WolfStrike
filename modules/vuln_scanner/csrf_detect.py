# modules/vuln_scanner/csrf_detect.py

"""
CSRF Vulnerability Detector
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects Cross-Site Request Forgery vulnerabilities
by checking for missing anti-CSRF tokens.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


class CSRFDetector:
    """
    Cross-Site Request Forgery detector.
    
    Checks forms for anti-CSRF token presence and
    validates token implementation.
    """
    
    CSRF_TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrf-token', '_csrf',
        'xsrf', '_token', 'authenticity_token',
        'csrfmiddlewaretoken', '__RequestVerificationToken',
        'nonce', '_wpnonce',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CSRF detector.
        
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
        
        self.vulnerable_forms: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def analyze_page(self, url: str) -> List[Dict[str, Any]]:
        """
        Analyze page for forms without CSRF protection.
        
        Args:
            url: Page URL
            
        Returns:
            List of vulnerable form dictionaries
        """
        vulnerable = []
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                form_url = urljoin(url, action) if action else url
                
                if method == 'GET':
                    continue
                
                has_csrf_token = False
                token_field = ''
                
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '')
                    input_type = input_tag.get('type', 'hidden')
                    
                    if input_type == 'hidden':
                        for token_name in self.CSRF_TOKEN_NAMES:
                            if token_name.lower() in input_name.lower():
                                has_csrf_token = True
                                token_field = input_name
                                break
                
                csrf_header_found = False
                meta_tags = soup.find_all('meta')
                
                for meta in meta_tags:
                    meta_name = meta.get('name', '').lower()
                    
                    for token_name in self.CSRF_TOKEN_NAMES:
                        if token_name.lower() in meta_name:
                            csrf_header_found = True
                            break
                
                if not has_csrf_token and not csrf_header_found:
                    vulnerable.append({
                        'action': form_url,
                        'method': method,
                        'page_url': url,
                        'has_csrf_token': False,
                        'has_csrf_meta': csrf_header_found,
                    })
            
            return vulnerable
            
        except RequestException as e:
            self.errors.append(f"Page analysis failed: {str(e)}")
            return []
    
    def run(self) -> Dict[str, Any]:
        """
        Run CSRF detection.
        
        Returns:
            Dictionary with detection results
        """
        test_urls = [
            self.target,
            f"{self.target}/login",
            f"{self.target}/register",
            f"{self.target}/contact",
        ]
        
        for url in test_urls:
            vulnerable = self.analyze_page(url)
            self.vulnerable_forms.extend(vulnerable)
        
        findings = []
        
        for form in self.vulnerable_forms:
            findings.append({
                'type': 'Cross-Site Request Forgery (CSRF)',
                'severity': 'medium',
                'endpoint': form['action'],
                'description': f"Form at {form['page_url']} ({form['method']}) lacks CSRF protection",
                'evidence': form,
                'remediation': 'Implement anti-CSRF tokens in all state-changing forms. Use SameSite cookies.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'vulnerable_forms': len(self.vulnerable_forms),
        }