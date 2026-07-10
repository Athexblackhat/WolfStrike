# modules/vuln_scanner/clickjacking.py

"""
Clickjacking Vulnerability Detector
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects clickjacking vulnerabilities by checking
for missing X-Frame-Options and CSP frame-ancestors.
"""

import re
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class ClickjackingDetector:
    """
    Clickjacking vulnerability detector.
    
    Checks HTTP headers for anti-clickjacking
    protections and identifies vulnerable pages.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the clickjacking detector.
        
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
        
        self.vulnerable_pages: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def check_page(self, url: str) -> Dict[str, Any]:
        """
        Check a page for clickjacking protections.
        
        Args:
            url: Page URL
            
        Returns:
            Dictionary with check results
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            x_frame_options = headers.get('x-frame-options', '')
            csp_header = headers.get('content-security-policy', '')
            
            has_x_frame = bool(x_frame_options)
            has_csp_frame_ancestors = 'frame-ancestors' in csp_header.lower()
            
            x_frame_valid = False
            if has_x_frame:
                x_frame_lower = x_frame_options.lower()
                x_frame_valid = (
                    'deny' in x_frame_lower or
                    'sameorigin' in x_frame_lower
                )
            
            is_protected = has_x_frame or has_csp_frame_ancestors
            is_vulnerable = not is_protected or (has_x_frame and not x_frame_valid)
            
            return {
                'url': url,
                'vulnerable': is_vulnerable,
                'x_frame_options': x_frame_options,
                'has_csp_frame_ancestors': has_csp_frame_ancestors,
                'csp_header': csp_header[:200] if csp_header else '',
                'protected_by': 'X-Frame-Options' if has_x_frame else 'CSP' if has_csp_frame_ancestors else 'None',
            }
            
        except RequestException as e:
            self.errors.append(f"Page check failed: {str(e)}")
            return {'url': url, 'vulnerable': True, 'error': str(e)}
    
    def run(self) -> Dict[str, Any]:
        """
        Run clickjacking detection.
        
        Returns:
            Dictionary with detection results
        """
        test_urls = [
            self.target,
            f"{self.target}/login",
            f"{self.target}/admin",
            f"{self.target}/dashboard",
        ]
        
        for url in test_urls:
            result = self.check_page(url)
            
            if result.get('vulnerable'):
                self.vulnerable_pages.append(result)
        
        findings = []
        
        for page in self.vulnerable_pages:
            findings.append({
                'type': 'Clickjacking Vulnerability',
                'severity': 'medium',
                'endpoint': page['url'],
                'description': f"Page lacks clickjacking protection. "
                               f"Current: {page['protected_by']}",
                'evidence': page,
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN header. '
                               'Use CSP frame-ancestors directive.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'pages_checked': len(test_urls),
            'vulnerable_pages': len(self.vulnerable_pages),
        }