# modules/scanner/cookie_analyzer.py

"""
Cookie Security Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes cookies for security attributes including
Secure, HttpOnly, SameSite flags and session management.
"""

from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class CookieAnalyzer:
    """
    Cookie security analyzer.
    
    Checks cookies for security attributes and
    identifies insecure configurations.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the cookie analyzer.
        
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
    
    def analyze_cookie(self, cookie: Any) -> Dict[str, Any]:
        """
        Analyze a single cookie for security attributes.
        
        Args:
            cookie: Cookie object
            
        Returns:
            Dictionary with cookie analysis
        """
        issues = []
        
        analysis = {
            'name': cookie.name,
            'value_length': len(cookie.value),
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly'),
            'samesite': 'Not Set',
            'path': cookie.path if cookie.path else '/',
            'domain': cookie.domain if cookie.domain else 'Not Set',
            'expires': str(cookie.expires) if cookie.expires else 'Session',
        }
        
        if not analysis['secure']:
            issues.append('Missing Secure flag - cookie transmitted over HTTP')
        
        if not analysis['httponly']:
            issues.append('Missing HttpOnly flag - accessible via JavaScript')
        
        set_cookie_raw = ''
        if hasattr(cookie, '__dict__'):
            set_cookie_raw = str(cookie.__dict__)
        
        if 'samesite' in set_cookie_raw.lower():
            if 'samesite=none' in set_cookie_raw.lower():
                analysis['samesite'] = 'None'
                if not analysis['secure']:
                    issues.append('SameSite=None requires Secure flag')
            elif 'samesite=lax' in set_cookie_raw.lower():
                analysis['samesite'] = 'Lax'
            elif 'samesite=strict' in set_cookie_raw.lower():
                analysis['samesite'] = 'Strict'
        else:
            issues.append('Missing SameSite attribute')
        
        if analysis['value_length'] < 16 and any(
            keyword in analysis['name'].lower()
            for keyword in ['session', 'auth', 'token', 'sid']
        ):
            issues.append('Short session cookie value - possible weak entropy')
        
        analysis['issues'] = issues
        analysis['is_secure'] = len(issues) == 0
        
        return analysis
    
    def run(self) -> Dict[str, Any]:
        """
        Run cookie analysis.
        
        Returns:
            Dictionary with analysis results
        """
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            cookie_analyses = []
            
            for cookie in response.cookies:
                analysis = self.analyze_cookie(cookie)
                cookie_analyses.append(analysis)
            
            set_cookie_headers = []
            for header_name, header_value in response.headers.items():
                if header_name.lower() == 'set-cookie':
                    set_cookie_headers.append(header_value)
            
            findings = []
            
            insecure_cookies = [c for c in cookie_analyses if not c['is_secure']]
            
            if insecure_cookies:
                for cookie in insecure_cookies:
                    findings.append({
                        'type': 'Insecure Cookie Configuration',
                        'severity': 'medium',
                        'target': self.target,
                        'description': f"Cookie '{cookie['name']}' has security issues",
                        'evidence': {
                            'cookie': cookie['name'],
                            'issues': cookie['issues'],
                        },
                        'remediation': 'Set Secure, HttpOnly, and SameSite=Lax on all cookies',
                    })
            
            session_cookies = [
                c for c in cookie_analyses
                if any(kw in c['name'].lower() for kw in ['session', 'auth', 'token', 'sid', 'jsessionid'])
            ]
            
            if session_cookies:
                findings.append({
                    'type': 'Session Cookies Identified',
                    'severity': 'info',
                    'target': self.target,
                    'description': f'Found {len(session_cookies)} session cookies',
                    'evidence': [{'name': c['name'], 'secure': c['secure'], 'httponly': c['httponly']} for c in session_cookies],
                    'remediation': 'Ensure all session cookies have Secure, HttpOnly, and SameSite flags',
                })
            
            return {
                'findings': findings,
                'errors': self.errors,
                'target': self.target,
                'cookies': cookie_analyses,
                'set_cookie_headers': set_cookie_headers,
                'total_cookies': len(cookie_analyses),
            }
            
        except RequestException as e:
            self.errors.append(f"Cookie analysis failed: {str(e)}")
            return {
                'findings': [],
                'errors': self.errors,
                'cookies': [],
            }