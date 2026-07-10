# modules/auth_tester/session_tester.py

"""
Session Management Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests session management for vulnerabilities including
session fixation, insecure cookies, session timeout,
and logout issues.
"""

import time
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class SessionTestResult:
    """Represents a session test result."""
    url: str
    test_type: str
    cookie_name: str
    cookie_value: str
    secure_flag: bool
    http_only_flag: bool
    same_site_flag: str
    vulnerability_found: bool
    description: str


class SessionTester:
    """
    Session management vulnerability tester.
    
    Tests session handling for common security issues
    including cookie attributes, session fixation,
    timeout, and logout vulnerabilities.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the session tester.
        
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
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.test_credentials = self.config.get('test_credentials', {})
        
        self.results: List[SessionTestResult] = []
        self.errors: List[str] = []
    
    def analyze_cookie(
        self,
        cookie_name: str,
        cookie_value: str,
        cookie_attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze a cookie for security attributes.
        
        Args:
            cookie_name: Cookie name
            cookie_value: Cookie value
            cookie_attributes: Cookie attributes
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'name': cookie_name,
            'value_length': len(cookie_value),
            'secure': cookie_attributes.get('secure', False),
            'httponly': cookie_attributes.get('httponly', False),
            'samesite': cookie_attributes.get('samesite', 'Not Set'),
            'path': cookie_attributes.get('path', '/'),
            'domain': cookie_attributes.get('domain', 'Not Set'),
            'expires': cookie_attributes.get('expires', None),
            'is_session_cookie': cookie_attributes.get('expires') is None,
            'issues': [],
        }
        
        if not analysis['secure']:
            analysis['issues'].append('Missing Secure flag')
        
        if not analysis['httponly']:
            analysis['issues'].append('Missing HttpOnly flag')
        
        if analysis['samesite'] == 'Not Set':
            analysis['issues'].append('Missing SameSite attribute')
        
        if len(cookie_value) < 16:
            analysis['issues'].append('Short session ID (weak entropy)')
        
        if analysis['domain'] != 'Not Set':
            if analysis['domain'].startswith('.'):
                analysis['issues'].append('Overly permissive domain scope')
        
        return analysis
    
    def test_cookie_attributes(self, url: str) -> List[Dict[str, Any]]:
        """
        Test session cookie security attributes.
        
        Args:
            url: Target URL
            
        Returns:
            List of cookie analysis dictionaries
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            cookie_analyses = []
            
            for cookie in response.cookies:
                cookie_attrs = {
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': 'Not Set',
                    'path': cookie.path,
                    'domain': cookie.domain,
                    'expires': cookie.expires,
                }
                
                analysis = self.analyze_cookie(
                    cookie.name, cookie.value, cookie_attrs
                )
                
                cookie_analyses.append(analysis)
            
            for header, value in response.headers.items():
                if header.lower() == 'set-cookie':
                    cookie_analyses.append({
                        'raw_header': value,
                        'issues': self._analyze_set_cookie_header(value),
                    })
            
            return cookie_analyses
            
        except RequestException as e:
            self.errors.append(f"Cookie attribute test failed: {str(e)}")
            return []
    
    def _analyze_set_cookie_header(self, header_value: str) -> List[str]:
        """
        Analyze Set-Cookie header for security issues.
        
        Args:
            header_value: Set-Cookie header value
            
        Returns:
            List of security issues
        """
        issues = []
        header_lower = header_value.lower()
        
        if 'secure' not in header_lower:
            issues.append('Missing Secure flag in Set-Cookie')
        
        if 'httponly' not in header_lower:
            issues.append('Missing HttpOnly flag in Set-Cookie')
        
        if 'samesite' not in header_lower:
            issues.append('Missing SameSite attribute in Set-Cookie')
        
        if 'samesite=none' in header_lower and 'secure' not in header_lower:
            issues.append('SameSite=None requires Secure flag')
        
        return issues
    
    def test_session_fixation(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = 'username',
        password_field: str = 'password'
    ) -> Dict[str, Any]:
        """
        Test for session fixation vulnerability.
        
        Args:
            login_url: Login endpoint URL
            username: Test username
            password: Test password
            username_field: Username field name
            password_field: Password field name
            
        Returns:
            Dictionary with test results
        """
        try:
            pre_login_response = self.session.get(
                login_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            pre_login_cookies = {c.name: c.value for c in pre_login_response.cookies}
            
            session_cookies = {
                name: value for name, value in pre_login_cookies.items()
                if any(keyword in name.lower() for keyword in ['session', 'sid', 'token', 'auth', 'jsessionid'])
            }
            
            data = {
                username_field: username,
                password_field: password,
            }
            
            login_response = self.session.post(
                login_url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            post_login_cookies = {c.name: c.value for c in login_response.cookies}
            
            session_cookies.update({
                name: value for name, value in post_login_cookies.items()
                if any(keyword in name.lower() for keyword in ['session', 'sid', 'token', 'auth', 'jsessionid'])
            })
            
            fixation_detected = False
            evidence = ""
            
            for cookie_name in session_cookies:
                pre_value = pre_login_cookies.get(cookie_name)
                post_value = post_login_cookies.get(cookie_name)
                
                if pre_value and post_value and pre_value == post_value:
                    fixation_detected = True
                    evidence = f"Session cookie '{cookie_name}' unchanged after login"
                    break
            
            return {
                'fixation_detected': fixation_detected,
                'evidence': evidence,
                'pre_login_cookies': pre_login_cookies,
                'post_login_cookies': post_login_cookies,
            }
            
        except RequestException as e:
            self.errors.append(f"Session fixation test failed: {str(e)}")
            return {'fixation_detected': False, 'evidence': str(e)}
    
    def test_session_timeout(
        self,
        protected_url: str,
        wait_seconds: int = 10
    ) -> Dict[str, Any]:
        """
        Test session timeout behavior.
        
        Args:
            protected_url: URL requiring authentication
            wait_seconds: Seconds to wait before re-checking
            
        Returns:
            Dictionary with test results
        """
        try:
            initial_response = self.session.get(
                protected_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            initial_authenticated = initial_response.status_code == 200
            
            time.sleep(wait_seconds)
            
            delayed_response = self.session.get(
                protected_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            still_authenticated = delayed_response.status_code == 200
            
            return {
                'initial_authenticated': initial_authenticated,
                'still_authenticated': still_authenticated,
                'wait_seconds': wait_seconds,
                'timeout_detected': initial_authenticated and still_authenticated,
                'description': 'Session still valid after wait period' if still_authenticated
                               else 'Session expired during wait period',
            }
            
        except RequestException as e:
            self.errors.append(f"Session timeout test failed: {str(e)}")
            return {'error': str(e)}
    
    def test_logout(
        self,
        logout_url: str,
        protected_url: str
    ) -> Dict[str, Any]:
        """
        Test logout functionality effectiveness.
        
        Args:
            logout_url: Logout endpoint URL
            protected_url: URL that requires authentication
            
        Returns:
            Dictionary with test results
        """
        try:
            protected_before = self.session.get(
                protected_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            logout_response = self.session.get(
                logout_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            time.sleep(0.5)
            
            protected_after = self.session.get(
                protected_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            still_accessible = protected_after.status_code == 200
            
            return {
                'logout_effective': not still_accessible,
                'protected_before_logout': protected_before.status_code,
                'protected_after_logout': protected_after.status_code,
                'description': 'Protected page still accessible after logout' if still_accessible
                               else 'Logout successfully invalidated session',
            }
            
        except RequestException as e:
            self.errors.append(f"Logout test failed: {str(e)}")
            return {'error': str(e)}
    
    def test_concurrent_sessions(self, login_url: str) -> Dict[str, Any]:
        """
        Test for concurrent session handling.
        
        Args:
            login_url: Login endpoint URL
            
        Returns:
            Dictionary with test results
        """
        try:
            session1 = requests.Session()
            session2 = requests.Session()
            
            response1 = session1.get(login_url, timeout=self.timeout, verify=self.verify_ssl)
            response2 = session2.get(login_url, timeout=self.timeout, verify=self.verify_ssl)
            
            cookies1 = {c.name: c.value for c in response1.cookies}
            cookies2 = {c.name: c.value for c in response2.cookies}
            
            session_cookies1 = {
                name: value for name, value in cookies1.items()
                if any(kw in name.lower() for kw in ['session', 'sid', 'token', 'auth'])
            }
            session_cookies2 = {
                name: value for name, value in cookies2.items()
                if any(kw in name.lower() for kw in ['session', 'sid', 'token', 'auth'])
            }
            
            multiple_sessions_possible = len(session_cookies1) > 0 and len(session_cookies2) > 0
            
            return {
                'multiple_sessions_possible': multiple_sessions_possible,
                'session1_cookies': session_cookies1,
                'session2_cookies': session_cookies2,
            }
            
        except RequestException as e:
            self.errors.append(f"Concurrent session test failed: {str(e)}")
            return {'error': str(e)}
    
    def run(self) -> Dict[str, Any]:
        """
        Run all session management tests.
        
        Returns:
            Dictionary with test results
        """
        findings = []
        
        cookie_analyses = self.test_cookie_attributes(self.target)
        
        for analysis in cookie_analyses:
            if 'issues' in analysis and analysis['issues']:
                for issue in analysis['issues']:
                    findings.append({
                        'type': f'Session Cookie: {issue}',
                        'severity': 'medium',
                        'endpoint': self.target,
                        'cookie_name': analysis.get('name', 'unknown'),
                        'description': issue,
                        'evidence': str(analysis),
                        'remediation': 'Set Secure, HttpOnly, and SameSite flags on all session cookies.',
                    })
        
        login_urls = [
            f"{self.target}/login",
            f"{self.target}/api/login",
        ]
        
        for login_url in login_urls:
            if self.test_credentials:
                fixation_result = self.test_session_fixation(
                    login_url,
                    self.test_credentials.get('username', 'test'),
                    self.test_credentials.get('password', 'test')
                )
                
                if fixation_result.get('fixation_detected'):
                    findings.append({
                        'type': 'Session Fixation',
                        'severity': 'high',
                        'endpoint': login_url,
                        'description': 'Session cookie unchanged after login',
                        'evidence': fixation_result.get('evidence', ''),
                        'remediation': 'Regenerate session ID after successful authentication.',
                    })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': 1,
            'cookie_analyses': cookie_analyses,
            'vulnerabilities_found': len(findings),
        }