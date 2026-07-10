# modules/auth_tester/brute_force.py

"""
Brute Force Attack Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests login forms for brute force vulnerabilities including
lack of rate limiting, account lockout, and credential stuffing.
"""

import time
import threading
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException


@dataclass
class BruteForceResult:
    """Represents a brute force test result."""
    url: str
    username: str
    password: str
    success: bool
    status_code: int
    response_time: float
    response_length: int
    error_message: str
    rate_limited: bool
    account_locked: bool


class BruteForceTester:
    """
    Brute force vulnerability tester.
    
    Tests login forms for rate limiting, account lockout,
    and brute force protection mechanisms.
    """
    
    COMMON_USERNAMES = [
        'admin', 'administrator', 'root', 'user',
        'test', 'guest', 'manager', 'operator',
        'supervisor', 'support', 'info', 'sales',
    ]
    
    COMMON_PASSWORDS = [
        'admin', 'password', '123456', '12345678',
        'qwerty', 'letmein', 'welcome', 'monkey',
        'dragon', 'master', 'pass123', 'Password1',
        'Admin123', 'Test123', 'changeme',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the brute force tester.
        
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
        self.max_attempts = self.config.get('max_attempts', 50)
        self.delay = self.config.get('delay', 0.1)
        self.concurrent_workers = self.config.get('concurrent_workers', 5)
        
        self.results: List[BruteForceResult] = []
        self.errors: List[str] = []
        
        self.common_login_paths = [
            '/login', '/signin', '/auth/login',
            '/api/login', '/api/auth', '/admin/login',
            '/user/login', '/account/login', '/wp-login.php',
        ]
    
    def detect_login_form(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Detect login form parameters on a page.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with form details or None
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'post').upper()
                
                inputs = form.find_all('input')
                input_names = []
                
                for inp in inputs:
                    input_type = inp.get('type', 'text')
                    input_name = inp.get('name', '')
                    
                    if input_type in ['text', 'email', 'password', 'hidden']:
                        if input_name:
                            input_names.append(input_name)
                
                username_fields = [n for n in input_names if any(
                    keyword in n.lower() for keyword in ['user', 'email', 'login', 'name', 'id']
                )]
                password_fields = [n for n in input_names if any(
                    keyword in n.lower() for keyword in ['pass', 'pwd', 'secret', 'pin']
                )]
                
                if username_fields and password_fields:
                    form_action = action if action.startswith('http') else (
                        url.rstrip('/') + '/' + action.lstrip('/') if action else url
                    )
                    
                    return {
                        'action': form_action,
                        'method': method,
                        'username_field': username_fields[0],
                        'password_field': password_fields[0],
                        'csrf_token': None,
                        'extra_fields': input_names,
                    }
            
            return None
            
        except RequestException:
            return None
    
    def test_single_credential(
        self,
        url: str,
        method: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> BruteForceResult:
        """
        Test a single username/password combination.
        
        Args:
            url: Login URL
            method: HTTP method
            username_field: Username form field name
            password_field: Password form field name
            username: Username to test
            password: Password to test
            extra_data: Additional form data
            
        Returns:
            BruteForceResult object
        """
        data = extra_data.copy() if extra_data else {}
        data[username_field] = username
        data[password_field] = password
        
        try:
            start_time = time.time()
            
            if method == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            else:
                response = self.session.get(
                    url,
                    params=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
            
            elapsed = time.time() - start_time
            response_text = response.text.lower()
            
            success_indicators = [
                'welcome', 'dashboard', 'logout', 'sign out',
                'my account', 'profile', 'successfully logged',
            ]
            
            failure_indicators = [
                'invalid', 'incorrect', 'wrong password',
                'user not found', 'does not exist', 'try again',
                'invalid credentials', 'authentication failed',
            ]
            
            lockout_indicators = [
                'locked', 'too many attempts', 'try again later',
                'temporarily blocked', 'account suspended',
                'rate limit', 'too many requests',
            ]
            
            success = any(indicator in response_text for indicator in success_indicators)
            failure = any(indicator in response_text for indicator in failure_indicators)
            
            account_locked = any(indicator in response_text for indicator in lockout_indicators)
            rate_limited = response.status_code == 429 or account_locked
            
            if not success and not failure and response.status_code in [301, 302]:
                redirect_location = response.headers.get('Location', '').lower()
                if any(indicator in redirect_location for indicator in ['dashboard', 'home', 'profile']):
                    success = True
            
            result = BruteForceResult(
                url=url,
                username=username,
                password=password,
                success=success,
                status_code=response.status_code,
                response_time=elapsed,
                response_length=len(response.content),
                error_message=response_text[:200] if failure else '',
                rate_limited=rate_limited,
                account_locked=account_locked,
            )
            
            return result
            
        except RequestException as e:
            return BruteForceResult(
                url=url,
                username=username,
                password=password,
                success=False,
                status_code=0,
                response_time=0,
                response_length=0,
                error_message=str(e),
                rate_limited=False,
                account_locked=False,
            )
    
    def test_rate_limiting(
        self,
        url: str,
        method: str,
        username_field: str,
        password_field: str,
        extra_data: Optional[Dict[str, str]] = None,
        attempt_count: int = 30
    ) -> List[BruteForceResult]:
        """
        Test for rate limiting by sending multiple rapid requests.
        
        Args:
            url: Login URL
            method: HTTP method
            username_field: Username field name
            password_field: Password field name
            extra_data: Additional form data
            attempt_count: Number of attempts
            
        Returns:
            List of BruteForceResult objects
        """
        results = []
        
        for i in range(attempt_count):
            username = f"test_user_{i}@test.com"
            password = f"WrongPassword{i}"
            
            result = self.test_single_credential(
                url, method, username_field, password_field,
                username, password, extra_data
            )
            
            results.append(result)
            
            if result.rate_limited:
                break
            
            time.sleep(self.delay)
        
        self.results.extend(results)
        return results
    
    def test_common_credentials(
        self,
        url: str,
        method: str,
        username_field: str,
        password_field: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[BruteForceResult]:
        """
        Test common username/password combinations.
        
        Args:
            url: Login URL
            method: HTTP method
            username_field: Username field name
            password_field: Password field name
            extra_data: Additional form data
            
        Returns:
            List of BruteForceResult objects
        """
        results = []
        found_valid = False
        
        for username in self.COMMON_USERNAMES[:5]:
            if found_valid:
                break
            
            for password in self.COMMON_PASSWORDS[:5]:
                result = self.test_single_credential(
                    url, method, username_field, password_field,
                    username, password, extra_data
                )
                
                results.append(result)
                
                if result.success:
                    found_valid = True
                    break
                
                if result.rate_limited:
                    break
                
                time.sleep(self.delay)
            
            if found_valid:
                break
        
        self.results.extend(results)
        return results
    
    def test_user_enumeration(
        self,
        url: str,
        method: str,
        username_field: str,
        password_field: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Test for username enumeration vulnerability.
        
        Args:
            url: Login URL
            method: HTTP method
            username_field: Username field name
            password_field: Password field name
            extra_data: Additional form data
            
        Returns:
            List of enumeration result dictionaries
        """
        enumeration_results = []
        
        existing_user = self.COMMON_USERNAMES[0]
        non_existing_user = f"nonexistent_user_{int(time.time())}"
        test_password = "WrongPassword123"
        
        result1 = self.test_single_credential(
            url, method, username_field, password_field,
            existing_user, test_password, extra_data
        )
        
        time.sleep(0.5)
        
        result2 = self.test_single_credential(
            url, method, username_field, password_field,
            non_existing_user, test_password, extra_data
        )
        
        enumeration_detected = False
        evidence = ""
        
        if result1.response_length != result2.response_length:
            enumeration_detected = True
            evidence = f"Different response lengths: {result1.response_length} vs {result2.response_length}"
        
        if result1.response_time != result2.response_time:
            time_diff = abs(result1.response_time - result2.response_time)
            if time_diff > 0.5:
                enumeration_detected = True
                evidence = f"Different response times: {result1.response_time:.3f}s vs {result2.response_time:.3f}s"
        
        if result1.status_code != result2.status_code:
            enumeration_detected = True
            evidence = f"Different status codes: {result1.status_code} vs {result2.status_code}"
        
        enumeration_results.append({
            'url': url,
            'enumeration_detected': enumeration_detected,
            'evidence': evidence,
            'existing_user_response': result1.status_code,
            'non_existing_user_response': result2.status_code,
        })
        
        return enumeration_results
    
    def run(self) -> Dict[str, Any]:
        """
        Run all brute force tests.
        
        Returns:
            Dictionary with test results
        """
        findings = []
        
        for login_path in self.common_login_paths:
            full_url = f"{self.target}{login_path}"
            
            form_info = self.detect_login_form(full_url)
            
            if form_info:
                action_url = form_info['action']
                method = form_info['method']
                username_field = form_info['username_field']
                password_field = form_info['password_field']
                
                rate_results = self.test_rate_limiting(
                    action_url, method, username_field, password_field
                )
                
                rate_limited = any(r.rate_limited for r in rate_results)
                
                if not rate_limited:
                    findings.append({
                        'type': 'No Rate Limiting',
                        'severity': 'high',
                        'endpoint': action_url,
                        'description': f'Login endpoint does not implement rate limiting. '
                                       f'{len(rate_results)} attempts without blocking.',
                        'evidence': f'Sent {len(rate_results)} requests without rate limiting',
                        'remediation': 'Implement rate limiting on login endpoints. '
                                       'Use CAPTCHA after failed attempts.',
                    })
                
                locked_out = any(r.account_locked for r in rate_results)
                
                if not locked_out and len(rate_results) >= 10:
                    findings.append({
                        'type': 'No Account Lockout',
                        'severity': 'medium',
                        'endpoint': action_url,
                        'description': 'No account lockout mechanism detected after multiple failed attempts.',
                        'evidence': f'{len(rate_results)} failed attempts without account lockout',
                        'remediation': 'Implement account lockout after consecutive failed login attempts.',
                    })
                
                cred_results = self.test_common_credentials(
                    action_url, method, username_field, password_field
                )
                
                successful = [r for r in cred_results if r.success]
                if successful:
                    findings.append({
                        'type': 'Weak Credentials',
                        'severity': 'critical',
                        'endpoint': action_url,
                        'description': f'Login successful with common credentials: '
                                       f'{successful[0].username}:{successful[0].password}',
                        'evidence': f'Successful login with weak credentials',
                        'remediation': 'Enforce strong password policy. '
                                       'Require complex passwords.',
                    })
                
                enum_results = self.test_user_enumeration(
                    action_url, method, username_field, password_field
                )
                
                for enum_result in enum_results:
                    if enum_result['enumeration_detected']:
                        findings.append({
                            'type': 'Username Enumeration',
                            'severity': 'medium',
                            'endpoint': action_url,
                            'description': 'Application reveals whether usernames exist.',
                            'evidence': enum_result['evidence'],
                            'remediation': 'Use generic error messages. '
                                           'Do not reveal if username exists.',
                        })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(self.common_login_paths),
            'total_attempts': len(self.results),
            'vulnerabilities_found': len(findings),
        }