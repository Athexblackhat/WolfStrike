# modules/auth_tester/password_policy.py

"""
Password Policy Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests password policies for weaknesses including
minimum length, complexity requirements, and
common password acceptance.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class PasswordTestResult:
    """Represents a password policy test result."""
    url: str
    test_type: str
    password: str
    accepted: bool
    status_code: int
    response_message: str
    policy_violation: str


class PasswordPolicyTester:
    """
    Password policy vulnerability tester.
    
    Tests password policies for common weaknesses
    and compliance with security best practices.
    """
    
    WEAK_PASSWORDS = [
        'a', 'ab', 'abc', '123', '1234',
        'password', 'Password', 'PASSWORD',
        'pass', 'qwerty', 'abc123',
        'letmein', 'welcome', 'monkey',
        '111111', '123456', '12345678',
        '123456789', '1234567890',
        'aaaaaa', 'AAAAAA', 'abcdef',
        'password1', 'Password1',
    ]
    
    COMMON_COMPANY_PASSWORDS = [
        'company', 'Company123', 'welcome123',
        'changeme', 'temp123', 'seasonYear',
    ]
    
    SEQUENTIAL_PASSWORDS = [
        'abcdef', 'qwerty', 'asdfgh',
        '123456', '098765', '111111',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the password policy tester.
        
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
        
        self.results: List[PasswordTestResult] = []
        self.errors: List[str] = []
        
        self.registration_paths = [
            '/register', '/signup', '/api/register',
            '/api/users', '/create-account',
            '/user/register', '/auth/register',
        ]
        
        self.password_change_paths = [
            '/change-password', '/reset-password',
            '/api/password/change', '/account/password',
        ]
    
    def test_password(
        self,
        url: str,
        password: str,
        test_type: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> PasswordTestResult:
        """
        Test if a password is accepted by the policy.
        
        Args:
            url: Registration/Password change URL
            password: Password to test
            test_type: Type of test
            extra_data: Additional form data
            
        Returns:
            PasswordTestResult object
        """
        data = extra_data.copy() if extra_data else {}
        
        data['username'] = f"test_user_{hash(password) % 10000}"
        data['email'] = f"test_{hash(password) % 10000}@test.com"
        data['password'] = password
        
        if 'confirm' in data or 'password2' in data:
            confirm_field = 'confirm' if 'confirm' in data else 'password2'
            data[confirm_field] = password
        
        try:
            response = self.session.post(
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            response_text = response.text.lower()
            
            accepted = False
            policy_violation = ""
            
            success_indicators = [
                'success', 'created', 'registered',
                'welcome', 'account', 'verify',
            ]
            
            failure_indicators = [
                'too short', 'too weak', 'minimum length',
                'must contain', 'require', 'complexity',
                'uppercase', 'lowercase', 'number', 'special',
                '8 character', '6 character', '10 character',
                'password policy', 'password requirement',
            ]
            
            accepted = any(indicator in response_text for indicator in success_indicators)
            
            if not accepted:
                for indicator in failure_indicators:
                    if indicator in response_text:
                        policy_violation = indicator
                        break
            
            if response.status_code in [200, 201, 202]:
                if not any(indicator in response_text for indicator in failure_indicators):
                    accepted = True
            
            result = PasswordTestResult(
                url=url,
                test_type=test_type,
                password=password,
                accepted=accepted,
                status_code=response.status_code,
                response_message=response_text[:200],
                policy_violation=policy_violation,
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Password test failed: {str(e)}")
            
            return PasswordTestResult(
                url=url,
                test_type=test_type,
                password=password,
                accepted=False,
                status_code=0,
                response_message=str(e),
                policy_violation="",
            )
    
    def test_minimum_length(
        self,
        url: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[PasswordTestResult]:
        """
        Test minimum password length enforcement.
        
        Args:
            url: Target URL
            extra_data: Additional form data
            
        Returns:
            List of PasswordTestResult objects
        """
        results = []
        
        lengths_to_test = [1, 4, 6, 8, 10, 12]
        
        for length in lengths_to_test:
            password = 'a' * length
            
            if length >= 8:
                password = f"Aa1!{password[4:]}"
            
            result = self.test_password(url, password, 'minimum_length', extra_data)
            results.append(result)
        
        return results
    
    def test_complexity_requirements(
        self,
        url: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[PasswordTestResult]:
        """
        Test password complexity requirements.
        
        Args:
            url: Target URL
            extra_data: Additional form data
            
        Returns:
            List of PasswordTestResult objects
        """
        results = []
        
        complexity_tests = [
            ('lowercase_only', 'abcdefgh'),
            ('uppercase_only', 'ABCDEFGH'),
            ('numbers_only', '12345678'),
            ('lowercase_numbers', 'abcdef12'),
            ('uppercase_numbers', 'ABCDEF12'),
            ('mixed_case', 'AbCdEfGh'),
            ('mixed_case_numbers', 'AbCdEf12'),
            ('all_chars', 'Ab1!Cd2@'),
        ]
        
        for test_name, password in complexity_tests:
            result = self.test_password(url, password, test_name, extra_data)
            results.append(result)
        
        return results
    
    def test_weak_passwords(
        self,
        url: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[PasswordTestResult]:
        """
        Test if weak passwords are accepted.
        
        Args:
            url: Target URL
            extra_data: Additional form data
            
        Returns:
            List of PasswordTestResult objects
        """
        results = []
        
        for password in self.WEAK_PASSWORDS:
            result = self.test_password(url, password, 'weak_password', extra_data)
            results.append(result)
        
        return results
    
    def test_common_patterns(
        self,
        url: str,
        extra_data: Optional[Dict[str, str]] = None
    ) -> List[PasswordTestResult]:
        """
        Test if common password patterns are accepted.
        
        Args:
            url: Target URL
            extra_data: Additional form data
            
        Returns:
            List of PasswordTestResult objects
        """
        results = []
        
        for password in self.SEQUENTIAL_PASSWORDS:
            result = self.test_password(url, password, 'sequential_pattern', extra_data)
            results.append(result)
        
        for password in self.COMMON_COMPANY_PASSWORDS:
            result = self.test_password(url, password, 'company_pattern', extra_data)
            results.append(result)
        
        return results
    
    def analyze_results(self) -> List[Dict[str, Any]]:
        """
        Analyze password policy test results.
        
        Returns:
            List of vulnerability dictionaries
        """
        findings = []
        
        weak_accepted = [
            r for r in self.results
            if r.test_type == 'weak_password' and r.accepted
        ]
        
        if len(weak_accepted) >= 3:
            findings.append({
                'type': 'Weak Password Policy',
                'severity': 'high',
                'endpoint': self.results[0].url if self.results else '',
                'description': f'Application accepts {len(weak_accepted)} common weak passwords.',
                'evidence': f'Accepted passwords: {[r.password for r in weak_accepted[:5]]}',
                'remediation': 'Implement strong password policy. '
                               'Use password strength meter. '
                               'Reject common passwords from breach lists.',
            })
        
        length_results = [r for r in self.results if r.test_type == 'minimum_length']
        short_accepted = [r for r in length_results if r.accepted and len(r.password) < 8]
        
        if short_accepted:
            findings.append({
                'type': 'Insufficient Minimum Length',
                'severity': 'medium',
                'endpoint': self.results[0].url if self.results else '',
                'description': f'Application accepts passwords shorter than 8 characters.',
                'evidence': f'Accepted password length: {len(short_accepted[0].password)}',
                'remediation': 'Enforce minimum password length of at least 8 characters.',
            })
        
        complexity_results = [
            r for r in self.results if r.test_type in [
                'lowercase_only', 'numbers_only', 'lowercase_numbers'
            ]
        ]
        simple_accepted = [r for r in complexity_results if r.accepted]
        
        if len(simple_accepted) >= 2:
            findings.append({
                'type': 'Weak Complexity Requirements',
                'severity': 'medium',
                'endpoint': self.results[0].url if self.results else '',
                'description': 'Application does not enforce password complexity requirements.',
                'evidence': f'Accepted simple passwords: {[r.test_type for r in simple_accepted]}',
                'remediation': 'Require mix of uppercase, lowercase, numbers, and special characters.',
            })
        
        return findings
    
    def run(self) -> Dict[str, Any]:
        """
        Run all password policy tests.
        
        Returns:
            Dictionary with test results
        """
        for reg_path in self.registration_paths:
            full_url = f"{self.target}{reg_path}"
            
            extra_data = {
                'confirm': '',
                'terms': 'on',
            }
            
            self.test_minimum_length(full_url, extra_data)
            self.test_complexity_requirements(full_url, extra_data)
            self.test_weak_passwords(full_url, extra_data)
            self.test_common_patterns(full_url, extra_data)
        
        findings = self.analyze_results()
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(self.registration_paths),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }