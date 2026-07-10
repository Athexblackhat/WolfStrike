# modules/auth_tester/mfa_tester.py

"""
Multi-Factor Authentication Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests MFA implementations for bypass vulnerabilities
including response manipulation, rate limiting, and
backup code weaknesses.
"""

import time
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class MFATester:
    """
    MFA security vulnerability tester.
    
    Tests multi-factor authentication implementations
    for common bypass techniques and weaknesses.
    """
    
    COMMON_MFA_PATHS = [
        '/mfa', '/2fa', '/otp', '/verify',
        '/mfa/verify', '/2fa/verify', '/otp/verify',
        '/auth/mfa', '/auth/2fa', '/login/mfa',
        '/api/mfa/verify', '/api/2fa/verify',
    ]
    
    BYPASS_HEADERS = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-Host': '127.0.0.1'},
        {'X-Original-URL': '/dashboard'},
        {'X-Rewrite-URL': '/dashboard'},
        {'X-HTTP-Method-Override': 'GET'},
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the MFA tester.
        
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
        
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def detect_mfa_endpoints(self) -> List[str]:
        """
        Detect MFA endpoints on target.
        
        Returns:
            List of discovered MFA endpoint URLs
        """
        discovered = []
        
        for path in self.COMMON_MFA_PATHS:
            url = f"{self.target}{path}"
            
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 302, 401, 403]:
                    response_text = response.text.lower()
                    
                    mfa_indicators = [
                        'mfa', '2fa', 'two-factor', 'otp',
                        'verification code', 'authenticator',
                        'security code', 'one-time', 'backup code',
                    ]
                    
                    if any(indicator in response_text for indicator in mfa_indicators):
                        discovered.append(url)
                        
            except RequestException:
                continue
        
        return discovered
    
    def test_response_manipulation(
        self,
        mfa_url: str,
        protected_url: str
    ) -> Dict[str, Any]:
        """
        Test MFA bypass via response manipulation.
        
        Args:
            mfa_url: MFA verification endpoint
            protected_url: URL protected by MFA
            
        Returns:
            Dictionary with test results
        """
        manipulations = [
            ('status_code', {'status': 'success'}),
            ('boolean_true', {'mfa_verified': True}),
            ('boolean_true_alt', {'mfa_valid': True}),
            ('success_response', {'success': True, 'verified': True}),
        ]
        
        results = []
        
        for test_name, manip_data in manipulations:
            try:
                response = self.session.post(
                    mfa_url,
                    json={'code': '000000', **manip_data},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 302]:
                    protected_response = self.session.get(
                        protected_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    bypassed = protected_response.status_code == 200
                    
                    results.append({
                        'test': test_name,
                        'bypassed': bypassed,
                        'response_status': response.status_code,
                    })
                    
            except RequestException:
                continue
        
        return {
            'tests_performed': len(results),
            'bypasses_found': [r for r in results if r['bypassed']],
            'vulnerable': any(r['bypassed'] for r in results),
        }
    
    def test_direct_access(
        self,
        protected_url: str
    ) -> Dict[str, Any]:
        """
        Test if protected page is accessible without MFA.
        
        Args:
            protected_url: URL that should require MFA
            
        Returns:
            Dictionary with test results
        """
        try:
            response = self.session.get(
                protected_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            directly_accessible = response.status_code == 200
            
            return {
                'directly_accessible': directly_accessible,
                'status_code': response.status_code,
                'description': 'Protected page accessible without MFA' if directly_accessible
                               else 'MFA properly enforced',
            }
            
        except RequestException as e:
            self.errors.append(f"Direct access test failed: {str(e)}")
            return {'directly_accessible': False, 'error': str(e)}
    
    def test_rate_limiting(
        self,
        mfa_url: str,
        attempt_count: int = 20
    ) -> Dict[str, Any]:
        """
        Test MFA rate limiting for brute force protection.
        
        Args:
            mfa_url: MFA verification endpoint
            attempt_count: Number of attempts
            
        Returns:
            Dictionary with test results
        """
        results = []
        
        for i in range(attempt_count):
            try:
                response = self.session.post(
                    mfa_url,
                    data={'code': f'{i:06d}'},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                results.append({
                    'attempt': i + 1,
                    'status_code': response.status_code,
                    'rate_limited': response.status_code == 429,
                })
                
                if response.status_code == 429:
                    break
                
                time.sleep(0.05)
                
            except RequestException:
                continue
        
        rate_limited = any(r['rate_limited'] for r in results)
        
        return {
            'attempts_made': len(results),
            'rate_limited': rate_limited,
            'rate_limit_threshold': len(results) if rate_limited else 0,
            'description': 'Rate limiting enforced' if rate_limited
                           else f'No rate limiting after {len(results)} attempts',
        }
    
    def test_backup_code_endpoint(
        self,
        mfa_url: str
    ) -> Dict[str, Any]:
        """
        Test backup code functionality.
        
        Args:
            mfa_url: MFA endpoint URL
            
        Returns:
            Dictionary with test results
        """
        backup_codes_tested = ['123456', '000000', '111111', '999999']
        
        results = []
        
        for code in backup_codes_tested:
            try:
                response = self.session.post(
                    mfa_url,
                    data={'code': code, 'backup_code': 'true'},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                accepted = response.status_code in [200, 302]
                
                results.append({
                    'code': code,
                    'accepted': accepted,
                })
                
            except RequestException:
                continue
        
        return {
            'backup_codes_accepted': [r for r in results if r['accepted']],
            'vulnerable': any(r['accepted'] for r in results),
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Run all MFA tests.
        
        Returns:
            Dictionary with test results
        """
        mfa_endpoints = self.detect_mfa_endpoints()
        
        for endpoint in mfa_endpoints:
            protected_url = self.target + '/dashboard'
            
            rate_result = self.test_rate_limiting(endpoint)
            
            if not rate_result.get('rate_limited', False):
                self.findings.append({
                    'type': 'MFA No Rate Limiting',
                    'severity': 'high',
                    'endpoint': endpoint,
                    'description': 'MFA endpoint lacks rate limiting for brute force attacks',
                    'evidence': rate_result,
                    'remediation': 'Implement rate limiting and account lockout for MFA attempts',
                })
            
            direct_result = self.test_direct_access(protected_url)
            
            if direct_result.get('directly_accessible', False):
                self.findings.append({
                    'type': 'MFA Bypass - Direct Access',
                    'severity': 'critical',
                    'endpoint': protected_url,
                    'description': 'Protected page accessible without completing MFA',
                    'evidence': direct_result,
                    'remediation': 'Enforce MFA check on all protected endpoints server-side',
                })
            
            backup_result = self.test_backup_code_endpoint(endpoint)
            
            if backup_result.get('vulnerable', False):
                self.findings.append({
                    'type': 'MFA Weak Backup Codes',
                    'severity': 'medium',
                    'endpoint': endpoint,
                    'description': 'Weak backup codes accepted by MFA',
                    'evidence': backup_result,
                    'remediation': 'Use secure random backup codes and limit attempts',
                })
        
        return {
            'findings': self.findings,
            'errors': self.errors,
            'endpoints_discovered': len(mfa_endpoints),
            'vulnerabilities_found': len(self.findings),
        }