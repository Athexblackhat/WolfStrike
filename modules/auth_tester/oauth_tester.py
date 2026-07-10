# modules/auth_tester/oauth_tester.py

"""
OAuth Security Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests OAuth implementations for common vulnerabilities
including CSRF in authorization flow, redirect URI
manipulation, and token leakage.
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

import requests
from requests.exceptions import RequestException


class OAuthTester:
    """
    OAuth security vulnerability tester.
    
    Tests OAuth 2.0 implementations for common
    misconfigurations and security flaws.
    """
    
    COMMON_OAUTH_PATHS = [
        '/oauth/authorize', '/oauth2/authorize',
        '/authorize', '/oauth/token', '/oauth2/token',
        '/token', '/oauth/callback', '/oauth2/callback',
        '/auth/callback', '/login/oauth',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the OAuth tester.
        
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
    
    def detect_oauth_endpoints(self) -> List[str]:
        """
        Detect OAuth endpoints on target.
        
        Returns:
            List of discovered OAuth endpoint URLs
        """
        discovered = []
        
        for path in self.COMMON_OAUTH_PATHS:
            url = f"{self.target}{path}"
            
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 302, 400, 401]:
                    response_text = response.text.lower()
                    
                    oauth_indicators = [
                        'oauth', 'client_id', 'redirect_uri',
                        'response_type', 'grant_type', 'authorize',
                        'access_token', 'refresh_token', 'scope',
                    ]
                    
                    if any(indicator in response_text for indicator in oauth_indicators):
                        discovered.append(url)
                        
            except RequestException:
                continue
        
        return discovered
    
    def test_csrf_in_authorization(
        self,
        authorize_url: str,
        client_id: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Test for CSRF protection in authorization flow.
        
        Args:
            authorize_url: OAuth authorization endpoint
            client_id: Client ID
            redirect_uri: Redirect URI
            
        Returns:
            Dictionary with test results
        """
        try:
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'openid profile email',
            }
            
            response = self.session.get(
                authorize_url,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            state_found = 'state' in str(response.url)
            
            csrf_protected = state_found
            
            return {
                'csrf_protected': csrf_protected,
                'state_parameter_found': state_found,
                'description': 'State parameter present' if state_found else 'Missing state parameter - CSRF vulnerable',
            }
            
        except RequestException as e:
            self.errors.append(f"CSRF test failed: {str(e)}")
            return {'csrf_protected': False, 'error': str(e)}
    
    def test_redirect_uri_bypass(
        self,
        authorize_url: str,
        client_id: str,
        legitimate_redirect: str,
        malicious_redirect: str
    ) -> Dict[str, Any]:
        """
        Test for redirect URI validation bypass.
        
        Args:
            authorize_url: OAuth authorization endpoint
            client_id: Client ID
            legitimate_redirect: Legitimate redirect URI
            malicious_redirect: Malicious redirect URI
            
        Returns:
            Dictionary with test results
        """
        results = []
        
        bypass_payloads = [
            malicious_redirect,
            f"{legitimate_redirect}.evil.com",
            f"{legitimate_redirect}@evil.com",
            f"{legitimate_redirect}%40evil.com",
            f"{legitimate_redirect}//evil.com",
            f"{legitimate_redirect}\\@evil.com",
            f"evil.com#{legitimate_redirect}",
            f"evil.com?{legitimate_redirect}",
        ]
        
        for payload in bypass_payloads:
            try:
                params = {
                    'client_id': client_id,
                    'redirect_uri': payload,
                    'response_type': 'code',
                }
                
                response = self.session.get(
                    authorize_url,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                is_bypassed = response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', '')
                
                results.append({
                    'payload': payload,
                    'bypassed': is_bypassed,
                })
                
            except RequestException:
                continue
        
        return {
            'bypass_attempts': len(results),
            'successful_bypasses': [r for r in results if r['bypassed']],
            'vulnerable': any(r['bypassed'] for r in results),
        }
    
    def test_token_in_url(self, callback_url: str) -> Dict[str, Any]:
        """
        Test if tokens are passed in URL fragments.
        
        Args:
            callback_url: OAuth callback URL
            
        Returns:
            Dictionary with test results
        """
        try:
            parsed = urlparse(callback_url)
            
            fragment_tokens = []
            if parsed.fragment:
                fragment_params = parse_qs(parsed.fragment)
                token_keys = ['access_token', 'id_token', 'token', 'code']
                
                for key in token_keys:
                    if key in fragment_params:
                        fragment_tokens.append(key)
            
            query_tokens = []
            query_params = parse_qs(parsed.query)
            for key in token_keys:
                if key in query_params:
                    query_tokens.append(key)
            
            return {
                'tokens_in_fragment': fragment_tokens,
                'tokens_in_query': query_tokens,
                'token_leakage': len(fragment_tokens) > 0 or len(query_tokens) > 0,
                'description': f'Tokens found in URL: {fragment_tokens + query_tokens}',
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def run(self) -> Dict[str, Any]:
        """
        Run all OAuth tests.
        
        Returns:
            Dictionary with test results
        """
        endpoints = self.detect_oauth_endpoints()
        
        for endpoint in endpoints:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            client_id = params.get('client_id', ['unknown'])[0]
            redirect_uri = params.get('redirect_uri', [f"{self.target}/callback"])[0]
            
            csrf_result = self.test_csrf_in_authorization(
                endpoint, client_id, redirect_uri
            )
            
            if not csrf_result.get('csrf_protected', False):
                self.findings.append({
                    'type': 'OAuth CSRF Vulnerability',
                    'severity': 'high',
                    'endpoint': endpoint,
                    'description': 'OAuth authorization endpoint missing state parameter',
                    'evidence': csrf_result,
                    'remediation': 'Implement state parameter with random value to prevent CSRF attacks',
                })
            
            bypass_result = self.test_redirect_uri_bypass(
                endpoint, client_id, redirect_uri, 'https://evil.com/callback'
            )
            
            if bypass_result.get('vulnerable', False):
                self.findings.append({
                    'type': 'OAuth Redirect URI Bypass',
                    'severity': 'high',
                    'endpoint': endpoint,
                    'description': 'OAuth redirect URI validation can be bypassed',
                    'evidence': bypass_result,
                    'remediation': 'Implement strict redirect URI validation with exact matching',
                })
        
        return {
            'findings': self.findings,
            'errors': self.errors,
            'endpoints_discovered': len(endpoints),
            'vulnerabilities_found': len(self.findings),
        }