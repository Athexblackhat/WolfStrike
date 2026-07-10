# modules/auth_tester/jwt_analyzer.py

"""
JWT Security Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes JWT tokens for security misconfigurations
including algorithm weaknesses, missing claims, and
insecure token storage patterns.
"""

import json
import base64
import time
from typing import Dict, List, Any, Optional, Tuple

import requests
from requests.exceptions import RequestException


class JWTAnalyzer:
    """
    JWT security analyzer.
    
    Analyzes JWT tokens in requests and responses for
    security misconfigurations and vulnerabilities.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the JWT analyzer.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode JWT token without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Dictionary with header and payload
        """
        try:
            parts = token.split('.')
            
            if len(parts) != 3:
                return None
            
            def decode_part(part: str) -> Dict[str, Any]:
                padded = part + '=' * (4 - len(part) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                return json.loads(decoded)
            
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'raw': token,
            }
            
        except Exception:
            return None
    
    def extract_tokens_from_response(self, response: requests.Response) -> List[str]:
        """
        Extract JWT tokens from HTTP response.
        
        Args:
            response: HTTP response object
            
        Returns:
            List of JWT token strings
        """
        tokens = []
        
        for header_name, header_value in response.headers.items():
            if header_name.lower() == 'authorization':
                if header_value.lower().startswith('bearer '):
                    token = header_value[7:]
                    tokens.append(token)
            
            if header_name.lower() == 'set-cookie':
                jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.?[A-Za-z0-9._-]*'
                import re
                matches = re.findall(jwt_pattern, header_value)
                tokens.extend(matches)
        
        try:
            response_text = response.text
            
            jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.?[A-Za-z0-9._-]*'
            import re
            matches = re.findall(jwt_pattern, response_text)
            tokens.extend(matches)
        except Exception:
            pass
        
        return list(set(tokens))
    
    def analyze_token(self, token_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a decoded JWT token for security issues.
        
        Args:
            token_data: Decoded token dictionary
            
        Returns:
            List of vulnerability dictionaries
        """
        issues = []
        
        header = token_data.get('header', {})
        payload = token_data.get('payload', {})
        signature = token_data.get('signature', '')
        
        algorithm = header.get('alg', 'unknown')
        
        if algorithm == 'none':
            issues.append({
                'type': 'JWT None Algorithm',
                'severity': 'critical',
                'description': 'Token uses "none" algorithm, allowing signature bypass',
                'remediation': 'Reject tokens with "none" algorithm',
            })
        
        if algorithm.startswith('HS'):
            if len(signature) < 32:
                issues.append({
                    'type': 'JWT Weak HMAC Key',
                    'severity': 'high',
                    'description': 'Short signature suggests weak HMAC secret',
                    'remediation': 'Use strong secret keys (256+ bits)',
                })
        
        if 'exp' not in payload:
            issues.append({
                'type': 'JWT Missing Expiration',
                'severity': 'medium',
                'description': 'Token has no expiration claim (exp)',
                'remediation': 'Always include exp claim in tokens',
            })
        else:
            exp_time = payload['exp']
            current_time = int(time.time())
            
            if exp_time - current_time > 86400 * 30:
                issues.append({
                    'type': 'JWT Long Expiration',
                    'severity': 'medium',
                    'description': f'Token expiration is {(exp_time - current_time) / 86400:.0f} days',
                    'remediation': 'Use short-lived tokens (15 minutes to 24 hours)',
                })
        
        if 'iat' not in payload:
            issues.append({
                'type': 'JWT Missing Issued At',
                'severity': 'low',
                'description': 'Token has no issued at claim (iat)',
                'remediation': 'Include iat claim in tokens',
            })
        
        if 'jti' not in payload:
            issues.append({
                'type': 'JWT Missing JWT ID',
                'severity': 'low',
                'description': 'Token has no JWT ID claim (jti) for revocation',
                'remediation': 'Include unique jti claim for token revocation',
            })
        
        sensitive_claims = ['password', 'secret', 'ssn', 'credit_card', 'admin']
        for claim in sensitive_claims:
            if claim in payload:
                issues.append({
                    'type': 'JWT Sensitive Data Exposure',
                    'severity': 'high',
                    'description': f'Token payload contains sensitive data: {claim}',
                    'remediation': 'Do not store sensitive data in JWT payload',
                })
        
        return issues
    
    def run(self) -> Dict[str, Any]:
        """
        Run JWT security analysis.
        
        Returns:
            Dictionary with analysis results
        """
        all_issues = []
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            tokens = self.extract_tokens_from_response(response)
            
            for token in tokens:
                token_data = self.decode_token(token)
                
                if token_data:
                    issues = self.analyze_token(token_data)
                    
                    for issue in issues:
                        issue['token_preview'] = token[:50] + '...'
                        issue['algorithm'] = token_data.get('header', {}).get('alg', 'unknown')
                    
                    all_issues.extend(issues)
            
        except RequestException as e:
            self.errors.append(f"JWT analysis failed: {str(e)}")
        
        return {
            'findings': all_issues,
            'errors': self.errors,
            'tokens_found': len(set()),
            'vulnerabilities_found': len(all_issues),
        }