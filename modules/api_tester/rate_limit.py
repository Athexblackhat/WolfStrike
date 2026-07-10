# modules/api_tester/rate_limit.py

"""
Rate Limit Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0Tests API endpoints for rate limiting vulnerabilities
including brute force protection and resource exhaustion.
"""

import time
import threading
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
from requests.exceptions import RequestException


@dataclass
class RateLimitResult:
    """Represents rate limit test results."""
    endpoint: str
    requests_sent: int
    responses_received: int
    blocked_requests: int
    rate_limit_detected: bool
    rate_limit_threshold: int
    retry_after_header: bool
    status_codes: Dict[int, int]


class RateLimitTester:
    """
    API rate limiting tester.
    
    Tests endpoints for rate limiting implementation,
    brute force protection, and resource exhaustion.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the rate limit tester.
        
        Args:
            target: Target base URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WOLFSTRIKE-RateLimit-Tester/1.0',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.concurrent_requests = self.config.get('concurrent_requests', 50)
        self.burst_size = self.config.get('burst_size', 100)
        
        self.results: List[RateLimitResult] = []
        self.errors: List[str] = []
    
    def test_endpoint(
        self,
        endpoint: str,
        method: str = 'GET',
        total_requests: int = 100,
        delay: float = 0.01
    ) -> RateLimitResult:
        """
        Test a single endpoint for rate limiting.
        
        Args:
            endpoint: Target endpoint URL
            method: HTTP method
            total_requests: Total requests to send
            delay: Delay between requests in seconds
            
        Returns:
            RateLimitResult object
        """
        responses_received = 0
        blocked_requests = 0
        status_codes: Dict[int, int] = {}
        retry_after_detected = False
        
        for i in range(total_requests):
            try:
                response = self.session.request(
                    method,
                    endpoint,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                responses_received += 1
                status_code = response.status_code
                status_codes[status_code] = status_codes.get(status_code, 0) + 1
                
                if status_code == 429:
                    blocked_requests += 1
                    
                    if 'Retry-After' in response.headers:
                        retry_after_detected = True
                        
                        retry_after = response.headers.get('Retry-After', '0')
                        try:
                            wait_time = int(retry_after)
                            time.sleep(wait_time)
                        except ValueError:
                            time.sleep(5)
                
                elif status_code in [403, 503]:
                    blocked_requests += 1
                
                time.sleep(delay)
                
            except RequestException:
                continue
        
        rate_limit_detected = blocked_requests > 0
        
        threshold = 0
        if rate_limit_detected:
            for i in range(total_requests):
                if status_codes.get(200, 0) - blocked_requests <= i:
                    threshold = i + 1
                    break
            if threshold == 0:
                threshold = total_requests - blocked_requests
        
        result = RateLimitResult(
            endpoint=endpoint,
            requests_sent=total_requests,
            responses_received=responses_received,
            blocked_requests=blocked_requests,
            rate_limit_detected=rate_limit_detected,
            rate_limit_threshold=threshold,
            retry_after_header=retry_after_detected,
            status_codes=status_codes,
        )
        
        self.results.append(result)
        return result
    
    def test_concurrent_requests(
        self,
        endpoint: str,
        concurrent_count: int = 50
    ) -> RateLimitResult:
        """
        Test endpoint with concurrent requests.
        
        Args:
            endpoint: Target endpoint URL
            concurrent_count: Number of concurrent requests
            
        Returns:
            RateLimitResult object
        """
        responses_received = 0
        blocked_requests = 0
        status_codes: Dict[int, int] = {}
        lock = threading.Lock()
        
        def make_request():
            nonlocal responses_received, blocked_requests
            try:
                response = self.session.get(
                    endpoint,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                with lock:
                    responses_received += 1
                    status_code = response.status_code
                    status_codes[status_code] = status_codes.get(status_code, 0) + 1
                    
                    if status_code in [429, 403, 503]:
                        blocked_requests += 1
                        
            except RequestException:
                pass
        
        with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
            futures = [
                executor.submit(make_request)
                for _ in range(concurrent_count)
            ]
            
            for future in as_completed(futures):
                future.result()
        
        result = RateLimitResult(
            endpoint=endpoint,
            requests_sent=concurrent_count,
            responses_received=responses_received,
            blocked_requests=blocked_requests,
            rate_limit_detected=blocked_requests > 0,
            rate_limit_threshold=concurrent_count - blocked_requests,
            retry_after_header=False,
            status_codes=status_codes,
        )
        
        self.results.append(result)
        return result
    
    def analyze_results(self) -> List[Dict[str, Any]]:
        """
        Analyze rate limit test results for vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        for result in self.results:
            if not result.rate_limit_detected:
                vulnerabilities.append({
                    'type': 'No Rate Limiting',
                    'severity': 'high',
                    'endpoint': result.endpoint,
                    'description': f'Endpoint does not implement rate limiting. '
                                   f'{result.requests_sent} requests sent without blocking.',
                    'evidence': f'All {result.responses_received} requests completed successfully',
                    'remediation': 'Implement rate limiting with appropriate thresholds',
                })
            elif result.rate_limit_threshold > 100:
                vulnerabilities.append({
                    'type': 'Weak Rate Limiting',
                    'severity': 'medium',
                    'endpoint': result.endpoint,
                    'description': f'Rate limit threshold is too high ({result.rate_limit_threshold} requests)',
                    'evidence': f'Blocked after {result.rate_limit_threshold} requests',
                    'remediation': 'Reduce rate limit threshold to prevent abuse',
                })
            
            if not result.retry_after_header and result.rate_limit_detected:
                vulnerabilities.append({
                    'type': 'Missing Retry-After Header',
                    'severity': 'low',
                    'endpoint': result.endpoint,
                    'description': 'Rate limited responses missing Retry-After header',
                    'evidence': '429 responses without Retry-After header',
                    'remediation': 'Include Retry-After header in rate limit responses',
                })
        
        return vulnerabilities
    
    def run(self) -> Dict[str, Any]:
        """
        Run all rate limit tests.
        
        Returns:
            Dictionary with findings and errors
        """
        common_endpoints = [
            f"{self.target}/api/login",
            f"{self.target}/api/users",
            f"{self.target}/api/search",
        ]
        
        for endpoint in common_endpoints:
            self.test_endpoint(endpoint)
            self.test_concurrent_requests(endpoint)
        
        vulnerabilities = self.analyze_results()
        
        findings = []
        for vuln in vulnerabilities:
            findings.append(vuln)
        
        return {
            'findings': findings,
            'errors': self.errors,
            'endpoints_tested': len(common_endpoints),
            'vulnerabilities_found': len(vulnerabilities),
        }