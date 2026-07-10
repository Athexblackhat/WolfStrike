# modules/attacks/race_condition.py

"""
Race Condition Attack Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for race condition vulnerabilities including
TOCTOU, parallel request abuse, and limit-overrun attacks.
"""

import time
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException


@dataclass
class RaceConditionResult:
    """Represents a race condition test result."""
    endpoint: str
    test_type: str
    concurrent_requests: int
    successful_requests: int
    rate_limited_requests: int
    inconsistent_responses: int
    vulnerability_found: bool
    description: str
    evidence: Dict[str, Any]


class RaceConditionTester:
    """
    Race condition vulnerability tester.
    
    Tests for time-of-check time-of-use (TOCTOU) flaws,
    parallel request abuse, and limit-overrun vulnerabilities
    by sending concurrent requests to critical endpoints.
    """
    
    TEST_SCENARIOS = {
        'coupon_redemption': {
            'endpoints': ['/api/coupons/redeem', '/api/vouchers/apply', '/api/discounts/use'],
            'methods': ['POST'],
            'body_template': {'code': 'TEST100', 'amount': 100},
        },
        'balance_transfer': {
            'endpoints': ['/api/transfer', '/api/payment/send', '/api/wallet/transfer'],
            'methods': ['POST'],
            'body_template': {'to': 'user2', 'amount': 1000},
        },
        'account_creation': {
            'endpoints': ['/api/register', '/api/users', '/api/signup'],
            'methods': ['POST'],
            'body_template': {'username': 'testuser', 'email': 'test@test.com', 'password': 'Test123!'},
        },
        'voting_like': {
            'endpoints': ['/api/vote', '/api/like', '/api/upvote'],
            'methods': ['POST'],
            'body_template': {'item_id': 1},
        },
        'inventory_purchase': {
            'endpoints': ['/api/orders', '/api/purchase', '/api/buy'],
            'methods': ['POST'],
            'body_template': {'product_id': 1, 'quantity': 1},
        },
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the race condition tester.
        
        Args:
            target: Target base URL
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
        self.concurrent_requests = self.config.get('concurrent_requests', 20)
        
        self.results: List[RaceConditionResult] = []
        self.errors: List[str] = []
        self.auth_token: Optional[str] = self.config.get('auth_token')
        
        if self.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def test_endpoint(
        self,
        endpoint: str,
        method: str = 'POST',
        body: Optional[Dict[str, Any]] = None,
        concurrent_count: int = 20,
        test_type: str = 'generic'
    ) -> RaceConditionResult:
        """
        Test an endpoint for race conditions with concurrent requests.
        
        Args:
            endpoint: Target endpoint URL
            method: HTTP method
            body: Request body
            concurrent_count: Number of concurrent requests
            test_type: Type of race condition test
            
        Returns:
            RaceConditionResult object
        """
        full_url = f"{self.target}{endpoint}"
        
        successful = 0
        rate_limited = 0
        inconsistent = 0
        response_times: List[float] = []
        response_statuses: Dict[int, int] = {}
        response_bodies: List[str] = []
        
        lock = threading.Lock()
        
        def make_request(request_id: int):
            nonlocal successful, rate_limited, inconsistent
            
            try:
                start_time = time.time()
                
                if method == 'GET':
                    response = self.session.get(
                        full_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                else:
                    response = self.session.request(
                        method,
                        full_url,
                        json=body,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                
                elapsed = time.time() - start_time
                
                with lock:
                    response_times.append(elapsed)
                    
                    status_code = response.status_code
                    response_statuses[status_code] = response_statuses.get(status_code, 0) + 1
                    
                    if status_code in [200, 201, 202]:
                        successful += 1
                        response_bodies.append(response.text[:200])
                    elif status_code == 429:
                        rate_limited += 1
                    else:
                        response_bodies.append(response.text[:200])
                    
            except RequestException:
                with lock:
                    pass
        
        threads = []
        for i in range(concurrent_count):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=self.timeout + 5)
        
        unique_responses = len(set(response_bodies))
        if unique_responses > 1 and successful > 1:
            inconsistent = unique_responses
        
        vulnerability_found = False
        description = "No race condition detected"
        
        if successful > 1 and rate_limited == 0:
            vulnerability_found = True
            description = (
                f"Race condition possible: {successful}/{concurrent_count} "
                f"concurrent requests succeeded without rate limiting"
            )
        elif inconsistent > 1:
            vulnerability_found = True
            description = (
                f"Inconsistent responses detected: {inconsistent} different responses "
                f"from {successful} successful requests indicate race condition"
            )
        elif max(response_times) > min(response_times) * 3 and successful > 1:
            vulnerability_found = True
            description = (
                f"Significant response time variation ({min(response_times):.3f}s - "
                f"{max(response_times):.3f}s) suggests race condition"
            )
        
        result = RaceConditionResult(
            endpoint=full_url,
            test_type=test_type,
            concurrent_requests=concurrent_count,
            successful_requests=successful,
            rate_limited_requests=rate_limited,
            inconsistent_responses=inconsistent,
            vulnerability_found=vulnerability_found,
            description=description,
            evidence={
                'response_statuses': response_statuses,
                'response_times': {
                    'min': min(response_times) if response_times else 0,
                    'max': max(response_times) if response_times else 0,
                    'avg': sum(response_times) / len(response_times) if response_times else 0,
                },
                'unique_responses': unique_responses,
            }
        )
        
        self.results.append(result)
        return result
    
    def test_all_scenarios(self) -> List[RaceConditionResult]:
        """
        Test all predefined race condition scenarios.
        
        Returns:
            List of RaceConditionResult objects
        """
        for scenario_name, scenario in self.TEST_SCENARIOS.items():
            for endpoint in scenario['endpoints']:
                for method in scenario['methods']:
                    body = scenario.get('body_template', {})
                    self.test_endpoint(
                        endpoint=endpoint,
                        method=method,
                        body=body,
                        test_type=scenario_name
                    )
        
        return self.results
    
    def test_timing_attack(
        self,
        endpoint: str,
        sequential_count: int = 10
    ) -> RaceConditionResult:
        """
        Test for timing-based race conditions with sequential requests.
        
        Args:
            endpoint: Target endpoint URL
            sequential_count: Number of sequential requests
            
        Returns:
            RaceConditionResult object
        """
        full_url = f"{self.target}{endpoint}"
        response_times: List[float] = []
        successful = 0
        
        for i in range(sequential_count):
            try:
                start_time = time.time()
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                elapsed = time.time() - start_time
                
                response_times.append(elapsed)
                
                if response.status_code == 200:
                    successful += 1
                
                time.sleep(0.01)
                
            except RequestException:
                continue
        
        vulnerability_found = False
        description = "No timing vulnerability detected"
        
        if len(response_times) >= 3:
            first_half = response_times[:len(response_times)//2]
            second_half = response_times[len(response_times)//2:]
            
            avg_first = sum(first_half) / len(first_half)
            avg_second = sum(second_half) / len(second_half)
            
            if avg_second > avg_first * 1.5:
                vulnerability_found = True
                description = (
                    f"Response time degradation detected: "
                    f"{avg_first:.3f}s -> {avg_second:.3f}s"
                )
        
        result = RaceConditionResult(
            endpoint=full_url,
            test_type='timing_attack',
            concurrent_requests=sequential_count,
            successful_requests=successful,
            rate_limited_requests=0,
            inconsistent_responses=0,
            vulnerability_found=vulnerability_found,
            description=description,
            evidence={
                'response_times': response_times,
            }
        )
        
        self.results.append(result)
        return result
    
    def run(self) -> Dict[str, Any]:
        """
        Run all race condition tests.
        
        Returns:
            Dictionary with test results
        """
        self.test_all_scenarios()
        
        self.test_timing_attack('/api/users/1')
        
        findings = []
        for result in self.results:
            if result.vulnerability_found:
                findings.append({
                    'type': f'Race Condition: {result.test_type}',
                    'severity': 'high',
                    'endpoint': result.endpoint,
                    'description': result.description,
                    'evidence': result.evidence,
                    'remediation': 'Implement proper locking mechanisms, idempotency keys, '
                                   'and transaction isolation for critical operations',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'scenarios_tested': len(self.TEST_SCENARIOS),
            'total_tests': len(self.results),
            'vulnerabilities_found': len(findings),
        }