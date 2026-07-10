# stealth/rate_limiter.py

"""
Intelligent Rate Limiter
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Smart rate limiting with adaptive delays to avoid
detection and bypass rate-based WAF rules.
"""

import time
import random
from typing import Dict, Any, Optional


class RateLimiter:
    """
    Intelligent rate limiter for stealth scanning.
    
    Implements adaptive delays and jitter to avoid
    triggering rate-based detection systems.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the rate limiter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.base_delay = self.config.get('base_delay', 0.5)
        self.min_delay = self.config.get('min_delay', 0.1)
        self.max_delay = self.config.get('max_delay', 5.0)
        self.jitter = self.config.get('jitter', 0.3)
        self.adaptive_mode = self.config.get('adaptive_mode', True)
        
        self.last_request_time = 0.0
        self.request_count = 0
        self.consecutive_429 = 0
        self.current_delay = self.base_delay
        self.total_requests = 0
        self.total_delay_time = 0.0
    
    def wait(self) -> float:
        """
        Wait for the appropriate delay before next request.
        
        Returns:
            Actual delay time used
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.current_delay:
            wait_time = self.current_delay - time_since_last
            
            if self.jitter > 0:
                jitter_amount = random.uniform(-self.jitter, self.jitter)
                wait_time = max(self.min_delay, wait_time + jitter_amount)
            
            time.sleep(wait_time)
        else:
            wait_time = 0.0
        
        self.last_request_time = time.time()
        self.request_count += 1
        self.total_requests += 1
        self.total_delay_time += wait_time
        
        return wait_time
    
    def report_success(self) -> None:
        """Report a successful request to adjust rate."""
        if self.adaptive_mode:
            self.consecutive_429 = max(0, self.consecutive_429 - 1)
            
            if self.consecutive_429 == 0:
                self.current_delay = max(
                    self.min_delay,
                    self.current_delay * 0.9
                )
    
    def report_rate_limit(self) -> None:
        """Report a rate limit response (HTTP 429)."""
        self.consecutive_429 += 1
        
        if self.adaptive_mode:
            multiplier = 1.5 + (self.consecutive_429 * 0.5)
            self.current_delay = min(
                self.max_delay,
                self.current_delay * multiplier
            )
    
    def report_error(self) -> None:
        """Report a request error."""
        if self.adaptive_mode:
            self.current_delay = min(
                self.max_delay,
                self.current_delay * 1.2
            )
    
    def set_delay(self, delay: float) -> None:
        """
        Set the base delay.
        
        Args:
            delay: Delay in seconds
        """
        self.current_delay = max(self.min_delay, min(self.max_delay, delay))
    
    def reset(self) -> None:
        """Reset rate limiter state."""
        self.last_request_time = 0.0
        self.request_count = 0
        self.consecutive_429 = 0
        self.current_delay = self.base_delay
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiter statistics.
        
        Returns:
            Dictionary with rate statistics
        """
        return {
            'total_requests': self.total_requests,
            'total_delay_time': f'{self.total_delay_time:.2f}s',
            'current_delay': f'{self.current_delay:.3f}s',
            'base_delay': f'{self.base_delay:.3f}s',
            'consecutive_429': self.consecutive_429,
            'adaptive_mode': self.adaptive_mode,
            'jitter': self.jitter,
        }