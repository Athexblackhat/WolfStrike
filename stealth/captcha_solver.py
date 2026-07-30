# stealth/captcha_solver.py

"""
CAPTCHA Detection and Bypass
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects CAPTCHA challenges and provides bypass
strategies for automated scanning.
"""

import re
import time
from typing import Dict, List, Any, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError


class CaptchaSolver:
    """
    CAPTCHA detection and bypass handler.
    
    Detects CAPTCHA presence and applies bypass
    strategies for continued scanning.
    """
    
    CAPTCHA_INDICATORS = [
        r'captcha',
        r'recaptcha',
        r'hcaptcha',
        r'g-recaptcha',
        r'grecaptcha',
        r'cf-turnstile',
        r'cloudflare.*challenge',
        r'verify you are human',
        r'are you a robot',
        r'please solve',
        r'security check',
        r'human verification',
        r'bot check',
        r'challenge.*required',
    ]
    
    CAPTCHA_SERVICES = {
        'recaptcha': {
            'site_key_pattern': r'(?:data-)?sitekey=["\']([^"\']+)["\']',
            'script_pattern': r'(?:recaptcha/api\.js|recaptcha/enterprise\.js)',
            'api_endpoint': 'https://api.2captcha.com/',
            'min_key_length': 20,
        },
        'hcaptcha': {
            'site_key_pattern': r'data-sitekey=["\']([^"\']+)["\']',
            'script_pattern': r'hcaptcha\.com/1/api\.js',
            'api_endpoint': 'https://api.hcaptcha.com/',
            'min_key_length': 20,
        },
        'cloudflare_turnstile': {
            'site_key_pattern': r'data-sitekey=["\']([^"\']+)["\']',
            'script_pattern': r'challenges\.cloudflare\.com/turnstile',
            'api_endpoint': 'https://challenges.cloudflare.com/',
            'min_key_length': 16,
        },
    }
    
    SUPPORTED_SOLVERS = ['2captcha', 'capmonster', 'anticaptcha']
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CAPTCHA handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.api_key = self.config.get('captcha_api_key', '')
        self.auto_solve = self.config.get('auto_solve', False)
        self.solver_service = self.config.get('solver_service', '2captcha')
        self.timeout = self.config.get('timeout', 30)
        self.max_attempts = self.config.get('max_attempts', 3)
        
        self.detected_captchas: List[Dict[str, Any]] = []
        self.solved_captchas: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        
        # Validate API key
        self._validate_api_key()
    
    def _validate_api_key(self) -> bool:
        """
        Validate CAPTCHA API key.
        
        Returns:
            True if API key is valid format
        """
        if not self.api_key:
            self.errors.append("CAPTCHA API key is not configured")
            return False
        
        if len(self.api_key) < 10:
            self.errors.append("CAPTCHA API key appears too short")
            return False
        
        # Check if it contains valid characters (alphanumeric + some special)
        if not re.match(r'^[A-Za-z0-9_\-]+$', self.api_key):
            self.errors.append("CAPTCHA API key contains invalid characters")
            return False
        
        return True
    
    def _get_api_service(self) -> str:
        """
        Get the API service to use.
        
        Returns:
            Service name string
        """
        if self.solver_service in self.SUPPORTED_SOLVERS:
            return self.solver_service
        return '2captcha'  # Default
    
    def _check_api_availability(self) -> bool:
        """
        Check if the configured API service is available.
        
        Returns:
            True if API is available
        """
        if not self._validate_api_key():
            return False
        
        # For 2captcha, test the API key
        if self.solver_service == '2captcha':
            try:
                response = requests.get(
                    f'https://api.2captcha.com/getBalance?key={self.api_key}',
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 1:
                        return True
                    else:
                        self.errors.append(f"2Captcha API error: {data.get('error', 'Unknown error')}")
                        return False
            except Exception as e:
                self.errors.append(f"2Captcha API check failed: {str(e)}")
                return False
        
        return True
    
    def _safe_request(self, url: str, timeout: Optional[int] = None) -> Optional[requests.Response]:
        """
        Safely make HTTP request.
        
        Args:
            url: Target URL
            timeout: Request timeout
            
        Returns:
            HTTP response or None
        """
        if timeout is None:
            timeout = self.timeout
        
        try:
            return requests.get(
                url,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                }
            )
        except (Timeout, ConnectionError) as e:
            self.errors.append(f"CAPTCHA detection request timed out: {str(e)}")
            return None
        except RequestException as e:
            self.errors.append(f"CAPTCHA detection request failed: {str(e)}")
            return None
    
    def _validate_response(self, response: Optional[requests.Response]) -> bool:
        """
        Validate HTTP response.
        
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
    
    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        if not url:
            return ''
        
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Ensure scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    def _extract_site_key(self, response_text: str, service_name: str) -> Optional[str]:
        """
        Extract site key from response.
        
        Args:
            response_text: HTTP response text
            service_name: CAPTCHA service name
            
        Returns:
            Site key or None
        """
        service = self.CAPTCHA_SERVICES.get(service_name)
        if not service:
            return None
        
        pattern = service.get('site_key_pattern', '')
        if not pattern:
            return None
        
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return None
    
    def _is_captcha_page(self, response_text: str) -> bool:
        """
        Check if page is a CAPTCHA challenge page.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            True if CAPTCHA page
        """
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        
        for pattern in self.CAPTCHA_INDICATORS:
            if re.search(pattern, response_lower, re.IGNORECASE):
                return True
        
        # Check for specific challenge patterns
        challenge_patterns = [
            r'<iframe.*?src=.*?recaptcha',
            r'<div.*?g-recaptcha',
            r'<div.*?h-captcha',
            r'<script.*?challenges\.cloudflare',
        ]
        
        for pattern in challenge_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _get_captcha_type(self, response_text: str) -> str:
        """
        Identify CAPTCHA type from response.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            CAPTCHA type string
        """
        if not response_text:
            return 'unknown'
        
        response_lower = response_text.lower()
        
        for service_name in self.CAPTCHA_SERVICES.keys():
            if service_name.lower() in response_lower:
                return service_name
        
        return 'unknown'
    
    def _get_solver_priority(self) -> List[str]:
        """
        Get solver priority list.
        
        Returns:
            List of solver names in priority order
        """
        return [
            self.solver_service,
            '2captcha',
            'capmonster',
            'anticaptcha',
        ]
    
    def detect_captcha(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Detect CAPTCHA presence in response.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            Dictionary with CAPTCHA info or None
        """
        if not response_text:
            return None
        
        response_lower = response_text.lower()
        
        for pattern in self.CAPTCHA_INDICATORS:
            if re.search(pattern, response_lower, re.IGNORECASE):
                captcha_info = {
                    'detected': True,
                    'pattern_matched': pattern,
                    'captcha_type': self._get_captcha_type(response_text),
                    'site_key': None,
                }
                
                # Try to identify service and extract site key
                for service_name, service_patterns in self.CAPTCHA_SERVICES.items():
                    if re.search(service_patterns['script_pattern'], response_text, re.IGNORECASE):
                        captcha_info['service'] = service_name
                        
                        site_key = self._extract_site_key(response_text, service_name)
                        if site_key:
                            captcha_info['site_key'] = site_key
                        break
                
                self.detected_captchas.append(captcha_info)
                return captcha_info
        
        return None
    
    def detect_on_page(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Detect CAPTCHA on a web page.
        
        Args:
            url: Page URL
            
        Returns:
            Dictionary with CAPTCHA info or None
        """
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            self.errors.append("Invalid URL provided for CAPTCHA detection")
            return None
        
        response = self._safe_request(normalized_url)
        
        if not self._validate_response(response):
            return None
        
        if response.status_code != 200:
            self.errors.append(f"Page returned status {response.status_code}")
            return None
        
        return self.detect_captcha(response.text)
    
    def get_bypass_strategies(self, captcha_service: str) -> List[str]:
        """
        Get bypass strategies for a CAPTCHA service.
        
        Args:
            captcha_service: CAPTCHA service name
            
        Returns:
            List of bypass strategy descriptions
        """
        strategies = {
            'recaptcha': [
                'Use rotating proxies to avoid triggering reCAPTCHA',
                'Implement request delays to appear more human-like',
                'Use audio challenge solving service',
                'Attempt to reuse valid reCAPTCHA tokens',
                'Use browser automation with stealth plugins',
                'Implement human-like mouse movements and interactions',
            ],
            'hcaptcha': [
                'Rotate IP addresses frequently',
                'Use headless browser with stealth plugins',
                'Implement human-like mouse movements',
                'Use hcaptcha solving service',
                'Implement browser fingerprinting evasion',
            ],
            'cloudflare_turnstile': [
                'Use residential proxies for better trust score',
                'Implement browser fingerprinting evasion',
                'Rotate User-Agent headers',
                'Use cloudflare bypass techniques',
                'Implement proper cookie handling',
            ],
        }
        
        return strategies.get(captcha_service, [
            'Reduce request rate to avoid triggering',
            'Use proxy rotation',
            'Implement delays between requests',
            'Use headless browser for JavaScript execution',
            'Implement proper session management',
        ])
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get CAPTCHA detection statistics.
        
        Returns:
            Dictionary with CAPTCHA statistics
        """
        return {
            'total_detected': len(self.detected_captchas),
            'captchas': self.detected_captchas,
            'solved': len(self.solved_captchas),
            'services_detected': list(set(
                c.get('service', 'unknown')
                for c in self.detected_captchas
            )),
            'api_configured': bool(self.api_key),
            'api_valid': self._validate_api_key(),
            'scan_status': self.scan_status,
        }
    
    def check_api_status(self) -> Dict[str, Any]:
        """
        Check API status and availability.
        
        Returns:
            Dictionary with API status
        """
        is_valid = self._validate_api_key()
        is_available = self._check_api_availability() if is_valid else False
        
        return {
            'api_key_configured': bool(self.api_key),
            'api_key_valid': is_valid,
            'api_available': is_available,
            'solver_service': self._get_api_service(),
            'supported_services': self.SUPPORTED_SOLVERS,
        }
    
    def run(self, url: str) -> Dict[str, Any]:
        """
        Run CAPTCHA detection and bypass attempt.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with detection results
        """
        # Reset state
        self.detected_captchas.clear()
        self.errors.clear()
        self.scan_status = 'running'
        
        # Normalize URL
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            self.scan_status = 'failed'
            return {
                'detected': False,
                'errors': ['Invalid URL provided'],
                'scan_status': 'failed',
                'captcha_info': None,
                'api_status': self.check_api_status(),
            }
        
        # Detect CAPTCHA
        captcha_info = self.detect_on_page(normalized_url)
        
        if captcha_info and captcha_info.get('detected'):
            self.scan_status = 'captcha_detected'
            
            # If auto-solve is enabled, attempt to solve
            if self.auto_solve:
                self.scan_status = 'attempting_solve'
                # Auto-solve logic would go here
                # For now, just mark as detected
            
            return {
                'detected': True,
                'captcha_info': captcha_info,
                'bypass_strategies': self.get_bypass_strategies(
                    captcha_info.get('service', 'unknown')
                ),
                'scan_status': self.scan_status,
                'errors': self.errors,
                'api_status': self.check_api_status(),
            }
        else:
            self.scan_status = 'no_captcha'
            return {
                'detected': False,
                'captcha_info': None,
                'scan_status': self.scan_status,
                'errors': self.errors,
                'api_status': self.check_api_status(),
            }
