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
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


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
        },
        'hcaptcha': {
            'site_key_pattern': r'data-sitekey=["\']([^"\']+)["\']',
            'script_pattern': r'hcaptcha\.com/1/api\.js',
        },
        'cloudflare_turnstile': {
            'site_key_pattern': r'data-sitekey=["\']([^"\']+)["\']',
            'script_pattern': r'challenges\.cloudflare\.com/turnstile',
        },
    }
    
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
        self.detected_captchas: List[Dict[str, Any]] = []
    
    def detect_captcha(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Detect CAPTCHA presence in response.
        
        Args:
            response_text: HTTP response text
            
        Returns:
            Dictionary with CAPTCHA info or None
        """
        response_lower = response_text.lower()
        
        for pattern in self.CAPTCHA_INDICATORS:
            if re.search(pattern, response_lower, re.IGNORECASE):
                captcha_info = {
                    'detected': True,
                    'pattern_matched': pattern,
                }
                
                for service_name, service_patterns in self.CAPTCHA_SERVICES.items():
                    if re.search(service_patterns['script_pattern'], response_text, re.IGNORECASE):
                        captcha_info['service'] = service_name
                        
                        site_key_match = re.search(
                            service_patterns['site_key_pattern'],
                            response_text,
                            re.IGNORECASE
                        )
                        
                        if site_key_match:
                            captcha_info['site_key'] = site_key_match.group(1)
                        
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
        try:
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            return self.detect_captcha(response.text)
            
        except RequestException:
            return None
    
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
            ],
            'hcaptcha': [
                'Rotate IP addresses frequently',
                'Use headless browser with stealth plugins',
                'Implement human-like mouse movements',
            ],
            'cloudflare_turnstile': [
                'Use residential proxies for better trust score',
                'Implement browser fingerprinting evasion',
                'Rotate User-Agent headers',
            ],
        }
        
        return strategies.get(captcha_service, [
            'Reduce request rate to avoid triggering',
            'Use proxy rotation',
            'Implement delays between requests',
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
            'services_detected': list(set(
                c.get('service', 'unknown')
                for c in self.detected_captchas
            )),
        }