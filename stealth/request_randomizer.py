# stealth/request_randomizer.py

"""
Request Randomizer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Randomizes HTTP request parameters to avoid
fingerprinting and pattern-based detection.
"""

import random
import string
from typing import Dict, List, Any, Optional, Tuple


class RequestRandomizer:
    """
    HTTP request randomizer for stealth scanning.
    
    Randomizes headers, parameters, and request
    patterns to avoid detection and fingerprinting.
    """
    
    ACCEPT_HEADERS = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    ]
    
    ACCEPT_LANGUAGE_HEADERS = [
        'en-US,en;q=0.9',
        'en-US,en;q=0.5',
        'en-GB,en;q=0.9,en-US;q=0.8',
        'en-US,en;q=0.9,fr;q=0.7',
    ]
    
    ACCEPT_ENCODING_HEADERS = [
        'gzip, deflate, br',
        'gzip, deflate',
        'gzip, deflate, br, zstd',
    ]
    
    CACHE_CONTROL_HEADERS = [
        'no-cache',
        'max-age=0',
        'no-cache, no-store, must-revalidate',
    ]
    
    REFERER_TEMPLATES = [
        'https://www.google.com/search?q={keyword}',
        'https://www.bing.com/search?q={keyword}',
        'https://duckduckgo.com/?q={keyword}',
        None,
    ]
    
    KEYWORDS = [
        'security', 'technology', 'development',
        'web', 'software', 'cloud', 'data',
        'api', 'service', 'platform',
    ]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the request randomizer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.randomize_headers = self.config.get('randomize_headers', True)
        self.randomize_params = self.config.get('randomize_params', True)
        self.add_noise_params = self.config.get('add_noise_params', False)
    
    def get_random_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Generate randomized HTTP headers.
        
        Args:
            base_headers: Base headers to extend
            
        Returns:
            Dictionary of randomized headers
        """
        headers = base_headers.copy() if base_headers else {}
        
        if self.randomize_headers:
            headers['Accept'] = random.choice(self.ACCEPT_HEADERS)
            headers['Accept-Language'] = random.choice(self.ACCEPT_LANGUAGE_HEADERS)
            headers['Accept-Encoding'] = random.choice(self.ACCEPT_ENCODING_HEADERS)
            headers['Cache-Control'] = random.choice(self.CACHE_CONTROL_HEADERS)
            
            if 'Referer' not in headers:
                referer_template = random.choice(self.REFERER_TEMPLATES)
                
                if referer_template:
                    keyword = random.choice(self.KEYWORDS)
                    headers['Referer'] = referer_template.format(keyword=keyword)
            
            if 'Connection' not in headers:
                headers['Connection'] = random.choice(['keep-alive', 'close'])
        
        return headers
    
    def add_noise_parameters(
        self,
        params: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Add random noise parameters to request.
        
        Args:
            params: Original parameters
            
        Returns:
            Parameters with noise added
        """
        if not self.add_noise_params:
            return params
        
        noisy_params = params.copy()
        
        noise_params = {
            '_': str(random.randint(100000, 999999)),
            '_t': str(int(random.random() * 1000000)),
            'r': ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
        }
        
        for key, value in noise_params.items():
            if key not in noisy_params:
                if random.random() > 0.5:
                    noisy_params[key] = value
        
        return noisy_params
    
    def randomize_delay(self, base_delay: float) -> float:
        """
        Add random jitter to delay.
        
        Args:
            base_delay: Base delay in seconds
            
        Returns:
            Randomized delay value
        """
        if base_delay <= 0:
            return 0.0
        
        jitter = random.uniform(-0.3, 0.3) * base_delay
        return max(0.0, base_delay + jitter)
    
    def randomize_order(self, items: List[Any]) -> List[Any]:
        """
        Randomize the order of items.
        
        Args:
            items: List of items to randomize
            
        Returns:
            Shuffled list
        """
        shuffled = items.copy()
        random.shuffle(shuffled)
        return shuffled
    
    def generate_random_boundary(self) -> str:
        """
        Generate random multipart boundary string.
        
        Returns:
            Random boundary string
        """
        return '-' * 20 + ''.join(
            random.choices(string.hexdigits, k=16)
        )