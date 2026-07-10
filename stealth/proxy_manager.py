# stealth/proxy_manager.py

"""
Proxy Rotation Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages proxy server rotation for anonymous scanning
with support for HTTP, HTTPS, and SOCKS proxies.
"""

import random
import time
import socket
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


class ProxyManager:
    """
    Proxy rotation manager for anonymous scanning.
    
    Handles proxy validation, rotation, and health
    checking for HTTP, HTTPS, and SOCKS proxies.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the proxy manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.proxies: List[Dict[str, Any]] = []
        self.current_index = 0
        self.failed_proxies: Dict[str, int] = {}
        self.max_failures = self.config.get('max_failures', 3)
        self.rotation_strategy = self.config.get('rotation_strategy', 'round_robin')
        self.test_url = self.config.get('test_url', 'https://httpbin.org/ip')
        self.timeout = self.config.get('timeout', 10)
        
        self._load_proxies()
    
    def _load_proxies(self) -> None:
        """Load proxies from configuration."""
        proxy_list = self.config.get('proxy_list', [])
        proxy_file = self.config.get('proxy_file', '')
        
        if proxy_file:
            try:
                with open(proxy_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            proxy_list.append(line)
            except FileNotFoundError:
                pass
        
        for proxy_url in proxy_list:
            self.add_proxy(proxy_url)
    
    def add_proxy(self, proxy_url: str) -> bool:
        """
        Add a proxy to the rotation pool.
        
        Args:
            proxy_url: Proxy URL (http://host:port, socks5://host:port)
            
        Returns:
            True if proxy was added
        """
        parsed = urlparse(proxy_url)
        
        if not parsed.scheme or not parsed.hostname or not parsed.port:
            return False
        
        proxy_dict = {
            'url': proxy_url,
            'scheme': parsed.scheme,
            'host': parsed.hostname,
            'port': parsed.port,
            'username': parsed.username,
            'password': parsed.password,
            'added_at': time.time(),
            'last_used': 0,
            'success_count': 0,
            'failure_count': 0,
            'is_active': True,
        }
        
        self.proxies.append(proxy_dict)
        return True
    
    def remove_proxy(self, proxy_url: str) -> bool:
        """
        Remove a proxy from the rotation pool.
        
        Args:
            proxy_url: Proxy URL to remove
            
        Returns:
            True if proxy was removed
        """
        for i, proxy in enumerate(self.proxies):
            if proxy['url'] == proxy_url:
                self.proxies.pop(i)
                return True
        
        return False
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get next proxy from rotation pool.
        
        Returns:
            Proxy dictionary for requests library
        """
        active_proxies = [p for p in self.proxies if p['is_active']]
        
        if not active_proxies:
            return None
        
        if self.rotation_strategy == 'random':
            proxy = random.choice(active_proxies)
        elif self.rotation_strategy == 'round_robin':
            proxy = active_proxies[self.current_index % len(active_proxies)]
            self.current_index += 1
        else:
            proxy = active_proxies[0]
        
        proxy['last_used'] = time.time()
        
        proxy_url = proxy['url']
        
        if proxy.get('username') and proxy.get('password'):
            proxy_url = proxy_url.replace(
                f"{proxy['scheme']}://",
                f"{proxy['scheme']}://{proxy['username']}:{proxy['password']}@"
            )
        
        return {
            'http': proxy_url,
            'https': proxy_url,
        }
    
    def validate_proxy(self, proxy: Dict[str, Any]) -> bool:
        """
        Validate if a proxy is working.
        
        Args:
            proxy: Proxy dictionary
            
        Returns:
            True if proxy is valid
        """
        proxy_dict = {
            'http': proxy['url'],
            'https': proxy['url'],
        }
        
        try:
            response = requests.get(
                self.test_url,
                proxies=proxy_dict,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                proxy['success_count'] += 1
                proxy['is_active'] = True
                return True
            
        except RequestException:
            pass
        
        proxy['failure_count'] += 1
        
        if proxy['failure_count'] >= self.max_failures:
            proxy['is_active'] = False
        
        return False
    
    def validate_all_proxies(self) -> Dict[str, Any]:
        """
        Validate all proxies in pool.
        
        Returns:
            Dictionary with validation results
        """
        results = {'total': len(self.proxies), 'valid': 0, 'invalid': 0}
        
        for proxy in self.proxies:
            if self.validate_proxy(proxy):
                results['valid'] += 1
            else:
                results['invalid'] += 1
        
        return results
    
    def get_proxy_stats(self) -> Dict[str, Any]:
        """
        Get proxy pool statistics.
        
        Returns:
            Dictionary with proxy statistics
        """
        active = [p for p in self.proxies if p['is_active']]
        inactive = [p for p in self.proxies if not p['is_active']]
        
        return {
            'total_proxies': len(self.proxies),
            'active_proxies': len(active),
            'inactive_proxies': len(inactive),
            'proxies': [
                {
                    'url': p['url'],
                    'active': p['is_active'],
                    'success_count': p['success_count'],
                    'failure_count': p['failure_count'],
                    'last_used': p['last_used'],
                }
                for p in self.proxies
            ],
        }
    
    def rotate_proxy(self) -> Optional[Dict[str, str]]:
        """
        Rotate to next proxy and return it.
        
        Returns:
            Proxy dictionary for requests library
        """
        proxy = self.get_proxy()
        
        if proxy:
            self.current_index += 1
        
        return proxy
    
    def disable_failed_proxy(self, proxy_url: str) -> None:
        """
        Disable a failed proxy.
        
        Args:
            proxy_url: Proxy URL to disable
        """
        for proxy in self.proxies:
            if proxy['url'] == proxy_url:
                proxy['failure_count'] += 1
                
                if proxy['failure_count'] >= self.max_failures:
                    proxy['is_active'] = False
                break