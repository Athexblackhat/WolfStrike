# stealth/tor_handler.py

"""
TOR Network Handler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages TOR network routing for anonymous scanning
with automatic circuit renewal.
"""

import time
from typing import Dict, Any, Optional

import requests
from requests.exceptions import RequestException


class TorHandler:
    """
    TOR network routing handler.
    
    Provides TOR-based anonymous routing with
    circuit management and identity renewal.
    """
    
    DEFAULT_TOR_PROXY = 'socks5h://127.0.0.1:9050'
    DEFAULT_CONTROL_PORT = 9051
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the TOR handler.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.tor_proxy = self.config.get('tor_proxy', self.DEFAULT_TOR_PROXY)
        self.control_port = self.config.get('control_port', self.DEFAULT_CONTROL_PORT)
        self.control_password = self.config.get('control_password', '')
        self.auto_renew = self.config.get('auto_renew', False)
        self.renew_interval = self.config.get('renew_interval', 300)
        
        self.is_connected = False
        self.current_ip = ''
        self.last_renew_time = 0.0
        self.renew_count = 0
    
    def get_proxy_dict(self) -> Dict[str, str]:
        """
        Get TOR proxy configuration for requests.
        
        Returns:
            Proxy dictionary for requests library
        """
        return {
            'http': self.tor_proxy,
            'https': self.tor_proxy,
        }
    
    def test_connection(self) -> bool:
        """
        Test TOR connection.
        
        Returns:
            True if connected through TOR
        """
        try:
            proxies = self.get_proxy_dict()
            
            response = requests.get(
                'https://check.torproject.org/',
                proxies=proxies,
                timeout=15
            )
            
            if 'Congratulations' in response.text:
                self.is_connected = True
                
                ip_response = requests.get(
                    'https://api.ipify.org?format=json',
                    proxies=proxies,
                    timeout=10
                )
                
                if ip_response.status_code == 200:
                    import json
                    self.current_ip = ip_response.json().get('ip', '')
                
                return True
            
            return False
            
        except RequestException:
            self.is_connected = False
            return False
    
    def renew_identity(self) -> bool:
        """
        Renew TOR identity (new circuit).
        
        Returns:
            True if identity was renewed
        """
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', self.control_port))
            
            if self.control_password:
                sock.send(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
                response = sock.recv(512)
            
            sock.send(b'SIGNAL NEWNYM\r\n')
            response = sock.recv(512)
            
            sock.close()
            
            if b'250' in response:
                self.last_renew_time = time.time()
                self.renew_count += 1
                time.sleep(2)
                self.test_connection()
                return True
            
            return False
            
        except Exception:
            return False
    
    def check_and_renew(self) -> bool:
        """
        Check if renewal is needed and renew if necessary.
        
        Returns:
            True if identity is fresh
        """
        if not self.is_connected:
            return self.test_connection()
        
        if self.auto_renew:
            time_since_renew = time.time() - self.last_renew_time
            
            if time_since_renew >= self.renew_interval:
                return self.renew_identity()
        
        return self.is_connected
    
    def get_current_ip(self) -> str:
        """
        Get current TOR exit node IP.
        
        Returns:
            Current IP address string
        """
        if not self.current_ip:
            self.test_connection()
        
        return self.current_ip
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get TOR connection statistics.
        
        Returns:
            Dictionary with TOR statistics
        """
        return {
            'connected': self.is_connected,
            'current_ip': self.current_ip,
            'tor_proxy': self.tor_proxy,
            'renew_count': self.renew_count,
            'last_renew_time': self.last_renew_time,
            'auto_renew': self.auto_renew,
        }