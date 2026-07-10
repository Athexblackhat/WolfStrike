# utils/network_utils.py

"""
Network Utilities
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides network-related utility functions including
IP validation, DNS lookups, CIDR calculations, and
socket operations.
"""

import re
import socket
import ipaddress
from typing import Dict, List, Any, Optional, Tuple


class NetworkUtils:
    """
    Network utility functions.
    
    Provides static methods for IP operations,
    DNS lookups, and network calculations.
    """
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Check if string is a valid IPv4 address.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv4
        """
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not re.match(pattern, ip):
            return False
        
        parts = ip.split('.')
        
        return all(0 <= int(p) <= 255 for p in parts)
    
    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """
        Check if string is a valid IPv6 address.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv6
        """
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP is in private range.
        
        Args:
            ip: IP address string
            
        Returns:
            True if private IP
        """
        try:
            return ipaddress.IPv4Address(ip).is_private
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address string or None
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    @staticmethod
    def reverse_dns(ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.gaierror, socket.herror):
            return None
    
    @staticmethod
    def calculate_cidr_range(cidr: str) -> Optional[Dict[str, Any]]:
        """
        Calculate IP range from CIDR notation.
        
        Args:
            cidr: CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            Dictionary with range details
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'hostmask': str(network.hostmask),
                'total_addresses': network.num_addresses,
                'usable_hosts': network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
                'first_host': str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address),
                'last_host': str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.broadcast_address),
            }
        except (ipaddress.AddressValueError, ValueError):
            return None
    
    @staticmethod
    def ip_to_integer(ip: str) -> Optional[int]:
        """
        Convert IP address to integer.
        
        Args:
            ip: IP address string
            
        Returns:
            Integer representation
        """
        try:
            return int(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            return None
    
    @staticmethod
    def integer_to_ip(ip_int: int) -> str:
        """
        Convert integer to IP address.
        
        Args:
            ip_int: Integer IP representation
            
        Returns:
            IP address string
        """
        try:
            return str(ipaddress.IPv4Address(ip_int))
        except ipaddress.AddressValueError:
            return '0.0.0.0'
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a TCP port is open.
        
        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout
            
        Returns:
            True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.error:
            return False
    
    @staticmethod
    def get_local_ip() -> str:
        """
        Get local machine IP address.
        
        Returns:
            Local IP address string
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(('8.8.8.8', 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except socket.error:
            return '127.0.0.1'
    
    @staticmethod
    def is_hostname(host: str) -> bool:
        """
        Check if string is a hostname.
        
        Args:
            host: Hostname string
            
        Returns:
            True if looks like hostname
        """
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(hostname_pattern, host))
    
    @staticmethod
    def parse_url(url: str) -> Dict[str, Optional[str]]:
        """
        Parse a URL into components.
        
        Args:
            url: URL string
            
        Returns:
            Dictionary with URL components
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        
        return {
            'scheme': parsed.scheme or None,
            'hostname': parsed.hostname or None,
            'port': str(parsed.port) if parsed.port else None,
            'path': parsed.path or '/',
            'query': parsed.query or None,
            'fragment': parsed.fragment or None,
            'netloc': parsed.netloc or None,
        }
    
    @staticmethod
    def build_url(
        scheme: str = 'https',
        hostname: str = '',
        port: Optional[int] = None,
        path: str = '/',
        query: Optional[str] = None
    ) -> str:
        """
        Build a URL from components.
        
        Args:
            scheme: URL scheme
            hostname: Hostname
            port: Port number
            path: URL path
            query: Query string
            
        Returns:
            Constructed URL string
        """
        url = f"{scheme}://{hostname}"
        
        if port and port not in [80, 443]:
            url += f":{port}"
        
        if path:
            url += '/' + path.lstrip('/')
        
        if query:
            url += '?' + query.lstrip('?')
        
        return url
    
    @staticmethod
    def get_http_status_text(status_code: int) -> str:
        """
        Get HTTP status code description.
        
        Args:
            status_code: HTTP status code
            
        Returns:
            Status description string
        """
        status_texts = {
            200: 'OK',
            201: 'Created',
            204: 'No Content',
            301: 'Moved Permanently',
            302: 'Found',
            304: 'Not Modified',
            307: 'Temporary Redirect',
            308: 'Permanent Redirect',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout',
        }
        
        return status_texts.get(status_code, 'Unknown')