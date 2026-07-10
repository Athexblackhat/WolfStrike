# modules/recon/reverse_ip.py

"""
Reverse IP Lookup
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Finds other domains hosted on the same IP address
to discover related targets and shared infrastructure.
"""

import socket
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class ReverseIPLookup:
    """
    Reverse IP address lookup engine.
    
    Discovers other domains hosted on the same IP
    to identify shared hosting and related targets.
    """
    
    LOOKUP_SOURCES = [
        'https://api.hackertarget.com/reverseiplookup/?q={ip}',
        'https://domains.yougetsignal.com/domains.php',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the reverse IP lookup.
        
        Args:
            target: Target domain or IP
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 15)
        
        self.domains: List[str] = []
        self.errors: List[str] = []
    
    def resolve_to_ip(self) -> Optional[str]:
        """
        Resolve domain to IP address.
        
        Returns:
            IP address string
        """
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, self.target):
            return self.target
        
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as e:
            self.errors.append(f"DNS resolution failed: {str(e)}")
            return None
    
    def lookup_hackertarget(self, ip: str) -> List[str]:
        """
        Query HackerTarget for reverse IP.
        
        Args:
            ip: IP address
            
        Returns:
            List of domain names
        """
        domains = []
        
        try:
            url = self.LOOKUP_SOURCES[0].format(ip=ip)
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                
                for line in lines:
                    line = line.strip().lower()
                    if line and not line.startswith('error') and not line.startswith('api'):
                        domains.append(line)
                        
        except RequestException as e:
            self.errors.append(f"HackerTarget reverse IP failed: {str(e)}")
        
        return domains
    
    def lookup_yougetsignal(self, ip: str) -> List[str]:
        """
        Query YouGetSignal for reverse IP.
        
        Args:
            ip: IP address
            
        Returns:
            List of domain names
        """
        domains = []
        
        try:
            data = {'remoteAddress': ip}
            response = self.session.post(
                self.LOOKUP_SOURCES[1],
                data=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                import json
                result = response.json()
                
                domain_list = result.get('domainArray', [])
                
                for domain_data in domain_list:
                    if isinstance(domain_data, list) and len(domain_data) >= 1:
                        domains.append(domain_data[0].lower())
                        
        except (RequestException, ValueError) as e:
            self.errors.append(f"YouGetSignal reverse IP failed: {str(e)}")
        
        return domains
    
    def run(self) -> Dict[str, Any]:
        """
        Run reverse IP lookup.
        
        Returns:
            Dictionary with lookup results
        """
        ip = self.resolve_to_ip()
        
        if not ip:
            return {
                'findings': [],
                'errors': self.errors,
                'ip': None,
                'domains': [],
            }
        
        hackertarget_domains = self.lookup_hackertarget(ip)
        yougetsignal_domains = self.lookup_yougetsignal(ip)
        
        all_domains = list(set(hackertarget_domains + yougetsignal_domains))
        all_domains.sort()
        
        findings = []
        
        if all_domains:
            findings.append({
                'type': 'Reverse IP Lookup',
                'severity': 'info',
                'ip': ip,
                'description': f'Found {len(all_domains)} domains hosted on {ip}',
                'evidence': all_domains[:30],
                'remediation': 'Review co-hosted domains for security implications',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'ip': ip,
            'domains': all_domains,
            'total_domains': len(all_domains),
        }