# modules/network/asn_lookup.py

"""
ASN Lookup Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Performs ASN lookups and IP range analysis for
network reconnaissance and scope identification.
"""

import re
import socket
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

import dns.resolver


class ASNLookup:
    """
    ASN and IP range lookup module.
    
    Queries multiple sources for ASN information,
    IP ranges, and network ownership details.
    """
    
    ASN_SOURCES = [
        'https://api.hackertarget.com/aslookup/?q={target}',
        'https://rdap.arin.net/registry/ip/{target}',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the ASN lookup module.
        
        Args:
            target: Target IP or domain
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        
        self.results: Dict[str, Any] = {}
        self.errors: List[str] = []
    
    def resolve_to_ip(self) -> Optional[str]:
        """
        Resolve domain to IP address.
        
        Returns:
            IP address string or None
        """
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, self.target):
            return self.target
        
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror as e:
            self.errors.append(f"DNS resolution failed: {str(e)}")
            return None
    
    def lookup_asn_hackertarget(self, target: str) -> Optional[str]:
        """
        Query HackerTarget for ASN information.
        
        Args:
            target: IP address
            
        Returns:
            Raw response text or None
        """
        try:
            url = self.ASN_SOURCES[0].format(target=target)
            request = Request(url, headers={'User-Agent': 'WOLFSTRIKE/1.0'})
            
            with urlopen(request, timeout=10) as response:
                return response.read().decode('utf-8')
                
        except URLError as e:
            return None
        except Exception as e:
            self.errors.append(f"HackerTarget lookup failed: {str(e)}")
            return None
    
    def parse_asn_info(self, raw_data: str) -> Dict[str, Any]:
        """
        Parse ASN information from raw response.
        
        Args:
            raw_data: Raw response text
            
        Returns:
            Dictionary with parsed ASN data
        """
        info = {
            'asn': '',
            'asn_name': '',
            'ip_range': '',
            'organization': '',
            'country': '',
            'raw': raw_data,
        }
        
        lines = raw_data.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith('"') or line.startswith('ASN'):
                continue
            
            if '|' in line:
                parts = line.split('|')
                
                if len(parts) >= 2:
                    try:
                        info['ip_range'] = parts[0].strip().strip('"')
                        info['asn'] = parts[1].strip().strip('"')
                        
                        if len(parts) >= 3:
                            info['asn_name'] = parts[2].strip().strip('"')
                        
                        if len(parts) >= 4:
                            info['country'] = parts[3].strip().strip('"')
                    except (IndexError, ValueError):
                        pass
        
        return info
    
    def get_ptr_record(self, ip: str) -> Optional[str]:
        """
        Get PTR (reverse DNS) record for IP.
        
        Args:
            ip: IP address
            
        Returns:
            PTR record string or None
        """
        try:
            parts = ip.split('.')
            reverse_ip = '.'.join(reversed(parts)) + '.in-addr.arpa'
            
            answers = dns.resolver.resolve(reverse_ip, 'PTR')
            
            for answer in answers:
                return answer.to_text().rstrip('.')
            
            return None
            
        except Exception:
            return None
    
    def calculate_ip_range(self, ip: str, cidr: Optional[int] = None) -> Dict[str, Any]:
        """
        Calculate IP range information.
        
        Args:
            ip: IP address
            cidr: CIDR notation (e.g., 24)
            
        Returns:
            Dictionary with range information
        """
        try:
            parts = [int(p) for p in ip.split('.')]
            
            if not all(0 <= p <= 255 for p in parts):
                return {'error': 'Invalid IP address'}
            
            binary_ip = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            if cidr is None:
                cidr = 24
            
            mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
            network_start = binary_ip & mask
            network_end = network_start + (0xFFFFFFFF ^ mask)
            
            start_parts = [
                (network_start >> 24) & 0xFF,
                (network_start >> 16) & 0xFF,
                (network_start >> 8) & 0xFF,
                network_start & 0xFF,
            ]
            
            end_parts = [
                (network_end >> 24) & 0xFF,
                (network_end >> 16) & 0xFF,
                (network_end >> 8) & 0xFF,
                network_end & 0xFF,
            ]
            
            return {
                'network': '.'.join(str(p) for p in start_parts) + f'/{cidr}',
                'start_ip': '.'.join(str(p) for p in start_parts),
                'end_ip': '.'.join(str(p) for p in end_parts),
                'total_addresses': (network_end - network_start) + 1,
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def run(self) -> Dict[str, Any]:
        """
        Run ASN lookup.
        
        Returns:
            Dictionary with lookup results
        """
        ip = self.resolve_to_ip()
        
        if not ip:
            return {
                'findings': [],
                'errors': self.errors,
                'ip': None,
            }
        
        raw_data = self.lookup_asn_hackertarget(ip)
        asn_info = self.parse_asn_info(raw_data) if raw_data else {}
        ptr_record = self.get_ptr_record(ip)
        ip_range = self.calculate_ip_range(ip)
        
        findings = []
        
        if asn_info.get('asn'):
            findings.append({
                'type': 'ASN Information',
                'severity': 'info',
                'target': self.target,
                'ip': ip,
                'description': f'ASN: {asn_info["asn"]} - {asn_info.get("asn_name", "Unknown")}',
                'evidence': asn_info,
                'remediation': 'Review ASN and IP range for scope definition',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'ip': ip,
            'ptr_record': ptr_record,
            'asn_info': asn_info,
            'ip_range': ip_range,
        }