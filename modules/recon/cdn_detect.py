# modules/recon/cdn_detect.py

"""
CDN Detection Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects Content Delivery Networks and identifies
real origin IP behind CDN services.
"""

import socket
from typing import Dict, List, Any, Optional, Set

import requests
from requests.exceptions import RequestException
import dns.resolver


class CDNDetector:
    """
    Content Delivery Network detector.
    
    Identifies CDN providers and attempts to discover
    origin IP addresses behind CDN protection.
    """
    
    CDN_HEADERS = {
        'Cloudflare': ['cf-ray', 'CF-Cache-Status', 'CF-RAY'],
        'Akamai': ['X-Akamai-Transformed', 'Akamai-Ghost'],
        'Amazon CloudFront': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop', 'X-Amz-Cf-Origin'],
        'Fastly': ['X-Served-By', 'X-Cache', 'X-Cache-Hits', 'X-Timer'],
        'Azure CDN': ['X-Azure-Ref', 'X-Azure-RequestChain'],
        'StackPath': ['X-StackPath-Edge', 'X-StackPath-RequestId'],
        'KeyCDN': ['X-Edge-Location', 'X-Edge-IP'],
        'BunnyCDN': ['X-BunnyCDN', 'Server: BunnyCDN'],
        'Sucuri': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
        'Incapsula': ['X-Iinfo', 'X-CDN'],
    }
    
    CDN_CNAME_PATTERNS = {
        'Cloudflare': ['cloudflare.net', 'cfargotunnel.com'],
        'Akamai': ['akamai.net', 'akamaiedge.net', 'edgesuite.net'],
        'Amazon CloudFront': ['cloudfront.net'],
        'Fastly': ['fastly.net'],
        'Azure CDN': ['azureedge.net', 'vo.msecnd.net'],
        'StackPath': ['stackpathcdn.com'],
        'KeyCDN': ['kxcdn.com'],
        'BunnyCDN': ['b-cdn.net'],
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the CDN detector.
        
        Args:
            target: Target domain
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        self.session = requests.Session()
        
        self.timeout = self.config.get('timeout', 10)
        
        self.detected_cdns: List[str] = []
        self.origin_ips: Set[str] = set()
        self.errors: List[str] = []
    
    def detect_from_headers(self) -> List[str]:
        """
        Detect CDN from HTTP response headers.
        
        Returns:
            List of detected CDN names
        """
        detected = []
        
        try:
            url = f"https://{self.target}" if not self.target.startswith('http') else self.target
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for cdn_name, cdn_headers in self.CDN_HEADERS.items():
                for header in cdn_headers:
                    if header.lower() in headers:
                        detected.append(cdn_name)
                        break
            
        except RequestException:
            pass
        
        return detected
    
    def detect_from_cname(self) -> List[str]:
        """
        Detect CDN from CNAME records.
        
        Returns:
            List of detected CDN names
        """
        detected = []
        
        try:
            answers = dns.resolver.resolve(self.target, 'CNAME')
            
            for answer in answers:
                cname = answer.to_text().rstrip('.').lower()
                
                for cdn_name, patterns in self.CDN_CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in cname:
                            detected.append(cdn_name)
                            break
                            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            self.errors.append(f"CNAME lookup failed: {str(e)}")
        
        return detected
    
    def find_origin_ip(self) -> Set[str]:
        """
        Attempt to find origin IP behind CDN.
        
        Returns:
            Set of potential origin IP addresses
        """
        origin_ips = set()
        
        historical_dns_methods = [
            'https://api.hackertarget.com/hostsearch/?q={domain}',
        ]
        
        for method in historical_dns_methods:
            url = method.format(domain=self.target)
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    lines = response.text.strip().split('\n')
                    
                    for line in lines:
                        if ',' in line:
                            ip = line.split(',')[1].strip()
                            
                            import re
                            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                            if re.match(ip_pattern, ip):
                                if not ip.startswith(('10.', '172.', '192.168.')):
                                    origin_ips.add(ip)
                                    
            except RequestException:
                pass
        
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            
            for answer in answers:
                ip = answer.to_text()
                
                if ip not in origin_ips:
                    origin_ips.add(f"current:{ip}")
                    
        except Exception:
            pass
        
        return origin_ips
    
    def run(self) -> Dict[str, Any]:
        """
        Run CDN detection.
        
        Returns:
            Dictionary with detection results
        """
        header_cdns = self.detect_from_headers()
        cname_cdns = self.detect_from_cname()
        
        all_cdns = list(set(header_cdns + cname_cdns))
        origin_ips = self.find_origin_ip()
        
        findings = []
        
        if all_cdns:
            findings.append({
                'type': 'CDN Detected',
                'severity': 'info',
                'target': self.target,
                'description': f'Content Delivery Network detected: {", ".join(all_cdns)}',
                'evidence': {
                    'cdn_providers': all_cdns,
                    'detection_method': 'headers' if header_cdns else 'cname',
                },
                'remediation': 'CDN protects origin server but may hide other security issues',
            })
            
            if origin_ips:
                findings.append({
                    'type': 'Potential Origin IP Discovered',
                    'severity': 'medium',
                    'target': self.target,
                    'description': f'Found {len(origin_ips)} potential origin IPs behind CDN',
                    'evidence': list(origin_ips)[:10],
                    'remediation': 'Ensure origin server only accepts traffic from CDN IP ranges',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'cdn_detected': all_cdns,
            'has_cdn': len(all_cdns) > 0,
            'origin_ips': list(origin_ips),
        }