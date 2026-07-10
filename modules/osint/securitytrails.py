# modules/osint/securitytrails.py

"""
SecurityTrails API Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Queries SecurityTrails for DNS history, subdomain
enumeration, and domain intelligence.
"""

import json
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class SecurityTrails:
    """
    SecurityTrails API integration for DNS intelligence.
    
    Queries SecurityTrails for historical DNS data,
    subdomain enumeration, and domain profiling.
    """
    
    BASE_URL = "https://api.securitytrails.com/v1"
    
    def __init__(
        self,
        api_key: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SecurityTrails API client.
        
        Args:
            api_key: SecurityTrails API key
            config: Configuration dictionary
        """
        self.api_key = api_key
        self.config = config or {}
        
        self.errors: List[str] = []
        self.enabled = bool(api_key)
    
    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Make a request to SecurityTrails API.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Response dictionary or None
        """
        if not self.enabled:
            return None
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            request = Request(url)
            request.add_header('APIKEY', self.api_key)
            request.add_header('Accept', 'application/json')
            
            with urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode('utf-8'))
                
        except HTTPError as e:
            if e.code == 401:
                self.errors.append("Invalid SecurityTrails API key")
            elif e.code == 429:
                self.errors.append("SecurityTrails rate limit exceeded")
            else:
                self.errors.append(f"SecurityTrails API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"SecurityTrails API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from SecurityTrails")
            return None
    
    def get_subdomains(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get subdomains for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with subdomain list
        """
        endpoint = f"/domain/{domain}/subdomains"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        subdomains = data.get('subdomains', [])
        
        return {
            'domain': domain,
            'subdomain_count': len(subdomains),
            'subdomains': [f"{sub}.{domain}" for sub in subdomains],
        }
    
    def get_dns_history(self, domain: str, record_type: str = 'a') -> Optional[Dict[str, Any]]:
        """
        Get historical DNS records for a domain.
        
        Args:
            domain: Domain name
            record_type: DNS record type
            
        Returns:
            Dictionary with DNS history
        """
        endpoint = f"/history/{domain}/dns/{record_type}"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        records = data.get('records', [])
        
        return {
            'domain': domain,
            'record_type': record_type,
            'total_records': len(records),
            'records': records[:50],
        }
    
    def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get domain information.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with domain info
        """
        endpoint = f"/domain/{domain}"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        return {
            'domain': data.get('hostname', domain),
            'registrar': data.get('registrar', ''),
            'created_date': data.get('createdDate', ''),
            'expires_date': data.get('expiresDate', ''),
            'name_servers': data.get('currentDns', {}).get('ns', {}).get('values', []),
            'mx_records': data.get('currentDns', {}).get('mx', {}).get('values', []),
            'a_records': data.get('currentDns', {}).get('a', {}).get('values', []),
            'organization': data.get('organization', ''),
        }
    
    def get_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get WHOIS information for domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with WHOIS data
        """
        endpoint = f"/domain/{domain}/whois"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        return data
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run SecurityTrails reconnaissance on target.
        
        Args:
            target: Target domain
            
        Returns:
            Dictionary with reconnaissance results
        """
        findings = []
        
        domain_info = self.get_domain_info(target)
        
        if domain_info:
            findings.append({
                'type': 'Domain Information (SecurityTrails)',
                'severity': 'info',
                'target': target,
                'description': f'Registrar: {domain_info.get("registrar", "Unknown")}',
                'evidence': domain_info,
                'remediation': 'Review domain registration details',
            })
        
        subdomains = self.get_subdomains(target)
        
        if subdomains and subdomains.get('subdomain_count', 0) > 0:
            findings.append({
                'type': 'Subdomains Discovered (SecurityTrails)',
                'severity': 'info',
                'target': target,
                'description': f'Found {subdomains["subdomain_count"]} subdomains',
                'evidence': subdomains['subdomains'][:20],
                'remediation': 'Review subdomains for security vulnerabilities',
            })
        
        dns_history = self.get_dns_history(target, 'a')
        
        if dns_history and dns_history.get('total_records', 0) > 0:
            findings.append({
                'type': 'DNS History (SecurityTrails)',
                'severity': 'info',
                'target': target,
                'description': f'Found {dns_history["total_records"]} historical DNS records',
                'evidence': dns_history['records'][:10],
                'remediation': 'Review historical DNS for potential information leakage',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'api_enabled': self.enabled,
        }