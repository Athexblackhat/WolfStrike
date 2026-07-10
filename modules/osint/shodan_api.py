# modules/osint/shodan_api.py

"""
Shodan API Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Queries Shodan for open ports, services, vulnerabilities,
and other exposed information about target hosts.
"""

import json
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class ShodanAPI:
    """
    Shodan API integration for passive reconnaissance.
    
    Queries Shodan for exposed services, open ports,
    vulnerability information, and host details.
    """
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(
        self,
        api_key: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Shodan API client.
        
        Args:
            api_key: Shodan API key
            config: Configuration dictionary
        """
        self.api_key = api_key
        self.config = config or {}
        
        self.errors: List[str] = []
        self.enabled = bool(api_key)
    
    def _make_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Make a request to Shodan API.
        
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
            request.add_header('Accept', 'application/json')
            
            with urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode('utf-8'))
                
        except HTTPError as e:
            if e.code == 401:
                self.errors.append("Invalid Shodan API key")
            elif e.code == 404:
                return None
            else:
                self.errors.append(f"Shodan API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"Shodan API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from Shodan")
            return None
    
    def host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a host IP.
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary with host information
        """
        endpoint = f"/shodan/host/{ip}?key={self.api_key}"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        return {
            'ip': data.get('ip_str', ip),
            'organization': data.get('org', 'Unknown'),
            'operating_system': data.get('os', 'Unknown'),
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'domains': data.get('domains', []),
            'country': data.get('country_name', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'last_update': data.get('last_update', ''),
            'vulnerabilities': data.get('vulns', []),
            'services': [],
        }
    
    def search(self, query: str, limit: int = 20) -> Optional[Dict[str, Any]]:
        """
        Search Shodan for matching hosts.
        
        Args:
            query: Search query string
            limit: Maximum results
            
        Returns:
            Dictionary with search results
        """
        from urllib.parse import quote
        
        endpoint = f"/shodan/host/search?key={self.api_key}&query={quote(query)}&limit={limit}"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        matches = []
        for match in data.get('matches', []):
            matches.append({
                'ip': match.get('ip_str', ''),
                'port': match.get('port', 0),
                'organization': match.get('org', ''),
                'hostnames': match.get('hostnames', []),
                'domains': match.get('domains', []),
                'transport': match.get('transport', ''),
                'timestamp': match.get('timestamp', ''),
            })
        
        return {
            'total': data.get('total', 0),
            'matches': matches,
        }
    
    def search_organization(self, org: str) -> Optional[Dict[str, Any]]:
        """
        Search for hosts belonging to an organization.
        
        Args:
            org: Organization name
            
        Returns:
            Dictionary with search results
        """
        return self.search(f'org:"{org}"')
    
    def search_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Search for hosts associated with a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with search results
        """
        return self.search(f'hostname:{domain}')
    
    def api_info(self) -> Optional[Dict[str, Any]]:
        """
        Get Shodan API account information.
        
        Returns:
            Dictionary with account info
        """
        endpoint = f"/api-info?key={self.api_key}"
        return self._make_request(endpoint)
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run Shodan reconnaissance on target.
        
        Args:
            target: Target IP or domain
            
        Returns:
            Dictionary with reconnaissance results
        """
        findings = []
        
        import re
        is_ip = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target)
        
        if is_ip:
            host_data = self.host_info(target)
            
            if host_data:
                findings.append({
                    'type': 'Shodan Host Information',
                    'severity': 'info',
                    'target': target,
                    'description': f'Host: {host_data["organization"]}, '
                                   f'OS: {host_data["operating_system"]}, '
                                   f'Open ports: {len(host_data["ports"])}',
                    'evidence': host_data,
                    'remediation': 'Review exposed services and close unnecessary ports',
                })
                
                if host_data.get('vulnerabilities'):
                    findings.append({
                        'type': 'Known Vulnerabilities (Shodan)',
                        'severity': 'high',
                        'target': target,
                        'description': f'Found {len(host_data["vulnerabilities"])} known vulnerabilities',
                        'evidence': host_data['vulnerabilities'][:10],
                        'remediation': 'Patch identified vulnerabilities immediately',
                    })
        else:
            search_data = self.search_domain(target)
            
            if search_data and search_data.get('total', 0) > 0:
                findings.append({
                    'type': 'Shodan Domain Search',
                    'severity': 'info',
                    'target': target,
                    'description': f'Found {search_data["total"]} hosts associated with domain',
                    'evidence': search_data['matches'][:10],
                    'remediation': 'Review all exposed hosts and services',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'api_enabled': self.enabled,
        }