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
import re
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
        self.api_key = api_key.strip() if api_key else ''
        self.config = config or {}
        
        self.errors: List[str] = []
        self.enabled = bool(self.api_key)
        self.scan_status: str = 'initialized'
        
        # Validate API key format
        if self.enabled:
            self._validate_api_key()
    
    def _validate_api_key(self) -> bool:
        """
        Validate Shodan API key format.
        
        Returns:
            True if API key format is valid
        """
        if not self.api_key:
            self.errors.append("Shodan API key is empty")
            self.enabled = False
            return False
        
        # Shodan API keys are typically 32 characters alphanumeric
        if len(self.api_key) < 20:
            self.errors.append("Shodan API key appears too short")
            self.enabled = False
            return False
        
        return True
    
    def _get_auth_header(self) -> str:
        """
        Get authentication header for Shodan API.
        
        Returns:
            Authorization header string
        """
        return f"Bearer {self.api_key}"
    
    def _build_headers(self) -> Dict[str, str]:
        """
        Build request headers for Shodan API.
        
        Returns:
            Dictionary of headers
        """
        return {
            'Accept': 'application/json',
            'Authorization': self._get_auth_header(),
            'User-Agent': 'WOLFSTRIKE-Shodan/1.0',
        }
    
    def _safe_json_parse(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Safely parse JSON response.
        
        Args:
            data: Raw bytes data
            
        Returns:
            Parsed JSON or None
        """
        try:
            return json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.errors.append("Invalid JSON response from Shodan")
            return None
    
    def _handle_api_error(self, error: HTTPError) -> None:
        """
        Handle Shodan API errors.
        
        Args:
            error: HTTPError from urllib
        """
        if error.code == 401:
            self.errors.append("Invalid Shodan API key - authentication failed")
            self.enabled = False
        elif error.code == 403:
            self.errors.append("Shodan API access forbidden - insufficient permissions")
            self.enabled = False
        elif error.code == 404:
            # Not found is not an error, just no results
            pass
        elif error.code == 429:
            self.errors.append("Shodan API rate limit exceeded - please wait")
        else:
            self.errors.append(f"Shodan API error: {error.code}")
    
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
        
        # Ensure endpoint starts with /
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        
        # Build URL without API key in query string
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            headers = self._build_headers()
            request = Request(url, headers=headers)
            
            with urlopen(request, timeout=15) as response:
                data = response.read()
                parsed_data = self._safe_json_parse(data)
                
                if parsed_data is not None:
                    return parsed_data
                
                return None
                
        except HTTPError as e:
            self._handle_api_error(e)
            return None
        except URLError as e:
            self.errors.append(f"Shodan API connection failed: {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"Shodan API request failed: {str(e)}")
            return None
    
    def _normalize_ip(self, ip: str) -> str:
        """
        Normalize IP address.
        
        Args:
            ip: IP address string
            
        Returns:
            Normalized IP address
        """
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, ip):
            return ip
        return ''
    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain name.
        
        Args:
            domain: Domain string
            
        Returns:
            Normalized domain
        """
        domain = domain.strip().lower()
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove path
        domain = domain.split('/')[0]
        return domain
    
    def host_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a host IP.
        
        Args:
            ip: Target IP address
            
        Returns:
            Dictionary with host information
        """
        normalized_ip = self._normalize_ip(ip)
        if not normalized_ip:
            self.errors.append(f"Invalid IP address: {ip}")
            return None
        
        # API key is now in header, not in URL
        endpoint = f"/shodan/host/{normalized_ip}"
        data = self._make_request(endpoint)
        
        if not data:
            return None
        
        # Extract vulnerability data if present
        vulns = data.get('vulns', {})
        vuln_list = []
        if isinstance(vulns, dict):
            vuln_list = list(vulns.keys())
        elif isinstance(vulns, list):
            vuln_list = vulns
        
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
            'vulnerabilities': vuln_list,
            'services': data.get('data', []),
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
        if not query:
            self.errors.append("Search query is empty")
            return None
        
        # API key is now in header, not in URL
        from urllib.parse import quote
        endpoint = f"/shodan/host/search?query={quote(query)}&limit={limit}"
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
                'country': match.get('location', {}).get('country_name', ''),
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
        if not org:
            self.errors.append("Organization name is empty")
            return None
        
        # Escape quotes in organization name
        org_escaped = org.replace('"', '\\"')
        return self.search(f'org:"{org_escaped}"')
    
    def search_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Search for hosts associated with a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with search results
        """
        normalized_domain = self._normalize_domain(domain)
        if not normalized_domain:
            self.errors.append(f"Invalid domain: {domain}")
            return None
        
        return self.search(f'hostname:{normalized_domain}')
    
    def api_info(self) -> Optional[Dict[str, Any]]:
        """
        Get Shodan API account information.
        
        Returns:
            Dictionary with account info
        """
        # API key is now in header, not in URL
        endpoint = "/api-info"
        data = self._make_request(endpoint)
        
        if data:
            return {
                'plan': data.get('plan', 'Unknown'),
                'credits': data.get('credits', 0),
                'query_credits': data.get('query_credits', 0),
                'scan_credits': data.get('scan_credits', 0),
                'monitored_ips': data.get('monitored_ips', 0),
                'unlocked': data.get('unlocked', 0),
                'unlocked_left': data.get('unlocked_left', 0),
            }
        
        return None
    
    def test_connection(self) -> bool:
        """
        Test Shodan API connection.
        
        Returns:
            True if connection successful
        """
        if not self.enabled:
            return False
        
        result = self.api_info()
        return result is not None
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run Shodan reconnaissance on target.
        
        Args:
            target: Target IP or domain
            
        Returns:
            Dictionary with reconnaissance results
        """
        self.scan_status = 'running'
        self.errors.clear()
        findings = []
        
        # Check if API is enabled
        if not self.enabled:
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': ['Shodan API is not configured or invalid'],
                'api_enabled': False,
                'scan_status': 'failed',
            }
        
        # Check if target is IP or domain
        is_ip = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target)
        
        if is_ip:
            host_data = self.host_info(target)
            
            if host_data:
                findings.append({
                    'type': 'Shodan Host Information',
                    'severity': 'info',
                    'target': target,
                    'description': f"Host: {host_data['organization']}, "
                                   f"OS: {host_data['operating_system']}, "
                                   f"Open ports: {len(host_data['ports'])}",
                    'evidence': {
                        'ip': host_data['ip'],
                        'organization': host_data['organization'],
                        'os': host_data['operating_system'],
                        'ports': host_data['ports'][:20],
                        'hostnames': host_data['hostnames'][:10],
                    },
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
                findings.append({
                    'type': 'Shodan Host Not Found',
                    'severity': 'info',
                    'target': target,
                    'description': 'No Shodan data found for this IP address',
                    'remediation': 'Host may be private or not exposed to internet',
                })
        else:
            # Search by domain
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
            else:
                findings.append({
                    'type': 'Shodan Domain Search',
                    'severity': 'info',
                    'target': target,
                    'description': 'No Shodan data found for this domain',
                    'remediation': 'Domain may not have exposed services',
                })
        
        self.scan_status = 'completed'
        
        return {
            'findings': findings,
            'errors': self.errors,
            'api_enabled': self.enabled,
            'scan_status': self.scan_status,
        }
