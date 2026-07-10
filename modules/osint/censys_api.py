# modules/osint/censys_api.py

"""
Censys API Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Queries Censys for SSL certificates, open ports,
services, and host information about target domains.
"""

import json
import base64
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class CensysAPI:
    """
    Censys API integration for passive reconnaissance.
    
    Queries Censys for certificate transparency data,
    host information, and exposed services.
    """
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(
        self,
        api_id: str,
        api_secret: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Censys API client.
        
        Args:
            api_id: Censys API ID
            api_secret: Censys API secret
            config: Configuration dictionary
        """
        self.api_id = api_id
        self.api_secret = api_secret
        self.config = config or {}
        
        self.errors: List[str] = []
        self.enabled = bool(api_id) and bool(api_secret)
        
        credentials = f"{api_id}:{api_secret}"
        self.auth_header = base64.b64encode(credentials.encode()).decode()
    
    def _make_request(self, endpoint: str, method: str = 'GET', body: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """
        Make a request to Censys API.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            body: Request body for POST
            
        Returns:
            Response dictionary or None
        """
        if not self.enabled:
            return None
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            data = json.dumps(body).encode() if body else None
            
            request = Request(url, data=data, method=method)
            request.add_header('Authorization', f'Basic {self.auth_header}')
            request.add_header('Accept', 'application/json')
            
            if body:
                request.add_header('Content-Type', 'application/json')
            
            with urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode('utf-8'))
                
        except HTTPError as e:
            if e.code == 401:
                self.errors.append("Invalid Censys API credentials")
            elif e.code == 403:
                self.errors.append("Censys API access forbidden")
            else:
                self.errors.append(f"Censys API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"Censys API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from Censys")
            return None
    
    def search_hosts(self, query: str, limit: int = 20) -> Optional[Dict[str, Any]]:
        """
        Search Censys for hosts matching query.
        
        Args:
            query: Search query string
            limit: Maximum results
            
        Returns:
            Dictionary with search results
        """
        body = {
            'query': query,
            'per_page': min(limit, 100),
        }
        
        data = self._make_request('/hosts/search', method='POST', body=body)
        
        if not data:
            return None
        
        hits = []
        for hit in data.get('result', {}).get('hits', []):
            hits.append({
                'ip': hit.get('ip', ''),
                'location': hit.get('location', {}),
                'services': [s.get('service_name', '') for s in hit.get('services', [])],
                'operating_system': hit.get('autonomous_system', {}).get('name', ''),
            })
        
        return {
            'total': data.get('result', {}).get('total', 0),
            'hits': hits,
        }
    
    def search_certificates(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Search Censys for SSL certificates for domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with certificate data
        """
        body = {
            'query': f'names: {domain}',
            'per_page': 25,
        }
        
        data = self._make_request('/certificates/search', method='POST', body=body)
        
        if not data:
            return None
        
        certs = []
        for hit in data.get('result', {}).get('hits', []):
            certs.append({
                'fingerprint': hit.get('fingerprint_sha256', ''),
                'subject': hit.get('parsed', {}).get('subject', {}),
                'issuer': hit.get('parsed', {}).get('issuer', {}),
                'valid_from': hit.get('parsed', {}).get('validity_period', {}).get('not_before', ''),
                'valid_to': hit.get('parsed', {}).get('validity_period', {}).get('not_after', ''),
                'names': hit.get('parsed', {}).get('names', []),
            })
        
        return {
            'total': data.get('result', {}).get('total', 0),
            'certificates': certs,
        }
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run Censys reconnaissance on target.
        
        Args:
            target: Target domain or IP
            
        Returns:
            Dictionary with reconnaissance results
        """
        findings = []
        
        import re
        is_ip = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target)
        
        if is_ip:
            host_data = self.search_hosts(target)
            
            if host_data and host_data.get('total', 0) > 0:
                findings.append({
                    'type': 'Censys Host Information',
                    'severity': 'info',
                    'target': target,
                    'description': f'Found host information for {target}',
                    'evidence': host_data['hits'][:5],
                    'remediation': 'Review exposed services',
                })
        else:
            cert_data = self.search_certificates(target)
            
            if cert_data and cert_data.get('total', 0) > 0:
                subdomains = set()
                for cert in cert_data['certificates']:
                    for name in cert.get('names', []):
                        if name.endswith(target):
                            subdomains.add(name)
                
                findings.append({
                    'type': 'Subdomains from Certificate Transparency',
                    'severity': 'info',
                    'target': target,
                    'description': f'Found {len(subdomains)} subdomains via Censys certificates',
                    'evidence': {
                        'certificates_found': cert_data['total'],
                        'subdomains': list(subdomains)[:20],
                    },
                    'remediation': 'Review discovered subdomains for security',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'api_enabled': self.enabled,
        }