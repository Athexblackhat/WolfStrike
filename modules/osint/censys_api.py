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
import re
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
        self.api_id = api_id.strip() if api_id else ''
        self.api_secret = api_secret.strip() if api_secret else ''
        self.config = config or {}
        
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self.enabled = bool(self.api_id) and bool(self.api_secret)
        
        # Validate credentials
        if self.enabled:
            self._validate_credentials()
        
        # Build auth header
        if self.enabled:
            self.auth_header = self._build_auth_header()
        else:
            self.auth_header = ''
    
    def _validate_credentials(self) -> bool:
        """
        Validate Censys API credentials.
        
        Returns:
            True if credentials are valid format
        """
        if not self.api_id:
            self.errors.append("Censys API ID is empty")
            self.enabled = False
            return False
        
        if not self.api_secret:
            self.errors.append("Censys API secret is empty")
            self.enabled = False
            return False
        
        # Censys API IDs are typically alphanumeric
        if len(self.api_id) < 8:
            self.errors.append("Censys API ID appears too short")
            self.enabled = False
            return False
        
        if len(self.api_secret) < 10:
            self.errors.append("Censys API secret appears too short")
            self.enabled = False
            return False
        
        return True
    
    def _build_auth_header(self) -> str:
        """
        Build Basic Authentication header.
        
        Returns:
            Basic Auth header string
        """
        credentials = f"{self.api_id}:{self.api_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
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
            self.errors.append("Invalid JSON response from Censys")
            return None
    
    def _handle_api_error(self, error: HTTPError) -> None:
        """
        Handle Censys API errors.
        
        Args:
            error: HTTPError from urllib
        """
        if error.code == 401:
            self.errors.append("Invalid Censys API credentials - authentication failed")
            self.enabled = False
        elif error.code == 403:
            self.errors.append("Censys API access forbidden - insufficient permissions")
            self.enabled = False
        elif error.code == 404:
            # Not found is not an error, just no results
            pass
        elif error.code == 429:
            self.errors.append("Censys API rate limit exceeded - please wait")
        else:
            self.errors.append(f"Censys API error: {error.code}")
    
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
        
        # Ensure endpoint starts with /
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            data = json.dumps(body).encode() if body else None
            
            request = Request(url, data=data, method=method)
            request.add_header('Authorization', self.auth_header)
            request.add_header('Accept', 'application/json')
            request.add_header('User-Agent', 'WOLFSTRIKE-Censys/1.0')
            
            if body:
                request.add_header('Content-Type', 'application/json')
            
            with urlopen(request, timeout=15) as response:
                response_data = response.read()
                parsed_data = self._safe_json_parse(response_data)
                
                if parsed_data is not None:
                    return parsed_data
                
                return None
                
        except HTTPError as e:
            self._handle_api_error(e)
            return None
        except URLError as e:
            self.errors.append(f"Censys API connection failed: {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"Censys API request failed: {str(e)}")
            return None
    
    def _normalize_target(self, target: str) -> str:
        """
        Normalize target string.
        
        Args:
            target: Target domain or IP
            
        Returns:
            Normalized target
        """
        target = target.strip().lower()
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        # Remove path
        target = target.split('/')[0]
        # Remove port
        target = target.split(':')[0]
        return target
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if string is a valid IP address.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IP
        """
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if string is a valid domain name.
        
        Args:
            domain: Domain string
            
        Returns:
            True if valid domain
        """
        if len(domain) > 253:
            return False
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def _extract_subdomains_from_certs(self, certificates: List[Dict[str, Any]], domain: str) -> List[str]:
        """
        Extract subdomains from certificate data.
        
        Args:
            certificates: List of certificate dictionaries
            domain: Base domain
            
        Returns:
            List of unique subdomains
        """
        subdomains = set()
        
        for cert in certificates:
            names = cert.get('names', [])
            for name in names:
                name = name.strip().lower()
                # Remove wildcard prefix
                name = name.replace('*.', '')
                
                if name and name != domain:
                    if name.endswith('.' + domain):
                        subdomains.add(name)
                    elif name == domain:
                        pass
        
        return sorted(list(subdomains))
    
    def search_hosts(self, query: str, limit: int = 20) -> Optional[Dict[str, Any]]:
        """
        Search Censys for hosts matching query.
        
        Args:
            query: Search query string
            limit: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not query:
            self.errors.append("Search query is empty")
            return None
        
        body = {
            'query': query,
            'per_page': min(limit, 100),
        }
        
        data = self._make_request('/hosts/search', method='POST', body=body)
        
        if not data:
            return None
        
        hits = []
        for hit in data.get('result', {}).get('hits', []):
            services = []
            for service in hit.get('services', []):
                service_name = service.get('service_name', '')
                if service_name:
                    services.append(service_name)
            
            hits.append({
                'ip': hit.get('ip', ''),
                'location': {
                    'country': hit.get('location', {}).get('country', ''),
                    'city': hit.get('location', {}).get('city', ''),
                    'continent': hit.get('location', {}).get('continent', ''),
                },
                'services': services,
                'operating_system': hit.get('autonomous_system', {}).get('name', ''),
                'autonomous_system': {
                    'asn': hit.get('autonomous_system', {}).get('asn', ''),
                    'name': hit.get('autonomous_system', {}).get('name', ''),
                },
            })
        
        return {
            'total': data.get('result', {}).get('total', 0),
            'hits': hits,
        }
    
    def search_certificates(self, domain: str, limit: int = 25) -> Optional[Dict[str, Any]]:
        """
        Search Censys for SSL certificates for domain.
        
        Args:
            domain: Domain name
            limit: Maximum results
            
        Returns:
            Dictionary with certificate data
        """
        normalized_domain = self._normalize_target(domain)
        if not normalized_domain:
            self.errors.append(f"Invalid domain: {domain}")
            return None
        
        body = {
            'query': f'names: {normalized_domain}',
            'per_page': min(limit, 100),
        }
        
        data = self._make_request('/certificates/search', method='POST', body=body)
        
        if not data:
            return None
        
        certs = []
        for hit in data.get('result', {}).get('hits', []):
            parsed = hit.get('parsed', {})
            
            certs.append({
                'fingerprint': hit.get('fingerprint_sha256', ''),
                'fingerprint_sha1': hit.get('fingerprint_sha1', ''),
                'subject': parsed.get('subject', {}),
                'issuer': parsed.get('issuer', {}),
                'valid_from': parsed.get('validity_period', {}).get('not_before', ''),
                'valid_to': parsed.get('validity_period', {}).get('not_after', ''),
                'names': parsed.get('names', []),
                'serial_number': parsed.get('serial_number', ''),
                'signature_algorithm': parsed.get('signature_algorithm', {}).get('name', ''),
            })
        
        return {
            'total': data.get('result', {}).get('total', 0),
            'certificates': certs,
        }
    
    def test_connection(self) -> bool:
        """
        Test Censys API connection.
        
        Returns:
            True if connection successful
        """
        if not self.enabled:
            return False
        
        # Try a simple search to test credentials
        result = self.search_hosts('google.com', limit=1)
        return result is not None
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run Censys reconnaissance on target.
        
        Args:
            target: Target domain or IP
            
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
                'errors': ['Censys API is not configured or invalid credentials'],
                'api_enabled': False,
                'scan_status': 'failed',
            }
        
        # Normalize target
        normalized_target = self._normalize_target(target)
        if not normalized_target:
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': [f"Invalid target: {target}"],
                'api_enabled': self.enabled,
                'scan_status': 'failed',
            }
        
        # Check if target is IP or domain
        is_ip = self._is_valid_ip(normalized_target)
        is_domain = self._is_valid_domain(normalized_target)
        
        if not is_ip and not is_domain:
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': [f"Target is neither valid IP nor domain: {target}"],
                'api_enabled': self.enabled,
                'scan_status': 'failed',
            }
        
        if is_ip:
            # Search by IP
            host_data = self.search_hosts(normalized_target)
            
            if host_data and host_data.get('total', 0) > 0:
                findings.append({
                    'type': 'Censys Host Information',
                    'severity': 'info',
                    'target': target,
                    'description': f'Found {host_data["total"]} host entries for {target}',
                    'evidence': {
                        'total_hosts': host_data['total'],
                        'hosts': host_data['hits'][:5],
                    },
                    'remediation': 'Review exposed services on this host',
                })
            else:
                findings.append({
                    'type': 'Censys Host Not Found',
                    'severity': 'info',
                    'target': target,
                    'description': 'No Censys data found for this IP address',
                    'remediation': 'Host may be private or not exposed to internet',
                })
        else:
            # Search by domain - get certificates
            cert_data = self.search_certificates(normalized_target)
            
            if cert_data and cert_data.get('total', 0) > 0:
                subdomains = self._extract_subdomains_from_certs(
                    cert_data['certificates'],
                    normalized_target
                )
                
                findings.append({
                    'type': 'Subdomains from Certificate Transparency (Censys)',
                    'severity': 'info',
                    'target': target,
                    'description': f'Found {len(subdomains)} subdomains via Censys certificates',
                    'evidence': {
                        'certificates_found': cert_data['total'],
                        'subdomains': subdomains[:20],
                        'sample_certificates': cert_data['certificates'][:3],
                    },
                    'remediation': 'Review discovered subdomains for security',
                })
                
                # Check for expired certificates
                expired_certs = []
                for cert in cert_data['certificates']:
                    if cert.get('valid_to'):
                        try:
                            from datetime import datetime
                            valid_to = datetime.strptime(cert['valid_to'], '%Y-%m-%dT%H:%M:%S')
                            if valid_to < datetime.now():
                                expired_certs.append(cert['fingerprint'][:12])
                        except (ValueError, TypeError):
                            pass
                
                if expired_certs:
                    findings.append({
                        'type': 'Expired SSL Certificates (Censys)',
                        'severity': 'medium',
                        'target': target,
                        'description': f'Found {len(expired_certs)} expired certificates',
                        'evidence': expired_certs[:10],
                        'remediation': 'Renew or remove expired SSL certificates',
                    })
            else:
                findings.append({
                    'type': 'No Certificates Found (Censys)',
                    'severity': 'info',
                    'target': target,
                    'description': 'No certificate data found for this domain',
                    'remediation': 'Domain may not have SSL certificates or may not be in Censys database',
                })
        
        self.scan_status = 'completed'
        
        return {
            'findings': findings,
            'errors': self.errors,
            'api_enabled': self.enabled,
            'scan_status': self.scan_status,
        }
