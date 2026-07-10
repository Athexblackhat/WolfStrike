# modules/scanner/api_discovery.py

"""
API Endpoint Discovery
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Discovers API endpoints through common path guessing,
Swagger/OpenAPI parsing, and response analysis.
"""

from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


class APIDiscovery:
    """
    API endpoint discovery engine.
    
    Finds API endpoints through common path enumeration
    and documentation parsing.
    """
    
    COMMON_API_PATHS = [
        '/api/', '/api/v1/', '/api/v2/', '/v1/', '/v2/',
        '/rest/', '/rest/v1/', '/graphql', '/query',
        '/swagger.json', '/openapi.json', '/api-docs',
        '/api/docs', '/swagger-ui.html', '/docs',
        '/redoc', '/api/swagger.json', '/api/openapi.json',
        '/api/spec', '/api/schema', '/api/playground',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the API discovery module.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.discovered_endpoints: List[str] = []
        self.errors: List[str] = []
    
    def check_path(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Check if an API path exists.
        
        Args:
            path: API path to check
            
        Returns:
            Dictionary with path info or None
        """
        url = urljoin(self.target, path)
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            if response.status_code in [200, 301, 302, 401, 403]:
                content_type = response.headers.get('Content-Type', '')
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_type': content_type,
                    'content_length': len(response.content),
                    'is_json': 'application/json' in content_type,
                }
            
            return None
            
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run API endpoint discovery.
        
        Returns:
            Dictionary with discovery results
        """
        api_endpoints = []
        
        for path in self.COMMON_API_PATHS:
            result = self.check_path(path)
            
            if result:
                api_endpoints.append(result)
                self.discovered_endpoints.append(result['url'])
        
        findings = []
        
        if api_endpoints:
            json_endpoints = [ep for ep in api_endpoints if ep['is_json']]
            
            if json_endpoints:
                findings.append({
                    'type': 'API Documentation Discovered',
                    'severity': 'info',
                    'target': self.target,
                    'description': f'Found {len(json_endpoints)} API documentation/spec endpoints',
                    'evidence': json_endpoints,
                    'remediation': 'Restrict access to API documentation in production',
                })
            
            findings.append({
                'type': 'API Endpoints Discovered',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(api_endpoints)} potential API endpoints',
                'evidence': api_endpoints,
                'remediation': 'Review API endpoints for security and access control',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'endpoints': api_endpoints,
            'total_discovered': len(api_endpoints),
        }