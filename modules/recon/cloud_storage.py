# modules/recon/cloud_storage.py

"""
Cloud Storage Discovery
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Discovers exposed cloud storage buckets and containers
associated with target domain (AWS S3, GCP, Azure).
"""

from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class CloudStorageFinder:
    """
    Cloud storage bucket discovery.
    
    Checks for publicly accessible cloud storage
    buckets linked to target domain.
    """
    
    BUCKET_PATTERNS = {
        'AWS S3': [
            'https://{domain}.s3.amazonaws.com',
            'https://s3.amazonaws.com/{domain}',
            'https://{domain}-backup.s3.amazonaws.com',
            'https://{domain}-prod.s3.amazonaws.com',
            'https://{domain}-dev.s3.amazonaws.com',
        ],
        'Google Cloud Storage': [
            'https://storage.googleapis.com/{domain}',
            'https://{domain}.storage.googleapis.com',
        ],
        'Azure Blob': [
            'https://{domain}.blob.core.windows.net',
            'https://{domain}.azureedge.net',
        ],
        'DigitalOcean Spaces': [
            'https://{domain}.nyc3.digitaloceanspaces.com',
        ],
    }
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the cloud storage finder.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        
        self.discovered: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def check_bucket(self, cloud: str, url: str) -> Optional[Dict[str, Any]]:
        """
        Check if a cloud storage bucket is accessible.
        
        Args:
            cloud: Cloud provider name
            url: Bucket URL
            
        Returns:
            Dictionary with bucket info or None
        """
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            if response.status_code != 404:
                return {
                    'cloud': cloud,
                    'url': url,
                    'status_code': response.status_code,
                    'accessible': response.status_code in [200, 301, 302, 307],
                    'public': response.status_code == 200,
                }
            
            return None
            
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run cloud storage discovery.
        
        Returns:
            Dictionary with discovery results
        """
        domain_name = self.domain.split('.')[0]
        
        for cloud, patterns in self.BUCKET_PATTERNS.items():
            for pattern in patterns:
                url = pattern.format(domain=domain_name)
                result = self.check_bucket(cloud, url)
                
                if result:
                    self.discovered.append(result)
        
        accessible_buckets = [d for d in self.discovered if d.get('accessible')]
        public_buckets = [d for d in self.discovered if d.get('public')]
        
        findings = []
        
        if public_buckets:
            findings.append({
                'type': 'Public Cloud Storage Buckets',
                'severity': 'critical',
                'domain': self.domain,
                'description': f'Found {len(public_buckets)} publicly accessible storage buckets',
                'evidence': public_buckets,
                'remediation': 'Immediately secure or remove public access to cloud storage buckets',
            })
        elif accessible_buckets:
            findings.append({
                'type': 'Accessible Cloud Storage',
                'severity': 'medium',
                'domain': self.domain,
                'description': f'Found {len(accessible_buckets)} accessible storage endpoints',
                'evidence': accessible_buckets,
                'remediation': 'Review cloud storage access permissions',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'buckets': self.discovered,
            'accessible_count': len(accessible_buckets),
            'public_count': len(public_buckets),
        }