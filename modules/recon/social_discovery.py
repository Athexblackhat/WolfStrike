# modules/recon/social_discovery.py

"""
Social Media Discovery
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Discovers social media profiles and accounts
associated with target domain or organization.
"""

from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class SocialDiscovery:
    """
    Social media account discovery.
    
    Finds social media profiles linked to target
    domain for OSINT and brand monitoring.
    """
    
    SOCIAL_PLATFORMS = [
        {
            'name': 'LinkedIn',
            'url_template': 'https://www.linkedin.com/company/{domain}',
            'check_status': True,
        },
        {
            'name': 'Twitter/X',
            'url_template': 'https://twitter.com/{company}',
            'check_status': True,
        },
        {
            'name': 'Facebook',
            'url_template': 'https://www.facebook.com/{company}',
            'check_status': True,
        },
        {
            'name': 'Instagram',
            'url_template': 'https://www.instagram.com/{company}',
            'check_status': True,
        },
        {
            'name': 'GitHub',
            'url_template': 'https://github.com/{company}',
            'check_status': True,
        },
        {
            'name': 'YouTube',
            'url_template': 'https://www.youtube.com/@{company}',
            'check_status': True,
        },
        {
            'name': 'Reddit',
            'url_template': 'https://www.reddit.com/r/{company}',
            'check_status': True,
        },
    ]
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the social discovery module.
        
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
        
        self.company_name = self.domain.split('.')[0]
        
        self.discovered: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def check_profile(self, platform: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Check if a social media profile exists.
        
        Args:
            platform: Platform dictionary with URL template
            
        Returns:
            Dictionary with profile info or None
        """
        url = platform['url_template'].format(
            domain=self.domain,
            company=self.company_name
        )
        
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            if response.status_code in [200, 301, 302]:
                return {
                    'platform': platform['name'],
                    'url': url,
                    'status_code': response.status_code,
                    'exists': True,
                }
            else:
                return {
                    'platform': platform['name'],
                    'url': url,
                    'status_code': response.status_code,
                    'exists': False,
                }
                
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run social media discovery.
        
        Returns:
            Dictionary with discovery results
        """
        for platform in self.SOCIAL_PLATFORMS:
            result = self.check_profile(platform)
            
            if result:
                self.discovered.append(result)
        
        found_profiles = [d for d in self.discovered if d.get('exists')]
        
        findings = []
        
        if found_profiles:
            findings.append({
                'type': 'Social Media Profiles Discovered',
                'severity': 'info',
                'domain': self.domain,
                'description': f'Found {len(found_profiles)} social media profiles',
                'evidence': found_profiles,
                'remediation': 'Review social media presence for brand protection and information leakage',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'profiles': self.discovered,
            'found_count': len(found_profiles),
        }