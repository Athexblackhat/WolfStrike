# modules/recon/__init__.py

"""
WOLFSTRIKE Reconnaissance Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Passive and active reconnaissance modules for gathering
target information including subdomains, DNS records,
technologies, and infrastructure details.
"""

from typing import Dict, List, Any, Optional

from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.whois_lookup import WhoisLookup
from modules.recon.dns_enum import DNSEnumerator
from modules.recon.reverse_ip import ReverseIPLookup
from modules.recon.email_harvest import EmailHarvester
from modules.recon.social_discovery import SocialDiscovery
from modules.recon.cloud_storage import CloudStorageFinder
from modules.recon.tech_detect import TechDetector
from modules.recon.waf_detect import WAFDetector
from modules.recon.cdn_detect import CDNDetector
from modules.recon.ssl_analyzer import SSLAnalyzer
from modules.recon.robots_sitemap import RobotsSitemap

__all__ = [
    'SubdomainEnumerator',
    'WhoisLookup',
    'DNSEnumerator',
    'ReverseIPLookup',
    'EmailHarvester',
    'SocialDiscovery',
    'CloudStorageFinder',
    'TechDetector',
    'WAFDetector',
    'CDNDetector',
    'SSLAnalyzer',
    'RobotsSitemap',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all reconnaissance modules.
    
    Args:
        target: Target URL or domain
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    recon_modules = [
        ('subdomain_enum', SubdomainEnumerator),
        ('whois_lookup', WhoisLookup),
        ('dns_enum', DNSEnumerator),
        ('reverse_ip', ReverseIPLookup),
        ('email_harvest', EmailHarvester),
        ('social_discovery', SocialDiscovery),
        ('cloud_storage', CloudStorageFinder),
        ('tech_detect', TechDetector),
        ('waf_detect', WAFDetector),
        ('cdn_detect', CDNDetector),
        ('ssl_analyzer', SSLAnalyzer),
        ('robots_sitemap', RobotsSitemap),
    ]
    
    for name, module_class in recon_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in recon/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }