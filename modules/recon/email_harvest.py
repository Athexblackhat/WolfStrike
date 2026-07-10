# modules/recon/email_harvest.py

"""
Email Harvester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Harvests email addresses from target domain using
search engines, public sources, and web scraping.
"""

import re
from typing import Dict, List, Any, Optional, Set

import requests
from requests.exceptions import RequestException


class EmailHarvester:
    """
    Email address harvester.
    
    Discovers email addresses associated with target
    domain from public sources and web pages.
    """
    
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    SEARCH_SOURCES = [
        'https://www.google.com/search?q=%40{domain}',
    ]
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the email harvester.
        
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
        
        self.timeout = self.config.get('timeout', 15)
        
        self.emails: Set[str] = set()
        self.errors: List[str] = []
    
    def extract_emails_from_text(self, text: str) -> Set[str]:
        """
        Extract email addresses from text.
        
        Args:
            text: Raw text content
            
        Returns:
            Set of email addresses
        """
        emails = set()
        
        matches = re.findall(self.EMAIL_PATTERN, text, re.IGNORECASE)
        
        for email in matches:
            email_lower = email.lower()
            
            if email_lower.endswith('@' + self.domain):
                emails.add(email_lower)
            
            if email_lower.endswith('.' + self.domain.split('.')[-1]) or \
               self.domain.split('.')[-1] in email_lower.split('@')[1]:
                emails.add(email_lower)
        
        return emails
    
    def harvest_from_website(self, url: str) -> Set[str]:
        """
        Harvest emails from a website.
        
        Args:
            url: Website URL
            
        Returns:
            Set of email addresses
        """
        emails = set()
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                emails.update(self.extract_emails_from_text(response.text))
                
        except RequestException:
            pass
        
        return emails
    
    def harvest_from_search(self) -> Set[str]:
        """
        Harvest emails using search engine results.
        
        Returns:
            Set of email addresses
        """
        emails = set()
        
        for source_template in self.SEARCH_SOURCES:
            url = source_template.format(domain=self.domain)
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    emails.update(self.extract_emails_from_text(response.text))
                    
            except RequestException:
                pass
        
        return emails
    
    def run(self) -> Dict[str, Any]:
        """
        Run email harvesting.
        
        Returns:
            Dictionary with harvesting results
        """
        search_emails = self.harvest_from_search()
        self.emails.update(search_emails)
        
        website_urls = [
            f'https://www.{self.domain}',
            f'https://{self.domain}',
            f'https://{self.domain}/contact',
            f'https://{self.domain}/about',
        ]
        
        for url in website_urls:
            site_emails = self.harvest_from_website(url)
            self.emails.update(site_emails)
        
        findings = []
        
        if self.emails:
            findings.append({
                'type': 'Email Addresses Discovered',
                'severity': 'info',
                'domain': self.domain,
                'description': f'Found {len(self.emails)} email addresses',
                'evidence': sorted(list(self.emails))[:20],
                'remediation': 'Review exposed email addresses for phishing risk. '
                               'Consider using contact forms instead of public emails.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'emails': sorted(list(self.emails)),
            'total_emails': len(self.emails),
        }