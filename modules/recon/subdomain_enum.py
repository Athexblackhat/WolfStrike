# modules/recon/subdomain_enum.py

"""
Subdomain Enumeration Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Multi-source subdomain enumeration using passive APIs,
DNS brute force, and certificate transparency.
"""

import re
import time
import concurrent.futures
from typing import Dict, List, Any, Optional, Set

import dns.resolver
import requests
from requests.exceptions import RequestException


class SubdomainEnumerator:
    """
    Multi-source subdomain enumeration engine.
    
    Discovers subdomains using passive APIs, DNS brute force,
    certificate transparency logs, and search engines.
    """
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
        'ns1', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
        'm', 'imap', 'test', 'ns', 'blog', 'shop', 'dev', 'staging',
        'admin', 'api', 'cdn', 'mobile', 'secure', 'vpn', 'dns',
        'remote', 'portal', 'apps', 'webdisk', 'web', 'server',
        'mx', 'mx1', 'mx2', 'owa', 'mail2', 'beta', 'demo',
        'sandbox', 'jenkins', 'git', 'gitlab', 'jira', 'confluence',
        'wiki', 'docs', 'support', 'help', 'status', 'monitor',
        'dashboard', 'login', 'signin', 'auth', 'sso', 'ldap',
        'db', 'database', 'mysql', 'sql', 'oracle', 'redis',
        'elastic', 'kibana', 'grafana', 'prometheus', 'nagios',
        'ftp2', 'sftp', 'files', 'storage', 'backup', 'backups',
        'media', 'static', 'assets', 'images', 'img', 'css', 'js',
        'api2', 'api3', 'rest', 'graphql', 'ws', 'socket',
        'chat', 'forum', 'community', 'news', 'press', 'careers',
        'intranet', 'internal', 'corp', 'partner', 'partners',
        'stage', 'uat', 'qa', 'testing', 'development', 'prod',
    ]
    
    PASSIVE_SOURCES = [
        'https://crt.sh/?q=%25.{domain}&output=json',
        'https://api.hackertarget.com/hostsearch/?q={domain}',
    ]
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the subdomain enumerator.
        
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
        self.threads = self.config.get('threads', 50)
        self.wordlist = self.config.get('wordlist', [])
        
        self.subdomains: Set[str] = set()
        self.errors: List[str] = []
    
    def passive_enum_crtsh(self) -> Set[str]:
        """
        Enumerate subdomains using crt.sh certificate transparency.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            url = f'https://crt.sh/?q=%25.{self.domain}&output=json'
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        name = name.replace('*.', '')
                        
                        if name.endswith('.' + self.domain) or name == self.domain:
                            subdomains.add(name)
                            
        except (RequestException, ValueError) as e:
            self.errors.append(f"crt.sh enumeration failed: {str(e)}")
        
        return subdomains
    
    def passive_enum_hackertarget(self) -> Set[str]:
        """
        Enumerate subdomains using HackerTarget API.
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            url = f'https://api.hackertarget.com/hostsearch/?q={self.domain}'
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                
                for line in lines:
                    if ',' in line:
                        hostname = line.split(',')[0].strip().lower()
                        
                        if hostname.endswith('.' + self.domain) or hostname == self.domain:
                            subdomains.add(hostname)
                            
        except RequestException as e:
            self.errors.append(f"HackerTarget enumeration failed: {str(e)}")
        
        return subdomains
    
    def dns_brute_force(self, wordlist: Optional[List[str]] = None) -> Set[str]:
        """
        Brute force subdomains using DNS resolution.
        
        Args:
            wordlist: List of subdomain prefixes
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        if wordlist is None:
            wordlist = self.wordlist if self.wordlist else self.COMMON_SUBDOMAINS
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        def check_subdomain(prefix: str) -> Optional[str]:
            subdomain = f"{prefix}.{self.domain}"
            
            try:
                answers = resolver.resolve(subdomain, 'A')
                
                for answer in answers:
                    ip = answer.to_text()
                    if ip:
                        return subdomain
                        
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                pass
            except Exception:
                pass
            
            try:
                answers = resolver.resolve(subdomain, 'CNAME')
                
                for answer in answers:
                    cname = answer.to_text().rstrip('.')
                    if cname:
                        return subdomain
                        
            except Exception:
                pass
            
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_prefix = {
                executor.submit(check_subdomain, prefix): prefix
                for prefix in wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_prefix):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        return subdomains
    
    def enumerate_all(self) -> Set[str]:
        """
        Run all enumeration methods.
        
        Returns:
            Set of all discovered subdomains
        """
        crtsh_results = self.passive_enum_crtsh()
        self.subdomains.update(crtsh_results)
        
        hackertarget_results = self.passive_enum_hackertarget()
        self.subdomains.update(hackertarget_results)
        
        brute_results = self.dns_brute_force()
        self.subdomains.update(brute_results)
        
        return self.subdomains
    
    def resolve_subdomains(self, subdomains: Optional[Set[str]] = None) -> Dict[str, List[str]]:
        """
        Resolve subdomains to IP addresses.
        
        Args:
            subdomains: Set of subdomains (uses discovered if None)
            
        Returns:
            Dictionary mapping subdomains to IP lists
        """
        if subdomains is None:
            subdomains = self.subdomains
        
        resolved = {}
        
        def resolve_single(subdomain: str) -> tuple:
            ips = []
            
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                
                for answer in answers:
                    ips.append(answer.to_text())
                    
            except Exception:
                pass
            
            return subdomain, ips
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(resolve_single, sub): sub
                for sub in subdomains
            }
            
            for future in concurrent.futures.as_completed(futures):
                subdomain, ips = future.result()
                
                if ips:
                    resolved[subdomain] = ips
        
        return resolved
    
    def run(self) -> Dict[str, Any]:
        """
        Run subdomain enumeration.
        
        Returns:
            Dictionary with enumeration results
        """
        all_subdomains = self.enumerate_all()
        resolved = self.resolve_subdomains()
        
        findings = []
        
        if all_subdomains:
            findings.append({
                'type': 'Subdomains Discovered',
                'severity': 'info',
                'domain': self.domain,
                'description': f'Discovered {len(all_subdomains)} subdomains',
                'evidence': {
                    'total': len(all_subdomains),
                    'subdomains': sorted(list(all_subdomains))[:50],
                },
                'remediation': 'Review subdomains for security, remove unnecessary DNS records',
            })
        
        sensitive_subdomains = [
            sub for sub in all_subdomains
            if any(keyword in sub.lower() for keyword in [
                'admin', 'dev', 'staging', 'test', 'internal',
                'db', 'database', 'backup', 'jenkins', 'gitlab',
                'vpn', 'remote', 'sandbox', 'uat',
            ])
        ]
        
        if sensitive_subdomains:
            findings.append({
                'type': 'Sensitive Subdomains Exposed',
                'severity': 'medium',
                'domain': self.domain,
                'description': f'Found {len(sensitive_subdomains)} potentially sensitive subdomains',
                'evidence': sensitive_subdomains[:20],
                'remediation': 'Restrict access to sensitive subdomains, implement authentication',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'subdomains': sorted(list(all_subdomains)),
            'resolved': resolved,
            'total_discovered': len(all_subdomains),
            'total_resolved': len(resolved),
        }