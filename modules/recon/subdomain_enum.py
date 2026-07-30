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
from typing import Dict, List, Any, Optional, Set, Tuple

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
        self.max_wordlist_size = self.config.get('max_wordlist_size', 50000)
        
        self.subdomains: Set[str] = set()
        self.errors: List[str] = []
        self._resolver_cache: Dict[str, Optional[str]] = {}
    
    def _validate_domain(self) -> bool:
        """
        Validate that domain is valid.
        
        Returns:
            True if domain is valid
        """
        if not self.domain:
            self.errors.append("Domain is empty")
            return False
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, self.domain):
            self.errors.append(f"Invalid domain format: {self.domain}")
            return False
        
        return True
    
    def _validate_wordlist(self, wordlist: List[str]) -> bool:
        """
        Validate wordlist before use.
        
        Args:
            wordlist: List of subdomain prefixes
            
        Returns:
            True if wordlist is valid
        """
        if not wordlist:
            return False
        
        if not isinstance(wordlist, list):
            return False
        
        # Remove empty strings and duplicates
        cleaned = [w.strip() for w in wordlist if w and w.strip()]
        if not cleaned:
            return False
        
        return True
    
    def _get_wordlist(self) -> List[str]:
        """
        Get wordlist with proper fallback.
        
        Returns:
            Valid wordlist
        """
        # Try custom wordlist first
        if self.wordlist and self._validate_wordlist(self.wordlist):
            return self.wordlist[:self.max_wordlist_size]
        
        # Use default wordlist
        return self.COMMON_SUBDOMAINS
    
    def _chunk_wordlist(self, wordlist: List[str], chunk_size: int = 1000) -> List[List[str]]:
        """
        Split wordlist into chunks for better performance.
        
        Args:
            wordlist: List of subdomain prefixes
            chunk_size: Size of each chunk
            
        Returns:
            List of wordlist chunks
        """
        if not wordlist:
            return []
        
        return [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]
    
    def _normalize_subdomain(self, name: str) -> Optional[str]:
        """
        Normalize a subdomain string.
        
        Args:
            name: Subdomain name
            
        Returns:
            Normalized subdomain or None
        """
        if not name:
            return None
        
        # Remove wildcard prefix
        name = name.replace('*.', '')
        
        # Clean and lowercase
        name = name.strip().lower()
        
        # Skip if empty
        if not name:
            return None
        
        # Skip if not ending with domain (unless it's the domain itself)
        if not name.endswith('.' + self.domain) and name != self.domain:
            return None
        
        return name
    
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
                        normalized = self._normalize_subdomain(name)
                        if normalized:
                            subdomains.add(normalized)
                            
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
                        normalized = self._normalize_subdomain(hostname)
                        if normalized:
                            subdomains.add(normalized)
                            
        except RequestException as e:
            self.errors.append(f"HackerTarget enumeration failed: {str(e)}")
        
        return subdomains
    
    def _check_subdomain(self, prefix: str) -> Optional[str]:
        """
        Check a single subdomain prefix via DNS resolution.
        
        Args:
            prefix: Subdomain prefix
            
        Returns:
            Subdomain if found, None otherwise
        """
        if not prefix or not prefix.strip():
            return None
        
        subdomain = f"{prefix.strip()}.{self.domain}"
        
        # Check cache first
        if subdomain in self._resolver_cache:
            return self._resolver_cache[subdomain]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        # Try A record
        try:
            answers = resolver.resolve(subdomain, 'A')
            for answer in answers:
                ip = answer.to_text()
                if ip:
                    self._resolver_cache[subdomain] = subdomain
                    return subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception:
            pass
        
        # Try CNAME record
        try:
            answers = resolver.resolve(subdomain, 'CNAME')
            for answer in answers:
                cname = answer.to_text().rstrip('.')
                if cname:
                    self._resolver_cache[subdomain] = subdomain
                    return subdomain
        except Exception:
            pass
        
        self._resolver_cache[subdomain] = None
        return None
    
    def dns_brute_force(self, wordlist: Optional[List[str]] = None) -> Set[str]:
        """
        Brute force subdomains using DNS resolution.
        
        Args:
            wordlist: List of subdomain prefixes
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        # Get wordlist with fallback
        if wordlist is None:
            wordlist = self._get_wordlist()
        
        # Validate wordlist
        if not self._validate_wordlist(wordlist):
            self.errors.append("No valid wordlist entries found for DNS brute force")
            return subdomains
        
        # Limit wordlist size
        if len(wordlist) > self.max_wordlist_size:
            wordlist = wordlist[:self.max_wordlist_size]
            self.errors.append(f"Wordlist truncated to {self.max_wordlist_size} entries")
        
        # Chunk wordlist for better performance
        chunks = self._chunk_wordlist(wordlist, chunk_size=500)
        
        for chunk in chunks:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_prefix = {
                    executor.submit(self._check_subdomain, prefix): prefix
                    for prefix in chunk
                }
                
                for future in concurrent.futures.as_completed(future_to_prefix):
                    try:
                        result = future.result()
                        if result:
                            subdomains.add(result)
                    except Exception as e:
                        # Individual failure should not break the whole scan
                        pass
        
        return subdomains
    
    def enumerate_all(self) -> Set[str]:
        """
        Run all enumeration methods.
        
        Returns:
            Set of all discovered subdomains
        """
        # Validate domain first
        if not self._validate_domain():
            return set()
        
        # Passive enumeration
        crtsh_results = self.passive_enum_crtsh()
        self.subdomains.update(crtsh_results)
        
        hackertarget_results = self.passive_enum_hackertarget()
        self.subdomains.update(hackertarget_results)
        
        # DNS brute force
        brute_results = self.dns_brute_force()
        self.subdomains.update(brute_results)
        
        return self.subdomains
    
    def _resolve_single(self, subdomain: str) -> Tuple[str, List[str]]:
        """
        Resolve a single subdomain to IP addresses.
        
        Args:
            subdomain: Subdomain to resolve
            
        Returns:
            Tuple of (subdomain, list of IPs)
        """
        ips = []
        
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for answer in answers:
                ips.append(answer.to_text())
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception:
            pass
        
        return subdomain, ips
    
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
        
        if not subdomains:
            return {}
        
        resolved = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            futures = {
                executor.submit(self._resolve_single, sub): sub
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
        else:
            findings.append({
                'type': 'No Subdomains Discovered',
                'severity': 'info',
                'domain': self.domain,
                'description': 'No subdomains were discovered during enumeration',
                'remediation': 'Manual review may be required for hidden subdomains',
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
            'wordlist_size': len(self._get_wordlist()),
        }
