# modules/crawler/link_checker.py

"""
Broken Link Checker
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Checks for broken links, redirects, and accessibility
issues across discovered URLs to identify information
disclosure and configuration problems.
"""

import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException


@dataclass
class LinkStatus:
    """Represents a link check result."""
    url: str
    status_code: int
    redirect_url: Optional[str]
    redirect_chain: List[str]
    response_time: float
    is_broken: bool
    is_redirect: bool
    error_message: str


class LinkChecker:
    """
    Broken link and redirect checker.
    
    Checks URLs for broken links, redirect chains,
    and accessibility issues.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the link checker.
        
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
        
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_redirects = self.config.get('max_redirects', 10)
        self.concurrent_checks = self.config.get('concurrent_checks', 10)
        
        self.results: List[LinkStatus] = []
        self.errors: List[str] = []
    
    def check_link(self, url: str, method: str = 'HEAD') -> LinkStatus:
        """
        Check a single link for accessibility.
        
        Args:
            url: URL to check
            method: HTTP method to use
            
        Returns:
            LinkStatus object
        """
        redirect_chain = []
        final_url = url
        status_code = 0
        error_message = ""
        
        try:
            start_time = time.time()
            
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            response_time = time.time() - start_time
            status_code = response.status_code
            
            is_redirect = status_code in [301, 302, 303, 307, 308]
            
            if is_redirect:
                redirect_url = response.headers.get('Location', '')
                redirect_chain.append(url)
                
                chain_count = 0
                while is_redirect and chain_count < self.max_redirects:
                    if not redirect_url.startswith('http'):
                        from urllib.parse import urljoin
                        redirect_url = urljoin(url, redirect_url)
                    
                    redirect_chain.append(redirect_url)
                    
                    response = self.session.request(
                        method,
                        redirect_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False
                    )
                    
                    status_code = response.status_code
                    is_redirect = status_code in [301, 302, 303, 307, 308]
                    
                    if is_redirect:
                        redirect_url = response.headers.get('Location', '')
                    
                    chain_count += 1
                
                final_url = redirect_url
            
            is_broken = status_code >= 400
            
            result = LinkStatus(
                url=url,
                status_code=status_code,
                redirect_url=final_url if is_redirect else None,
                redirect_chain=redirect_chain,
                response_time=response_time,
                is_broken=is_broken,
                is_redirect=len(redirect_chain) > 0,
                error_message="",
            )
            
            self.results.append(result)
            return result
            
        except RequestException as e:
            result = LinkStatus(
                url=url,
                status_code=0,
                redirect_url=None,
                redirect_chain=[],
                response_time=0,
                is_broken=True,
                is_redirect=False,
                error_message=str(e),
            )
            
            self.results.append(result)
            return result
    
    def check_links_parallel(self, urls: List[str]) -> List[LinkStatus]:
        """
        Check multiple links in parallel.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            List of LinkStatus objects
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.concurrent_checks) as executor:
            future_to_url = {
                executor.submit(self.check_link, url): url
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    url = future_to_url[future]
                    self.errors.append(f"Link check failed for {url}: {str(e)}")
        
        return results
    
    def analyze_results(self) -> Dict[str, Any]:
        """
        Analyze link check results.
        
        Returns:
            Dictionary with analysis results
        """
        broken_links = [r for r in self.results if r.is_broken]
        redirects = [r for r in self.results if r.is_redirect]
        long_chains = [r for r in redirects if len(r.redirect_chain) > 3]
        open_redirects = []
        
        for r in redirects:
            if r.redirect_url:
                from urllib.parse import urlparse
                original_domain = urlparse(r.url).netloc
                redirect_domain = urlparse(r.redirect_url).netloc
                
                if original_domain != redirect_domain:
                    open_redirects.append(r)
        
        return {
            'total_checked': len(self.results),
            'broken_count': len(broken_links),
            'redirect_count': len(redirects),
            'long_redirect_chains': len(long_chains),
            'open_redirects': len(open_redirects),
            'broken_links': [
                {'url': r.url, 'status': r.status_code, 'error': r.error_message}
                for r in broken_links
            ],
            'open_redirects': [
                {'url': r.url, 'redirects_to': r.redirect_url}
                for r in open_redirects
            ],
        }
    
    def run(self, urls: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run link checker.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            Dictionary with check results
        """
        if urls is None:
            urls = [self.target]
        
        self.check_links_parallel(urls)
        
        analysis = self.analyze_results()
        
        findings = []
        
        if analysis['open_redirects'] > 0:
            findings.append({
                'type': 'Open Redirects Detected',
                'severity': 'medium',
                'description': f'Found {analysis["open_redirects"]} potential open redirects',
                'evidence': analysis['open_redirects'],
                'remediation': 'Validate redirect URLs against whitelist',
            })
        
        if analysis['long_redirect_chains'] > 0:
            findings.append({
                'type': 'Long Redirect Chains',
                'severity': 'low',
                'description': f'Found {analysis["long_redirect_chains"]} URLs with long redirect chains',
                'remediation': 'Simplify redirect chains to improve performance',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'analysis': analysis,
            'total_checked': len(self.results),
        }