# modules/crawler/spider.py

"""
Web Spider Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Advanced web spider for discovering URLs, endpoints,
and mapping website structure with configurable depth
and scope controls.
"""

import re
import time
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urldefrag
from collections import deque

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


@dataclass
class CrawledPage:
    """Represents a crawled page."""
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: str
    links_found: int
    forms_found: int
    scripts_found: int
    depth: int
    parent_url: Optional[str]
    timestamp: float


class WebSpider:
    """
    Advanced web spider for endpoint discovery.
    
    Crawls websites to discover URLs, forms, scripts,
    and build a complete site map with configurable depth.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the web spider.
        
        Args:
            target: Target URL to crawl
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
        self.max_depth = self.config.get('max_depth', 3)
        self.max_pages = self.config.get('max_pages', 500)
        self.delay = self.config.get('delay', 0.1)
        self.stay_in_scope = self.config.get('stay_in_scope', True)
        
        self.target_domain = urlparse(self.target).netloc
        
        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[CrawledPage] = []
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_scripts: Set[str] = set()
        self.errors: List[str] = []
        
        self.url_queue: deque = deque()
        self.url_queue.append((self.target, 0, None))
    
    def should_crawl(self, url: str) -> bool:
        """
        Determine if a URL should be crawled.
        
        Args:
            url: URL to check
            
        Returns:
            True if should crawl
        """
        if url in self.visited_urls:
            return False
        
        if len(self.visited_urls) >= self.max_pages:
            return False
        
        parsed = urlparse(url)
        
        if not parsed.scheme.startswith('http'):
            return False
        
        if self.stay_in_scope:
            if parsed.netloc != self.target_domain:
                if not parsed.netloc.endswith('.' + self.target_domain):
                    return False
        
        blocked_extensions = [
            '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.mp4', '.mp3', '.avi', '.mov', '.wmv',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.exe', '.dmg', '.iso', '.bin',
        ]
        
        path_lower = parsed.path.lower()
        for ext in blocked_extensions:
            if path_lower.endswith(ext):
                return False
        
        blocked_patterns = [
            '/logout', '/signout', '/delete',
            'javascript:', 'mailto:', 'tel:',
        ]
        
        url_lower = url.lower()
        for pattern in blocked_patterns:
            if pattern in url_lower:
                return False
        
        return True
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL by removing fragments and trailing slashes.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL string
        """
        url, _ = urldefrag(url)
        url = url.rstrip('/')
        return url
    
    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all links from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
            
        Returns:
            List of extracted URLs
        """
        links = []
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urljoin(base_url, href)
                absolute_url = self.normalize_url(absolute_url)
                links.append(absolute_url)
        
        for tag in soup.find_all(['img', 'script', 'iframe', 'source']):
            src = tag.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                absolute_url = self.normalize_url(absolute_url)
                links.append(absolute_url)
        
        return links
    
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract all forms from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving form actions
            
        Returns:
            List of form dictionaries
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'page_url': base_url,
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'required': input_tag.get('required') is not None,
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Extract all script sources from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving script URLs
            
        Returns:
            List of script URLs
        """
        scripts = []
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                scripts.append(absolute_url)
            elif script.string:
                content_hash = hashlib.md5(script.string.encode()).hexdigest()
                scripts.append(f"inline:{content_hash}")
        
        return scripts
    
    def crawl_page(self, url: str, depth: int, parent_url: Optional[str]) -> CrawledPage:
        """
        Crawl a single page and extract information.
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            parent_url: Parent URL that linked to this page
            
        Returns:
            CrawledPage object
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            content_type = response.headers.get('Content-Type', '')
            
            if 'text/html' not in content_type:
                return CrawledPage(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                    content_length=len(response.content),
                    title='',
                    links_found=0,
                    forms_found=0,
                    scripts_found=0,
                    depth=depth,
                    parent_url=parent_url,
                    timestamp=time.time(),
                )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title = ''
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text(strip=True)
            
            links = self.extract_links(soup, url)
            forms = self.extract_forms(soup, url)
            scripts = self.extract_scripts(soup, url)
            
            self.discovered_urls.update(links)
            self.discovered_forms.extend(forms)
            self.discovered_scripts.update(scripts)
            
            if depth < self.max_depth:
                for link in links:
                    if self.should_crawl(link):
                        self.url_queue.append((link, depth + 1, url))
            
            page = CrawledPage(
                url=url,
                status_code=response.status_code,
                content_type=content_type,
                content_length=len(response.content),
                title=title,
                links_found=len(links),
                forms_found=len(forms),
                scripts_found=len(scripts),
                depth=depth,
                parent_url=parent_url,
                timestamp=time.time(),
            )
            
            self.crawled_pages.append(page)
            return page
            
        except RequestException as e:
            self.errors.append(f"Crawl failed for {url}: {str(e)}")
            
            return CrawledPage(
                url=url,
                status_code=0,
                content_type='',
                content_length=0,
                title='',
                links_found=0,
                forms_found=0,
                scripts_found=0,
                depth=depth,
                parent_url=parent_url,
                timestamp=time.time(),
            )
    
    def start_crawling(self) -> List[CrawledPage]:
        """
        Start the crawling process.
        
        Returns:
            List of CrawledPage objects
        """
        while self.url_queue:
            if len(self.visited_urls) >= self.max_pages:
                break
            
            url, depth, parent = self.url_queue.popleft()
            
            url = self.normalize_url(url)
            
            if url in self.visited_urls:
                continue
            
            if not self.should_crawl(url):
                continue
            
            self.visited_urls.add(url)
            
            page = self.crawl_page(url, depth, parent)
            
            time.sleep(self.delay)
        
        return self.crawled_pages
    
    def get_site_map(self) -> Dict[str, Any]:
        """
        Generate a site map from crawled pages.
        
        Returns:
            Dictionary with site map data
        """
        site_map = {
            'target': self.target,
            'domain': self.target_domain,
            'total_pages': len(self.crawled_pages),
            'total_urls_discovered': len(self.discovered_urls),
            'total_forms': len(self.discovered_forms),
            'total_scripts': len(self.discovered_scripts),
            'pages': [],
            'forms': self.discovered_forms,
            'scripts': list(self.discovered_scripts),
        }
        
        for page in self.crawled_pages:
            site_map['pages'].append({
                'url': page.url,
                'status': page.status_code,
                'title': page.title,
                'depth': page.depth,
                'links_found': page.links_found,
                'forms_found': page.forms_found,
            })
        
        return site_map
    
    def get_endpoints(self) -> List[Dict[str, Any]]:
        """
        Extract potential API endpoints from crawled URLs.
        
        Returns:
            List of endpoint dictionaries
        """
        endpoints = []
        api_patterns = [
            r'/api/', r'/v\d+/', r'/rest/', r'/graphql',
            r'/json', r'/xml', r'\.json', r'\.xml',
        ]
        
        for url in self.discovered_urls:
            url_lower = url.lower()
            
            for pattern in api_patterns:
                if re.search(pattern, url_lower):
                    endpoints.append({
                        'url': url,
                        'pattern_matched': pattern,
                    })
                    break
        
        return endpoints
    
    def run(self) -> Dict[str, Any]:
        """
        Run the web spider.
        
        Returns:
            Dictionary with crawl results
        """
        self.start_crawling()
        
        site_map = self.get_site_map()
        endpoints = self.get_endpoints()
        
        findings = []
        
        if endpoints:
            findings.append({
                'type': 'API Endpoints Discovered',
                'severity': 'info',
                'description': f'Found {len(endpoints)} potential API endpoints',
                'evidence': endpoints[:10],
                'remediation': 'Review exposed API endpoints for security',
            })
        
        sensitive_files = [url for url in self.discovered_urls if any(
            keyword in url.lower() for keyword in [
                'backup', '.bak', '.old', '.swp', '~',
                '.git', '.env', 'config', 'password',
                'credential', 'secret', '.sql', '.dump',
            ]
        )]
        
        if sensitive_files:
            findings.append({
                'type': 'Sensitive Files Discovered',
                'severity': 'high',
                'description': f'Found {len(sensitive_files)} potentially sensitive files',
                'evidence': sensitive_files[:10],
                'remediation': 'Remove or protect sensitive files from public access',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'site_map': site_map,
            'endpoints': endpoints,
            'pages_crawled': len(self.crawled_pages),
            'urls_discovered': len(self.discovered_urls),
        }