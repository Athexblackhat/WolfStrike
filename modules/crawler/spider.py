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
from requests.exceptions import RequestException, Timeout, ConnectionError
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
    
    BLOCKED_EXTENSIONS = [
        '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
        '.mp4', '.mp3', '.avi', '.mov', '.wmv',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.exe', '.dmg', '.iso', '.bin',
    ]
    
    BLOCKED_PATTERNS = [
        '/logout', '/signout', '/delete',
        'javascript:', 'mailto:', 'tel:',
        'data:', 'blob:',
    ]
    
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
        self.target = target.rstrip('/') if target else ''
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
        self.respect_robots = self.config.get('respect_robots', True)
        
        self.target_domain = urlparse(self.target).netloc if self.target else ''
        
        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[CrawledPage] = []
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_scripts: Set[str] = set()
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self._robots_disallowed: Set[str] = set()
        
        self.url_queue: deque = deque()
        if self.target:
            self.url_queue.append((self.target, 0, None))
    
    def _is_valid_url(self, url: Optional[str]) -> bool:
        """
        Check if URL is valid for crawling.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is valid
        """
        if not url:
            return False
        
        if not isinstance(url, str):
            return False
        
        url = url.strip()
        if not url:
            return False
        
        # Check for valid scheme
        parsed = urlparse(url)
        if not parsed.scheme:
            return False
        
        if parsed.scheme not in ['http', 'https']:
            return False
        
        return True
    
    def _normalize_url_safe(self, url: str) -> str:
        """
        Safely normalize a URL.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL string
        """
        if not url:
            return ''
        
        try:
            url, _ = urldefrag(url)
            url = url.rstrip('/')
            return url
        except Exception:
            return url
    
    def _clean_url(self, url: str) -> str:
        """
        Clean URL by removing unwanted characters.
        
        Args:
            url: URL to clean
            
        Returns:
            Cleaned URL
        """
        if not url:
            return ''
        
        # Remove leading/trailing whitespace
        url = url.strip()
        
        # Remove newlines and tabs
        url = url.replace('\n', '').replace('\r', '').replace('\t', '')
        
        return url
    
    def _validate_target(self) -> Tuple[bool, str]:
        """
        Validate target before crawling.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.target:
            return False, "Target is empty"
        
        if not self._is_valid_url(self.target):
            return False, f"Invalid target URL: {self.target}"
        
        return True, ""
    
    def _is_blocked_extension(self, url: str) -> bool:
        """
        Check if URL has blocked extension.
        
        Args:
            url: URL to check
            
        Returns:
            True if blocked
        """
        if not url:
            return False
        
        path = urlparse(url).path.lower()
        
        for ext in self.BLOCKED_EXTENSIONS:
            if path.endswith(ext):
                return True
        
        return False
    
    def _is_blocked_pattern(self, url: str) -> bool:
        """
        Check if URL matches blocked pattern.
        
        Args:
            url: URL to check
            
        Returns:
            True if blocked
        """
        if not url:
            return False
        
        url_lower = url.lower()
        
        for pattern in self.BLOCKED_PATTERNS:
            if pattern in url_lower:
                return True
        
        return False
    
    def _should_crawl(self, url: str) -> bool:
        """
        Determine if a URL should be crawled.
        
        Args:
            url: URL to check
            
        Returns:
            True if should crawl
        """
        if not self._is_valid_url(url):
            return False
        
        normalized_url = self._normalize_url_safe(url)
        if not normalized_url:
            return False
        
        if normalized_url in self.visited_urls:
            return False
        
        if len(self.visited_urls) >= self.max_pages:
            return False
        
        parsed = urlparse(normalized_url)
        
        if not parsed.scheme.startswith('http'):
            return False
        
        if self.stay_in_scope:
            if parsed.netloc != self.target_domain:
                if not parsed.netloc.endswith('.' + self.target_domain):
                    return False
        
        # Check robots.txt
        if self.respect_robots and self._is_disallowed_by_robots(normalized_url):
            return False
        
        # Check blocked extensions
        if self._is_blocked_extension(normalized_url):
            return False
        
        # Check blocked patterns
        if self._is_blocked_pattern(normalized_url):
            return False
        
        return True
    
    def should_crawl(self, url: str) -> bool:
        """
        Determine if a URL should be crawled (legacy method).
        
        Args:
            url: URL to check
            
        Returns:
            True if should crawl
        """
        return self._should_crawl(url)
    
    def _get_robots_txt(self) -> Optional[str]:
        """
        Fetch robots.txt from target.
        
        Returns:
            Robots.txt content or None
        """
        if not self.target:
            return None
        
        try:
            parsed = urlparse(self.target)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            response = self.session.get(
                robots_url,
                timeout=5,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                return response.text
            
            return None
            
        except Exception:
            return None
    
    def _parse_robots_txt(self, content: str) -> Set[str]:
        """
        Parse robots.txt for disallowed paths.
        
        Args:
            content: Robots.txt content
            
        Returns:
            Set of disallowed paths
        """
        disallowed = set()
        
        if not content:
            return disallowed
        
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    disallowed.add(path)
        
        return disallowed
    
    def _is_disallowed_by_robots(self, url: str) -> bool:
        """
        Check if URL is disallowed by robots.txt.
        
        Args:
            url: URL to check
            
        Returns:
            True if disallowed
        """
        if not self._robots_disallowed:
            robots_content = self._get_robots_txt()
            if robots_content:
                self._robots_disallowed = self._parse_robots_txt(robots_content)
        
        if not self._robots_disallowed:
            return False
        
        path = urlparse(url).path
        
        for disallowed_path in self._robots_disallowed:
            if path.startswith(disallowed_path):
                return True
        
        return False
    
    def _safe_extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Safely extract links from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
            
        Returns:
            List of extracted URLs
        """
        links = []
        
        try:
            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href')
                if href:
                    href = self._clean_url(href)
                    if self._is_valid_url(href) or href.startswith('/'):
                        absolute_url = urljoin(base_url, href)
                        absolute_url = self._normalize_url_safe(absolute_url)
                        if absolute_url:
                            links.append(absolute_url)
            
            for tag in soup.find_all(['img', 'script', 'iframe', 'source']):
                src = tag.get('src')
                if src:
                    src = self._clean_url(src)
                    if self._is_valid_url(src) or src.startswith('/'):
                        absolute_url = urljoin(base_url, src)
                        absolute_url = self._normalize_url_safe(absolute_url)
                        if absolute_url:
                            links.append(absolute_url)
        except Exception as e:
            self.errors.append(f"Link extraction failed: {str(e)}")
        
        return links
    
    def _safe_extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """
        Safely extract forms from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving form actions
            
        Returns:
            List of form dictionaries
        """
        forms = []
        
        try:
            for form in soup.find_all('form'):
                action = form.get('action', '')
                action = self._clean_url(action) if action else ''
                
                form_data = {
                    'action': urljoin(base_url, action) if action else base_url,
                    'method': form.get('method', 'get').upper(),
                    'inputs': [],
                    'page_url': base_url,
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', '') or '',
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                        'required': input_tag.get('required') is not None,
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
        except Exception as e:
            self.errors.append(f"Form extraction failed: {str(e)}")
        
        return forms
    
    def _safe_extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """
        Safely extract scripts from HTML content.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving script URLs
            
        Returns:
            List of script URLs
        """
        scripts = []
        
        try:
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    src = self._clean_url(src)
                    absolute_url = urljoin(base_url, src)
                    absolute_url = self._normalize_url_safe(absolute_url)
                    if absolute_url:
                        scripts.append(absolute_url)
                elif script.string:
                    content_hash = hashlib.md5(script.string.encode()).hexdigest()
                    scripts.append(f"inline:{content_hash}")
        except Exception as e:
            self.errors.append(f"Script extraction failed: {str(e)}")
        
        return scripts
    
    def _safe_crawl_page(self, url: str, depth: int, parent_url: Optional[str]) -> Optional[CrawledPage]:
        """
        Safely crawl a single page.
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            parent_url: Parent URL that linked to this page
            
        Returns:
            CrawledPage object or None
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            content_type = response.headers.get('Content-Type', '')
            
            # Handle non-HTML content
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
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title = ''
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text(strip=True)
            
            links = self._safe_extract_links(soup, url)
            forms = self._safe_extract_forms(soup, url)
            scripts = self._safe_extract_scripts(soup, url)
            
            self.discovered_urls.update(links)
            self.discovered_forms.extend(forms)
            self.discovered_scripts.update(scripts)
            
            # Add new URLs to queue
            if depth < self.max_depth:
                for link in links:
                    if self._should_crawl(link):
                        self.url_queue.append((link, depth + 1, url))
            
            return CrawledPage(
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
            
        except (Timeout, ConnectionError) as e:
            self.errors.append(f"Timeout/Connection error for {url}: {str(e)}")
            return None
        except RequestException as e:
            self.errors.append(f"Crawl failed for {url}: {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"Unexpected error crawling {url}: {str(e)}")
            return None
    
    def crawl_page(self, url: str, depth: int, parent_url: Optional[str]) -> CrawledPage:
        """
        Crawl a single page and extract information (legacy method).
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
            parent_url: Parent URL that linked to this page
            
        Returns:
            CrawledPage object
        """
        result = self._safe_crawl_page(url, depth, parent_url)
        if result is None:
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
        return result
    
    def start_crawling(self) -> List[CrawledPage]:
        """
        Start the crawling process.
        
        Returns:
            List of CrawledPage objects
        """
        self.scan_status = 'running'
        
        while self.url_queue:
            if len(self.visited_urls) >= self.max_pages:
                break
            
            try:
                url, depth, parent = self.url_queue.popleft()
            except IndexError:
                break
            
            if not url:
                continue
            
            url = self._normalize_url_safe(url)
            
            if not url:
                continue
            
            if url in self.visited_urls:
                continue
            
            if not self._should_crawl(url):
                continue
            
            self.visited_urls.add(url)
            
            page = self._safe_crawl_page(url, depth, parent)
            
            if page:
                self.crawled_pages.append(page)
            
            time.sleep(self.delay)
        
        self.scan_status = 'completed'
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
            if not url:
                continue
            
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
        # Reset state
        self.visited_urls.clear()
        self.crawled_pages.clear()
        self.discovered_urls.clear()
        self.discovered_forms.clear()
        self.discovered_scripts.clear()
        self.errors.clear()
        self.scan_status = 'initialized'
        
        # Validate target
        valid, error = self._validate_target()
        if not valid:
            self.errors.append(error)
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'site_map': {},
                'endpoints': [],
                'pages_crawled': 0,
                'urls_discovered': 0,
                'scan_status': 'failed',
                'error': error,
            }
        
        # Initialize queue
        self.url_queue = deque()
        self.url_queue.append((self.target, 0, None))
        
        # Start crawling
        self.start_crawling()
        
        # Get results
        site_map = self.get_site_map()
        endpoints = self.get_endpoints()
        
        findings = []
        
        if endpoints:
            findings.append({
                'type': 'API Endpoints Discovered',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(endpoints)} potential API endpoints',
                'evidence': endpoints[:10],
                'remediation': 'Review exposed API endpoints for security',
            })
        
        sensitive_files = []
        for url in self.discovered_urls:
            if not url:
                continue
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in [
                'backup', '.bak', '.old', '.swp', '~',
                '.git', '.env', 'config', 'password',
                'credential', 'secret', '.sql', '.dump',
            ]):
                sensitive_files.append(url)
        
        if sensitive_files:
            findings.append({
                'type': 'Sensitive Files Discovered',
                'severity': 'high',
                'target': self.target,
                'description': f'Found {len(sensitive_files)} potentially sensitive files',
                'evidence': sensitive_files[:10],
                'remediation': 'Remove or protect sensitive files from public access',
            })
        
        if not self.crawled_pages:
            findings.append({
                'type': 'No Pages Crawled',
                'severity': 'info',
                'target': self.target,
                'description': 'No pages were crawled. Check target availability.',
                'remediation': 'Verify target is accessible and try again',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'site_map': site_map,
            'endpoints': endpoints,
            'pages_crawled': len(self.crawled_pages),
            'urls_discovered': len(self.discovered_urls),
            'scan_status': self.scan_status,
            'sensitive_files_found': len(sensitive_files),
        }
