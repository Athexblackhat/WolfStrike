# modules/recon/robots_sitemap.py

"""
Robots.txt and Sitemap Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes robots.txt for hidden paths and sitemap.xml
for comprehensive URL discovery.
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


class RobotsSitemap:
    """
    Robots.txt and Sitemap analyzer.
    
    Parses robots.txt for disallowed paths and sitemap.xml
    for comprehensive endpoint discovery.
    """
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the analyzer.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WOLFSTRIKE/1.0)',
        })
        
        self.timeout = self.config.get('timeout', 15)
        
        self.disallowed_paths: List[str] = []
        self.sitemap_urls: List[str] = []
        self.all_urls: Set[str] = set()
        self.errors: List[str] = []
    
    def fetch_robots_txt(self) -> Optional[str]:
        """
        Fetch robots.txt file.
        
        Returns:
            Raw robots.txt content
        """
        url = f"{self.target}/robots.txt"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                return response.text
            
            return None
            
        except RequestException as e:
            self.errors.append(f"Robots.txt fetch failed: {str(e)}")
            return None
    
    def parse_robots_txt(self, content: str) -> None:
        """
        Parse robots.txt content for disallowed paths and sitemaps.
        
        Args:
            content: Raw robots.txt content
        """
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                
                if path and path != '/':
                    self.disallowed_paths.append(path)
            
            sitemap_match = re.match(r'[Ss]itemap:\s*(.+)', line)
            if sitemap_match:
                sitemap_url = sitemap_match.group(1).strip()
                
                if sitemap_url.startswith('http'):
                    self.sitemap_urls.append(sitemap_url)
                else:
                    full_url = urljoin(self.target, sitemap_url)
                    self.sitemap_urls.append(full_url)
    
    def fetch_sitemap(self, sitemap_url: str) -> Optional[str]:
        """
        Fetch sitemap.xml content.
        
        Args:
            sitemap_url: Sitemap URL
            
        Returns:
            Raw sitemap XML content
        """
        try:
            response = self.session.get(sitemap_url, timeout=self.timeout)
            
            if response.status_code == 200:
                return response.text
            
            return None
            
        except RequestException as e:
            self.errors.append(f"Sitemap fetch failed for {sitemap_url}: {str(e)}")
            return None
    
    def parse_sitemap(self, content: str, base_url: str) -> Set[str]:
        """
        Parse sitemap XML for URLs.
        
        Args:
            content: Raw sitemap XML
            base_url: Base URL for sitemap
            
        Returns:
            Set of discovered URLs
        """
        urls = set()
        
        try:
            root = ET.fromstring(content)
            
            namespace = ''
            if '}' in root.tag:
                namespace = root.tag.split('}')[0].strip('{')
            
            ns = {'ns': namespace} if namespace else {}
            
            if 'sitemapindex' in root.tag.lower():
                for sitemap in root.findall('.//ns:sitemap', ns) or root.findall('.//sitemap'):
                    loc = sitemap.find('ns:loc', ns) or sitemap.find('loc')
                    
                    if loc is not None and loc.text:
                        sub_content = self.fetch_sitemap(loc.text.strip())
                        
                        if sub_content:
                            urls.update(self.parse_sitemap(sub_content, loc.text.strip()))
            
            elif 'urlset' in root.tag.lower():
                for url in root.findall('.//ns:url', ns) or root.findall('.//url'):
                    loc = url.find('ns:loc', ns) or url.find('loc')
                    
                    if loc is not None and loc.text:
                        urls.add(loc.text.strip())
            
        except ET.ParseError:
            url_pattern = r'<loc>([^<]+)</loc>'
            matches = re.findall(url_pattern, content, re.IGNORECASE)
            
            for match in matches:
                urls.add(match.strip())
        
        return urls
    
    def check_common_sitemaps(self) -> None:
        """Check common sitemap locations."""
        common_sitemaps = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap-index.xml',
            '/sitemap.php',
            '/sitemap.txt',
        ]
        
        for path in common_sitemaps:
            url = f"{self.target}{path}"
            
            if url not in self.sitemap_urls:
                self.sitemap_urls.append(url)
    
    def run(self) -> Dict[str, Any]:
        """
        Run robots.txt and sitemap analysis.
        
        Returns:
            Dictionary with analysis results
        """
        robots_content = self.fetch_robots_txt()
        
        if robots_content:
            self.parse_robots_txt(robots_content)
        
        self.check_common_sitemaps()
        
        for sitemap_url in self.sitemap_urls[:10]:
            content = self.fetch_sitemap(sitemap_url)
            
            if content:
                urls = self.parse_sitemap(content, sitemap_url)
                self.all_urls.update(urls)
        
        findings = []
        
        if self.disallowed_paths:
            interesting_paths = [
                path for path in self.disallowed_paths
                if any(keyword in path.lower() for keyword in [
                    'admin', 'backup', 'config', 'db', 'dev',
                    'internal', 'private', 'secret', 'staging',
                    'test', 'tmp', 'upload',
                ])
            ]
            
            if interesting_paths:
                findings.append({
                    'type': 'Hidden Paths in robots.txt',
                    'severity': 'medium',
                    'target': self.target,
                    'description': f'Found {len(interesting_paths)} interesting disallowed paths',
                    'evidence': interesting_paths[:20],
                    'remediation': 'Robots.txt may reveal sensitive paths. '
                                   'Use authentication instead of relying on robots.txt for security.',
                })
        
        if self.all_urls:
            findings.append({
                'type': 'Sitemap URLs Discovered',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(self.all_urls)} URLs from sitemaps',
                'evidence': {
                    'total_urls': len(self.all_urls),
                    'sample_urls': list(self.all_urls)[:20],
                },
                'remediation': 'Review sitemap URLs for security implications',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'robots_txt_found': robots_content is not None,
            'disallowed_paths': self.disallowed_paths,
            'sitemaps_found': self.sitemap_urls,
            'total_urls_from_sitemaps': len(self.all_urls),
        }