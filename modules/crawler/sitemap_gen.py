# modules/crawler/sitemap_gen.py

"""
Sitemap Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates XML sitemaps from crawled URLs and analyzes
existing sitemaps for hidden endpoints and structure.
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException


class SitemapGenerator:
    """
    Sitemap generator and analyzer.
    
    Generates XML sitemaps from discovered URLs and
    analyzes existing sitemaps for hidden content.
    """
    
    COMMON_SITEMAP_PATHS = [
        '/sitemap.xml',
        '/sitemap_index.xml',
        '/sitemap-index.xml',
        '/sitemap.php',
        '/sitemap.txt',
        '/sitemap_index.xml.gz',
        '/sitemap.xml.gz',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the sitemap generator.
        
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
        
        self.discovered_urls: Set[str] = set()
        self.existing_sitemaps: List[str] = []
        self.errors: List[str] = []
    
    def discover_existing_sitemaps(self) -> List[str]:
        """
        Discover existing sitemap files on target.
        
        Returns:
            List of sitemap URLs
        """
        for path in self.COMMON_SITEMAP_PATHS:
            url = f"{self.target}{path}"
            
            try:
                response = self.session.head(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    self.existing_sitemaps.append(url)
                    
            except RequestException:
                continue
        
        robots_url = f"{self.target}/robots.txt"
        
        try:
            response = self.session.get(
                robots_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                sitemap_pattern = r'[Ss]itemap:\s*(.+)'
                matches = re.findall(sitemap_pattern, response.text)
                
                for match in matches:
                    sitemap_url = match.strip()
                    if not sitemap_url.startswith('http'):
                        sitemap_url = urljoin(self.target, sitemap_url)
                    self.existing_sitemaps.append(sitemap_url)
                    
        except RequestException:
            pass
        
        return self.existing_sitemaps
    
    def parse_sitemap(self, sitemap_url: str) -> List[str]:
        """
        Parse an XML sitemap and extract URLs.
        
        Args:
            sitemap_url: Sitemap URL
            
        Returns:
            List of URLs from sitemap
        """
        urls = []
        
        try:
            response = self.session.get(
                sitemap_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                return urls
            
            content = response.text
            
            try:
                root = ET.fromstring(content)
                
                namespace = root.tag.split('}')[0].strip('{') if '}' in root.tag else ''
                
                ns = {'ns': namespace} if namespace else {}
                
                if 'sitemapindex' in root.tag.lower():
                    for sitemap in root.findall('.//ns:sitemap', ns) or root.findall('.//sitemap'):
                        loc = sitemap.find('ns:loc', ns) or sitemap.find('loc')
                        if loc is not None and loc.text:
                            sub_urls = self.parse_sitemap(loc.text.strip())
                            urls.extend(sub_urls)
                
                elif 'urlset' in root.tag.lower():
                    for url in root.findall('.//ns:url', ns) or root.findall('.//url'):
                        loc = url.find('ns:loc', ns) or url.find('loc')
                        if loc is not None and loc.text:
                            urls.append(loc.text.strip())
                
            except ET.ParseError:
                url_pattern = r'<loc>([^<]+)</loc>'
                matches = re.findall(url_pattern, content, re.IGNORECASE)
                urls.extend(matches)
            
        except RequestException as e:
            self.errors.append(f"Sitemap parsing failed: {str(e)}")
        
        return urls
    
    def analyze_sitemap_content(self, urls: List[str]) -> Dict[str, Any]:
        """
        Analyze sitemap URLs for interesting patterns.
        
        Args:
            urls: List of URLs from sitemap
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'total_urls': len(urls),
            'unique_domains': set(),
            'unique_paths': set(),
            'admin_urls': [],
            'api_urls': [],
            'backup_urls': [],
            'sensitive_urls': [],
        }
        
        for url in urls:
            parsed = urlparse(url)
            analysis['unique_domains'].add(parsed.netloc)
            analysis['unique_paths'].add(parsed.path)
            
            url_lower = url.lower()
            
            if any(keyword in url_lower for keyword in ['admin', 'administrator', 'manage', 'dashboard', 'panel']):
                analysis['admin_urls'].append(url)
            
            if any(keyword in url_lower for keyword in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
                analysis['api_urls'].append(url)
            
            if any(keyword in url_lower for keyword in ['backup', '.bak', '.old', '.sql', '.dump', '.zip']):
                analysis['backup_urls'].append(url)
            
            if any(keyword in url_lower for keyword in ['config', 'password', 'secret', '.env', '.git', 'credential']):
                analysis['sensitive_urls'].append(url)
        
        analysis['unique_domains'] = list(analysis['unique_domains'])
        analysis['unique_paths'] = list(analysis['unique_paths'])
        
        return analysis
    
    def generate_sitemap_xml(self, urls: List[str], priority_map: Optional[Dict[str, float]] = None) -> str:
        """
        Generate XML sitemap from URL list.
        
        Args:
            urls: List of URLs
            priority_map: Optional URL to priority mapping
            
        Returns:
            XML sitemap string
        """
        urlset = ET.Element('urlset', xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')
        
        for url in urls:
            url_element = ET.SubElement(urlset, 'url')
            
            loc = ET.SubElement(url_element, 'loc')
            loc.text = url
            
            lastmod = ET.SubElement(url_element, 'lastmod')
            lastmod.text = datetime.now().strftime('%Y-%m-%d')
            
            priority = ET.SubElement(url_element, 'priority')
            if priority_map and url in priority_map:
                priority.text = str(priority_map[url])
            else:
                priority.text = '0.5'
        
        return ET.tostring(urlset, encoding='unicode', xml_declaration=True)
    
    def run(self) -> Dict[str, Any]:
        """
        Run sitemap generation and analysis.
        
        Returns:
            Dictionary with sitemap results
        """
        existing = self.discover_existing_sitemaps()
        
        all_urls = []
        for sitemap_url in existing:
            urls = self.parse_sitemap(sitemap_url)
            all_urls.extend(urls)
        
        self.discovered_urls.update(all_urls)
        
        findings = []
        
        if existing:
            analysis = self.analyze_sitemap_content(all_urls)
            
            if analysis['admin_urls']:
                findings.append({
                    'type': 'Admin URLs in Sitemap',
                    'severity': 'medium',
                    'description': f'Found {len(analysis["admin_urls"])} admin URLs in sitemap',
                    'evidence': analysis['admin_urls'][:10],
                    'remediation': 'Remove sensitive admin URLs from public sitemaps',
                })
            
            if analysis['sensitive_urls']:
                findings.append({
                    'type': 'Sensitive URLs in Sitemap',
                    'severity': 'high',
                    'description': f'Found {len(analysis["sensitive_urls"])} sensitive URLs in sitemap',
                    'evidence': analysis['sensitive_urls'][:10],
                    'remediation': 'Remove sensitive URLs from public sitemaps immediately',
                })
        else:
            findings.append({
                'type': 'No Sitemap Found',
                'severity': 'info',
                'description': 'No sitemap.xml or sitemap reference found',
                'remediation': 'Consider adding a sitemap for SEO purposes',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'sitemaps_found': len(existing),
            'sitemap_urls': existing,
            'total_urls_discovered': len(self.discovered_urls),
            'analysis': self.analyze_sitemap_content(all_urls) if all_urls else {},
        }