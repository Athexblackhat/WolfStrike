# modules/crawler/ajax_crawler.py

"""
AJAX and JavaScript Crawler
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Crawls JavaScript-heavy websites and single-page applications
by analyzing JavaScript files for endpoints, API calls,
and hidden functionality.
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException


@dataclass
class JavaScriptFile:
    """Represents a JavaScript file."""
    url: str
    content_hash: str
    size: int
    endpoints_found: List[str]
    api_calls_found: List[str]
    secrets_found: List[str]
    interesting_patterns: List[str]


class AjaxCrawler:
    """
    JavaScript and AJAX endpoint crawler.
    
    Analyzes JavaScript files to discover API endpoints,
    hidden functionality, and potential vulnerabilities
    in single-page applications.
    """
    
    API_PATTERNS = [
        r'(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:url|baseURL|apiUrl|api_url|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:href|src|path|route)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:location|window\.location)\s*[:=.]\s*["\']([^"\']+)["\']',
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/v\d+\/[^"\']+)["\']',
        r'["\'](\/rest\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
        r'["\'](\/ws\/[^"\']+)["\']',
    ]
    
    SECRET_PATTERNS = [
        r'(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:secret|SECRET)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:token|TOKEN)\s*[:=]\s*["\']([^"\']{16,})["\']',
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:bearer|Bearer)\s+["\']?([A-Za-z0-9\-_\.]{20,})["\']?',
        r'["\'](AIza[0-9A-Za-z\-_]{35})["\']',
        r'["\'](sk-[A-Za-z0-9]{32,})["\']',
        r'["\'](ghp_[A-Za-z0-9]{36,})["\']',
        r'["\'](AKIA[0-9A-Z]{16})["\']',
    ]
    
    INTERESTING_PATTERNS = [
        r'(?:eval|Function)\s*\([^)]+\)',
        r'(?:innerHTML|outerHTML)\s*=',
        r'(?:document\.write|document\.writeln)\s*\(',
        r'(?:localStorage|sessionStorage)\.(?:get|set)Item',
        r'(?:debugger|console\.(?:log|warn|error))\s*\(',
        r'(?:postMessage|addEventListener)\s*\(',
        r'\.(?:prototype|__proto__)\s*=',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the AJAX crawler.
        
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
        
        self.script_files: List[JavaScriptFile] = []
        self.discovered_endpoints: Set[str] = set()
        self.discovered_secrets: List[Dict[str, str]] = []
        self.errors: List[str] = []
        
        self.processed_scripts: Set[str] = set()
    
    def extract_scripts_from_page(self, url: str) -> List[str]:
        """
        Extract JavaScript file URLs from a page.
        
        Args:
            url: Page URL
            
        Returns:
            List of JavaScript file URLs
        """
        script_urls = []
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            content_type = response.headers.get('Content-Type', '')
            
            if 'text/html' not in content_type:
                return script_urls
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    absolute_url = urljoin(url, src)
                    script_urls.append(absolute_url)
            
            inline_patterns = [
                r'(?:import|require)\s*\(\s*["\']([^"\']+)["\']\)',
                r'loadScript\s*\(\s*["\']([^"\']+)["\']\)',
                r'\.src\s*=\s*["\']([^"\']+)["\']',
            ]
            
            for script in soup.find_all('script'):
                if script.string:
                    for pattern in inline_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            if match.startswith('http'):
                                script_urls.append(match)
                            elif not match.startswith('//'):
                                absolute_url = urljoin(url, match)
                                script_urls.append(absolute_url)
            
        except RequestException as e:
            self.errors.append(f"Script extraction failed: {str(e)}")
        
        return list(set(script_urls))
    
    def analyze_script(self, script_url: str) -> Optional[JavaScriptFile]:
        """
        Analyze a JavaScript file for endpoints and secrets.
        
        Args:
            script_url: JavaScript file URL
            
        Returns:
            JavaScriptFile object or None
        """
        if script_url in self.processed_scripts:
            return None
        
        self.processed_scripts.add(script_url)
        
        try:
            response = self.session.get(
                script_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                return None
            
            content = response.text
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            endpoints_found = []
            for pattern in self.API_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if not match.startswith('http') and not match.startswith('//'):
                        if match.startswith('/'):
                            match = urljoin(self.target, match)
                        else:
                            continue
                    endpoints_found.append(match)
            
            secrets_found = []
            for pattern in self.SECRET_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 10:
                        secrets_found.append(match)
                        self.discovered_secrets.append({
                            'file': script_url,
                            'secret': match,
                            'pattern': pattern,
                        })
            
            api_calls_found = []
            api_call_patterns = [
                r'(?:axios|fetch|ajax|http)\.(?:get|post|put|delete|patch)\s*\(',
                r'\.request\s*\(',
                r'XMLHttpRequest',
            ]
            for pattern in api_call_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                api_calls_found.extend(matches)
            
            interesting_patterns = []
            for pattern in self.INTERESTING_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                interesting_patterns.extend(matches)
            
            self.discovered_endpoints.update(endpoints_found)
            
            js_file = JavaScriptFile(
                url=script_url,
                content_hash=content_hash,
                size=len(content),
                endpoints_found=list(set(endpoints_found)),
                api_calls_found=list(set(api_calls_found)),
                secrets_found=list(set(secrets_found)),
                interesting_patterns=list(set(interesting_patterns)),
            )
            
            self.script_files.append(js_file)
            return js_file
            
        except RequestException as e:
            self.errors.append(f"Script analysis failed for {script_url}: {str(e)}")
            return None
    
    def analyze_source_maps(self, script_url: str) -> List[str]:
        """
        Extract source map URLs from JavaScript files.
        
        Args:
            script_url: JavaScript file URL
            
        Returns:
            List of source map URLs
        """
        source_maps = []
        
        try:
            response = self.session.get(
                script_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            map_pattern = r'//#\s*sourceMappingURL=(.+\.map)'
            matches = re.findall(map_pattern, response.text)
            
            for match in matches:
                if match.startswith('http'):
                    source_maps.append(match)
                else:
                    source_maps.append(urljoin(script_url, match))
            
        except RequestException:
            pass
        
        return source_maps
    
    def run(self) -> Dict[str, Any]:
        """
        Run the AJAX crawler.
        
        Returns:
            Dictionary with crawl results
        """
        initial_scripts = self.extract_scripts_from_page(self.target)
        
        for script_url in initial_scripts:
            js_file = self.analyze_script(script_url)
            
            if js_file:
                source_maps = self.analyze_source_maps(script_url)
                
                for map_url in source_maps:
                    self.analyze_script(map_url)
        
        findings = []
        
        if self.discovered_secrets:
            findings.append({
                'type': 'Hardcoded Secrets in JavaScript',
                'severity': 'critical',
                'description': f'Found {len(self.discovered_secrets)} potential secrets in JavaScript files',
                'evidence': self.discovered_secrets[:5],
                'remediation': 'Remove secrets from client-side code. Use server-side environment variables.',
            })
        
        if self.discovered_endpoints:
            findings.append({
                'type': 'API Endpoints in JavaScript',
                'severity': 'info',
                'description': f'Found {len(self.discovered_endpoints)} API endpoints in JavaScript files',
                'evidence': list(self.discovered_endpoints)[:20],
                'remediation': 'Review exposed endpoints for security implications',
            })
        
        for js_file in self.script_files:
            if js_file.interesting_patterns:
                findings.append({
                    'type': 'Interesting JavaScript Patterns',
                    'severity': 'low',
                    'endpoint': js_file.url,
                    'description': f'Found {len(js_file.interesting_patterns)} interesting patterns in {js_file.url}',
                    'evidence': js_file.interesting_patterns[:10],
                    'remediation': 'Review JavaScript for potentially dangerous patterns',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'scripts_analyzed': len(self.script_files),
            'endpoints_discovered': len(self.discovered_endpoints),
            'secrets_discovered': len(self.discovered_secrets),
            'total_endpoints': list(self.discovered_endpoints),
        }