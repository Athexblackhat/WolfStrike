# modules/recon/tech_detect.py

"""
Technology Stack Detector
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects technologies used by target website including
web servers, frameworks, CMS, and JavaScript libraries.
"""

import re
from typing import Dict, List, Any, Optional, Set, Tuple

import requests
from requests.exceptions import RequestException


class TechDetector:
    """
    Technology stack detection engine.
    
    Identifies web technologies by analyzing HTTP headers,
    HTML content, cookies, and JavaScript files.
    """
    
    TECHNOLOGY_SIGNATURES = {
        'web_servers': {
            'Apache': {'headers': {'Server': r'Apache'}},
            'Nginx': {'headers': {'Server': r'nginx'}},
            'IIS': {'headers': {'Server': r'Microsoft-IIS'}},
            'LiteSpeed': {'headers': {'Server': r'LiteSpeed'}},
            'Caddy': {'headers': {'Server': r'Caddy'}},
            'Tomcat': {'headers': {'Server': r'Apache-Coyote'}},
        },
        'programming_languages': {
            'PHP': {'headers': {'X-Powered-By': r'PHP'}},
            'Python': {'headers': {'X-Powered-By': r'Python'}, 'cookies': ['sessionid']},
            'Ruby': {'headers': {'X-Powered-By': r'Ruby'}},
            'Node.js': {'headers': {'X-Powered-By': r'Express'}},
            'Java': {'cookies': ['JSESSIONID']},
            'ASP.NET': {'headers': {'X-Powered-By': r'ASP\.NET'}, 'html': ['__VIEWSTATE']},
            'Go': {'headers': {'X-Powered-By': r'Go'}},
        },
        'frameworks': {
            'Django': {'cookies': ['csrftoken', 'sessionid']},
            'Laravel': {'cookies': ['laravel_session']},
            'Rails': {'cookies': ['_session_id']},
            'Spring': {'cookies': ['JSESSIONID']},
            'Express': {'headers': {'X-Powered-By': r'Express'}},
            'React': {'html': ['react-root', 'data-reactroot']},
            'Angular': {'html': ['ng-app', 'ng-version']},
            'Vue.js': {'html': ['v-app', 'data-v-']},
            'Next.js': {'html': ['__NEXT_DATA__']},
        },
        'cms': {
            'WordPress': {'paths': ['/wp-content/', '/wp-admin/', '/wp-includes/'], 'meta': {'generator': r'WordPress'}},
            'Drupal': {'paths': ['/sites/default/', '/sites/all/'], 'headers': {'X-Generator': r'Drupal'}},
            'Joomla': {'paths': ['/components/com_', '/templates/']},
            'Magento': {'paths': ['/skin/frontend/'], 'cookies': ['frontend']},
            'Shopify': {'headers': {'X-Shopify-Stage': r'.+'}},
        },
        'javascript_libraries': {
            'jQuery': {'scripts': [r'jquery[.-]([\d.]+)(?:\.min)?\.js']},
            'Bootstrap': {'scripts': [r'bootstrap[.-]([\d.]+)(?:\.min)?\.js']},
            'Font Awesome': {'scripts': [r'font-?awesome']},
            'Google Analytics': {'scripts': [r'google-analytics\.com/analytics\.js', r'googletagmanager\.com/gtag/js']},
        },
        'cdn_hosting': {
            'Cloudflare': {'headers': {'cf-ray': r'.+', 'CF-Cache-Status': r'.+'}},
            'Akamai': {'headers': {'X-Akamai-Transformed': r'.+'}},
            'Amazon CloudFront': {'headers': {'X-Amz-Cf-Id': r'.+'}},
            'Fastly': {'headers': {'X-Served-By': r'.+', 'X-Cache': r'.+'}},
        },
        'databases': {
            'MySQL': {'html': [r'mysql_fetch_array', r'mysql_connect']},
            'PostgreSQL': {'html': [r'pg_query', r'pg_connect']},
            'MongoDB': {'html': [r'MongoError', r'ObjectId']},
        },
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the technology detector.
        
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
        
        self.timeout = self.config.get('timeout', 15)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.detected_tech: Dict[str, Set[str]] = {}
        self.errors: List[str] = []
    
    def fetch_page(self) -> Tuple[Optional[Dict[str, str]], Optional[str], Optional[Dict[str, str]]]:
        """
        Fetch target page for analysis.
        
        Returns:
            Tuple of (headers, html, cookies)
        """
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            headers = dict(response.headers)
            html = response.text
            
            cookies = {}
            for cookie in response.cookies:
                cookies[cookie.name] = cookie.value
            
            return headers, html, cookies
            
        except RequestException as e:
            self.errors.append(f"Page fetch failed: {str(e)}")
            return None, None, None
    
    def detect_technology(
        self,
        category: str,
        tech_name: str,
        signatures: Dict[str, Any],
        headers: Dict[str, str],
        html: str,
        cookies: Dict[str, str]
    ) -> bool:
        """
        Detect a specific technology.
        
        Args:
            category: Technology category
            tech_name: Technology name
            signatures: Detection signatures
            headers: HTTP response headers
            html: HTML content
            cookies: Response cookies
            
        Returns:
            True if technology detected
        """
        if 'headers' in signatures:
            for header_name, pattern in signatures['headers'].items():
                header_value = headers.get(header_name, '')
                
                if header_name.lower() in [k.lower() for k in headers]:
                    actual_value = ''
                    for k, v in headers.items():
                        if k.lower() == header_name.lower():
                            actual_value = v
                            break
                    
                    if re.search(pattern, actual_value, re.IGNORECASE):
                        return True
        
        if 'html' in signatures and html:
            for pattern in signatures['html']:
                if re.search(pattern, html, re.IGNORECASE):
                    return True
        
        if 'cookies' in signatures:
            for cookie_name in signatures['cookies']:
                if cookie_name.lower() in [c.lower() for c in cookies]:
                    return True
        
        if 'scripts' in signatures and html:
            for pattern in signatures['scripts']:
                script_pattern = r'<script[^>]*src=["\']([^"\']*' + pattern + r'[^"\']*)["\']'
                if re.search(script_pattern, html, re.IGNORECASE):
                    return True
        
        if 'meta' in signatures and html:
            for meta_name, pattern in signatures['meta'].items():
                meta_pattern = r'<meta[^>]*name=["\']' + meta_name + r'["\'][^>]*content=["\']([^"\']*' + pattern + r'[^"\']*)["\']'
                if re.search(meta_pattern, html, re.IGNORECASE):
                    return True
        
        if 'paths' in signatures:
            for path in signatures['paths']:
                try:
                    check_url = self.target.rstrip('/') + path
                    resp = self.session.head(check_url, timeout=5, verify=self.verify_ssl)
                    
                    if resp.status_code in [200, 301, 302, 403]:
                        return True
                except RequestException:
                    pass
        
        return False
    
    def run(self) -> Dict[str, Any]:
        """
        Run technology detection.
        
        Returns:
            Dictionary with detection results
        """
        headers, html, cookies = self.fetch_page()
        
        if not html:
            return {
                'findings': [],
                'errors': self.errors,
                'technologies': {},
            }
        
        detected = {}
        
        for category, technologies in self.TECHNOLOGY_SIGNATURES.items():
            detected[category] = []
            
            for tech_name, signatures in technologies.items():
                if self.detect_technology(category, tech_name, signatures, headers, html, cookies):
                    detected[category].append(tech_name)
        
        total_technologies = sum(len(v) for v in detected.values())
        
        findings = []
        
        if total_technologies > 0:
            tech_summary = {}
            for category, techs in detected.items():
                if techs:
                    tech_summary[category] = techs
            
            findings.append({
                'type': 'Technology Stack Detected',
                'severity': 'info',
                'target': self.target,
                'description': f'Detected {total_technologies} technologies',
                'evidence': tech_summary,
                'remediation': 'Review technology stack for outdated or vulnerable components',
            })
            
            if 'cms' in detected and detected['cms']:
                findings.append({
                    'type': 'CMS Detected',
                    'severity': 'info',
                    'target': self.target,
                    'description': f'CMS: {", ".join(detected["cms"])}',
                    'remediation': 'Keep CMS and plugins updated to latest versions',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'technologies': detected,
            'total_detected': total_technologies,
        }