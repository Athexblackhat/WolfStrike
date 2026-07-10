# modules/scanner/js_analyzer.py

"""
JavaScript Security Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes JavaScript files for sensitive information,
endpoints, and potential vulnerabilities.
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


class JSAnalyzer:
    """
    JavaScript security analyzer.
    
    Extracts and analyzes JavaScript for secrets,
    endpoints, and dangerous patterns.
    """
    
    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["\']([^"\']{10,})["\']', 'API Key'),
        (r'(?:secret|SECRET)\s*[:=]\s*["\']([^"\']{10,})["\']', 'Secret'),
        (r'(?:token|TOKEN)\s*[:=]\s*["\']([^"\']{16,})["\']', 'Token'),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', 'Password'),
        (r'(?:bearer|Bearer)\s+["\']?([A-Za-z0-9\-_\.]{20,})["\']?', 'Bearer Token'),
        (r'["\'](AIza[0-9A-Za-z\-_]{35})["\']', 'Google API Key'),
        (r'["\'](ghp_[A-Za-z0-9]{36,})["\']', 'GitHub Token'),
        (r'["\'](AKIA[0-9A-Z]{16})["\']', 'AWS Access Key'),
    ]
    
    ENDPOINT_PATTERNS = [
        r'(?:url|baseURL|apiUrl|api_url|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/v\d+\/[^"\']+)["\']',
        r'["\'](\/rest\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
    ]
    
    DANGEROUS_PATTERNS = [
        (r'eval\s*\(', 'eval() usage'),
        (r'innerHTML\s*=', 'innerHTML assignment'),
        (r'document\.write\s*\(', 'document.write()'),
        (r'localStorage\.(?:get|set)Item', 'localStorage usage'),
        (r'postMessage\s*\(', 'postMessage usage'),
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the JS analyzer.
        
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
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.findings_list: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def extract_script_urls(self) -> List[str]:
        """
        Extract JavaScript file URLs from page.
        
        Returns:
            List of script URLs
        """
        script_urls = []
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for script in soup.find_all('script'):
                src = script.get('src')
                
                if src:
                    absolute_url = urljoin(self.target, src)
                    script_urls.append(absolute_url)
            
        except RequestException as e:
            self.errors.append(f"Script extraction failed: {str(e)}")
        
        return script_urls
    
    def analyze_script(self, script_url: str) -> Dict[str, Any]:
        """
        Analyze a JavaScript file.
        
        Args:
            script_url: JavaScript file URL
            
        Returns:
            Dictionary with analysis results
        """
        try:
            response = self.session.get(
                script_url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                return {}
            
            content = response.text
            
            secrets_found = []
            for pattern, secret_type in self.SECRET_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    if len(match) > 8:
                        secrets_found.append({
                            'type': secret_type,
                            'value_preview': match[:20] + '...' if len(match) > 20 else match,
                            'pattern': pattern,
                        })
            
            endpoints_found = []
            for pattern in self.ENDPOINT_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                endpoints_found.extend(matches)
            
            dangerous_found = []
            for pattern, description in self.DANGEROUS_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                
                if matches:
                    dangerous_found.append({
                        'pattern': description,
                        'occurrences': len(matches),
                    })
            
            return {
                'url': script_url,
                'size': len(content),
                'secrets': secrets_found,
                'endpoints': list(set(endpoints_found)),
                'dangerous_patterns': dangerous_found,
            }
            
        except RequestException:
            return {}
    
    def run(self) -> Dict[str, Any]:
        """
        Run JavaScript analysis.
        
        Returns:
            Dictionary with analysis results
        """
        script_urls = self.extract_script_urls()
        
        all_secrets = []
        all_endpoints = set()
        all_dangerous = []
        
        for script_url in script_urls[:20]:
            analysis = self.analyze_script(script_url)
            
            if analysis:
                if analysis.get('secrets'):
                    all_secrets.append({
                        'script': script_url,
                        'secrets': analysis['secrets'],
                    })
                
                if analysis.get('endpoints'):
                    all_endpoints.update(analysis['endpoints'])
                
                if analysis.get('dangerous_patterns'):
                    all_dangerous.append({
                        'script': script_url,
                        'patterns': analysis['dangerous_patterns'],
                    })
        
        findings = []
        
        if all_secrets:
            findings.append({
                'type': 'Secrets in JavaScript',
                'severity': 'critical',
                'target': self.target,
                'description': f'Found {len(all_secrets)} scripts containing potential secrets',
                'evidence': all_secrets[:5],
                'remediation': 'Remove secrets from client-side JavaScript. Use environment variables.',
            })
        
        if all_endpoints:
            findings.append({
                'type': 'API Endpoints in JavaScript',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(all_endpoints)} endpoints in JavaScript',
                'evidence': list(all_endpoints)[:20],
                'remediation': 'Review exposed endpoints for security',
            })
        
        if all_dangerous:
            findings.append({
                'type': 'Dangerous JavaScript Patterns',
                'severity': 'low',
                'target': self.target,
                'description': f'Found dangerous patterns in {len(all_dangerous)} scripts',
                'evidence': all_dangerous[:5],
                'remediation': 'Review and refactor dangerous JavaScript patterns',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'scripts_analyzed': len(script_urls),
            'secrets_found': len(all_secrets),
            'endpoints_found': len(all_endpoints),
        }