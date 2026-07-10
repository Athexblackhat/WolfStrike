# modules/osint/github_dorks.py

"""
GitHub Dork Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Searches GitHub for exposed secrets, credentials,
API keys, and sensitive information using dorks.
"""

import json
import re
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote


class GitHubDorks:
    """
    GitHub dork scanner for exposed secrets.
    
    Searches GitHub code for accidentally committed
    credentials, API keys, and sensitive files.
    """
    
    GITHUB_API = "https://api.github.com"
    GITHUB_SEARCH = "https://api.github.com/search/code"
    
    DORK_PATTERNS = [
        '"{domain}" password',
        '"{domain}" secret',
        '"{domain}" api_key',
        '"{domain}" token',
        '"{domain}" credentials',
        '"{domain}" private_key',
        '"{domain}" .env',
        '"{domain}" config',
        '"{domain}" database',
        '"{domain}" s3',
        '"{domain}" bucket',
    ]
    
    SENSITIVE_FILES = [
        '.env', '.env.example', 'config.php', 'wp-config.php',
        'settings.py', 'application.properties', 'web.config',
        'credentials.json', 'service-account.json',
        '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519',
    ]
    
    def __init__(
        self,
        github_token: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the GitHub dork scanner.
        
        Args:
            github_token: GitHub personal access token
            config: Configuration dictionary
        """
        self.github_token = github_token
        self.config = config or {}
        
        self.errors: List[str] = []
        self.enabled = True
    
    def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Make a request to GitHub API.
        
        Args:
            url: API endpoint URL
            
        Returns:
            Response dictionary or None
        """
        try:
            request = Request(url)
            request.add_header('Accept', 'application/vnd.github.v3+json')
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            
            if self.github_token:
                request.add_header('Authorization', f'token {self.github_token}')
            
            with urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode('utf-8'))
                
        except HTTPError as e:
            if e.code == 403:
                self.errors.append("GitHub API rate limit exceeded")
            elif e.code == 401:
                self.errors.append("Invalid GitHub token")
            else:
                self.errors.append(f"GitHub API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"GitHub API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from GitHub")
            return None
    
    def search_code(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Search GitHub code for a query.
        
        Args:
            query: Search query string
            
        Returns:
            Dictionary with search results
        """
        url = f"{self.GITHUB_SEARCH}?q={quote(query)}&per_page=30"
        return self._make_request(url)
    
    def search_domain(self, domain: str) -> List[Dict[str, Any]]:
        """
        Search GitHub for domain-related sensitive information.
        
        Args:
            domain: Target domain
            
        Returns:
            List of findings
        """
        findings = []
        
        for dork_pattern in self.DORK_PATTERNS:
            query = dork_pattern.format(domain=domain)
            result = self.search_code(query)
            
            if result and result.get('total_count', 0) > 0:
                items = result.get('items', [])
                
                for item in items[:10]:
                    findings.append({
                        'repository': item.get('repository', {}).get('full_name', ''),
                        'path': item.get('path', ''),
                        'url': item.get('html_url', ''),
                        'query': query,
                    })
        
        return findings
    
    def search_sensitive_files(self, domain: str) -> List[Dict[str, Any]]:
        """
        Search GitHub for sensitive files related to domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of findings
        """
        findings = []
        
        for filename in self.SENSITIVE_FILES:
            query = f'"{domain}" filename:{filename}'
            result = self.search_code(query)
            
            if result and result.get('total_count', 0) > 0:
                items = result.get('items', [])
                
                for item in items[:5]:
                    findings.append({
                        'repository': item.get('repository', {}).get('full_name', ''),
                        'path': item.get('path', ''),
                        'url': item.get('html_url', ''),
                        'filename': filename,
                    })
        
        return findings
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run GitHub dork scan on target.
        
        Args:
            target: Target domain
            
        Returns:
            Dictionary with scan results
        """
        domain = target.replace('https://', '').replace('http://', '').rstrip('/')
        
        dork_findings = self.search_domain(domain)
        sensitive_files = self.search_sensitive_files(domain)
        
        findings = []
        
        if dork_findings:
            findings.append({
                'type': 'GitHub Dork Results',
                'severity': 'high',
                'target': domain,
                'description': f'Found {len(dork_findings)} potential sensitive code references on GitHub',
                'evidence': dork_findings[:10],
                'remediation': 'Remove sensitive information from public repositories. '
                               'Use .gitignore for sensitive files. Rotate exposed credentials.',
            })
        
        if sensitive_files:
            findings.append({
                'type': 'Sensitive Files on GitHub',
                'severity': 'critical',
                'target': domain,
                'description': f'Found {len(sensitive_files)} potential sensitive files on GitHub',
                'evidence': sensitive_files[:10],
                'remediation': 'Immediately remove sensitive files from repositories. '
                               'Check git history and force push cleaned version.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'dork_findings': dork_findings,
            'sensitive_files': sensitive_files,
        }