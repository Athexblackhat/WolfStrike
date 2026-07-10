# modules/crawler/wayback_machine.py

"""
Wayback Machine Integration
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Retrieves historical URLs and content from the Wayback Machine
for discovering old endpoints, hidden pages, and information
that may still be accessible.
"""

import json
import re
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException


class WaybackMachine:
    """
    Wayback Machine historical URL retriever.
    
    Queries the Internet Archive's Wayback Machine for
    historical URLs, discovering old endpoints and
    potentially sensitive forgotten pages.
    """
    
    CDX_API_URL = "http://web.archive.org/cdx/search/cdx"
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Wayback Machine retriever.
        
        Args:
            target: Target domain
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 30)
        self.max_results = self.config.get('max_results', 1000)
        
        self.discovered_urls: Set[str] = set()
        self.snapshots: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        
        parsed = urlparse(target)
        self.domain = parsed.netloc if parsed.netloc else parsed.path
    
    def fetch_cdx_data(
        self,
        match_type: str = 'domain',
        filters: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[List[str]]:
        """
        Fetch CDX API data from Wayback Machine.
        
        Args:
            match_type: Match type (domain, host, prefix)
            filters: List of filter strings
            limit: Maximum results
            
        Returns:
            List of CDX data rows
        """
        params = {
            'url': f'*.{self.domain}/*' if match_type == 'domain' else f'{self.target}/*',
            'output': 'json',
            'fl': 'timestamp,original,statuscode,digest,length,mimetype',
            'limit': min(limit, self.max_results),
            'collapse': 'urlkey',
        }
        
        if filters:
            params['filter'] = filters
        
        try:
            response = self.session.get(
                self.CDX_API_URL,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if len(data) > 1:
                    return data[1:]
            
            return []
            
        except (RequestException, json.JSONDecodeError, ValueError) as e:
            self.errors.append(f"CDX API query failed: {str(e)}")
            return []
    
    def fetch_snapshots(self) -> List[Dict[str, Any]]:
        """
        Fetch and parse historical snapshots.
        
        Returns:
            List of snapshot dictionaries
        """
        raw_data = self.fetch_cdx_data()
        snapshots = []
        
        for row in raw_data:
            if len(row) >= 6:
                timestamp = row[0]
                original_url = row[1]
                status_code = row[2]
                digest = row[3]
                length = row[4]
                mimetype = row[5]
                
                snapshot = {
                    'timestamp': timestamp,
                    'url': original_url,
                    'status_code': int(status_code) if status_code.isdigit() else 0,
                    'digest': digest,
                    'length': int(length) if length.isdigit() else 0,
                    'mimetype': mimetype,
                    'wayback_url': f"https://web.archive.org/web/{timestamp}/{original_url}",
                }
                
                snapshots.append(snapshot)
                self.discovered_urls.add(original_url)
        
        self.snapshots = snapshots
        return snapshots
    
    def filter_interesting_snapshots(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Filter snapshots for interesting content.
        
        Returns:
            Dictionary with categorized snapshots
        """
        categorized = {
            'admin_pages': [],
            'backup_files': [],
            'config_files': [],
            'api_endpoints': [],
            'login_pages': [],
            'old_versions': [],
        }
        
        for snapshot in self.snapshots:
            url_lower = snapshot['url'].lower()
            
            if any(keyword in url_lower for keyword in [
                'admin', 'administrator', 'dashboard', 'panel',
                'manage', 'cms', 'backend', 'control',
            ]):
                categorized['admin_pages'].append(snapshot)
            
            if any(keyword in url_lower for keyword in [
                '.bak', '.backup', '.old', '.sql', '.dump',
                '.zip', '.tar', '.gz', '.swp', '~',
            ]):
                categorized['backup_files'].append(snapshot)
            
            if any(keyword in url_lower for keyword in [
                '.env', 'config', 'wp-config', 'settings',
                '.htaccess', '.htpasswd', 'web.config',
            ]):
                categorized['config_files'].append(snapshot)
            
            if any(keyword in url_lower for keyword in [
                '/api/', '/rest/', '/graphql', '/v1/', '/v2/',
                '/json', '/xml', 'endpoint',
            ]):
                categorized['api_endpoints'].append(snapshot)
            
            if any(keyword in url_lower for keyword in [
                'login', 'signin', 'auth', 'authenticate',
                'session', 'oauth',
            ]):
                categorized['login_pages'].append(snapshot)
            
            if snapshot['status_code'] >= 400:
                categorized['old_versions'].append(snapshot)
        
        return categorized
    
    def check_current_accessibility(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Check if historical URLs are still accessible.
        
        Args:
            urls: List of historical URLs
            
        Returns:
            List of accessibility results
        """
        results = []
        
        for url in urls[:50]:
            try:
                response = self.session.head(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                results.append({
                    'url': url,
                    'accessible': response.status_code < 400,
                    'status_code': response.status_code,
                })
                
            except RequestException:
                results.append({
                    'url': url,
                    'accessible': False,
                    'status_code': 0,
                })
        
        return results
    
    def run(self) -> Dict[str, Any]:
        """
        Run Wayback Machine analysis.
        
        Returns:
            Dictionary with analysis results
        """
        snapshots = self.fetch_snapshots()
        categorized = self.filter_interesting_snapshots()
        
        findings = []
        
        if categorized['admin_pages']:
            findings.append({
                'type': 'Historical Admin Pages Discovered',
                'severity': 'medium',
                'description': f'Found {len(categorized["admin_pages"])} historical admin pages',
                'evidence': [s['url'] for s in categorized['admin_pages'][:10]],
                'remediation': 'Ensure old admin pages are not accessible or removed',
            })
        
        if categorized['config_files']:
            findings.append({
                'type': 'Historical Config Files Discovered',
                'severity': 'high',
                'description': f'Found {len(categorized["config_files"])} historical config files',
                'evidence': [s['url'] for s in categorized['config_files'][:10]],
                'remediation': 'Check if sensitive config files were exposed in the past',
            })
        
        if categorized['backup_files']:
            findings.append({
                'type': 'Historical Backup Files Discovered',
                'severity': 'high',
                'description': f'Found {len(categorized["backup_files"])} historical backup files',
                'evidence': [s['url'] for s in categorized['backup_files'][:10]],
                'remediation': 'Ensure backup files are not accessible',
            })
        
        admin_urls = [s['url'] for s in categorized['admin_pages']]
        config_urls = [s['url'] for s in categorized['config_files']]
        accessibility = self.check_current_accessibility(admin_urls + config_urls)
        
        still_accessible = [a for a in accessibility if a['accessible']]
        
        if still_accessible:
            findings.append({
                'type': 'Historical URLs Still Accessible',
                'severity': 'high',
                'description': f'Found {len(still_accessible)} historical URLs still accessible',
                'evidence': still_accessible,
                'remediation': 'Remove or protect historical pages that should not be public',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'total_snapshots': len(snapshots),
            'unique_urls': len(self.discovered_urls),
            'categorized': {
                k: len(v) for k, v in categorized.items()
            },
            'still_accessible': len(still_accessible),
        }