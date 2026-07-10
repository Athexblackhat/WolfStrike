# modules/scanner/backup_finder.py

"""
Backup File Finder
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Discovers exposed backup files, configuration backups,
and temporary files that may contain sensitive data.
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


class BackupFinder:
    """
    Backup and temporary file discovery.
    
    Searches for exposed backup files that may
    contain sensitive source code or configuration.
    """
    
    BACKUP_EXTENSIONS = [
        '.bak', '.backup', '.old', '.orig', '.save',
        '.swp', '.swo', '.tmp', '.temp', '.zip',
        '.tar', '.tar.gz', '.tgz', '.gz', '.rar',
        '.7z', '.sql', '.sql.gz', '.dump',
        '~', '.dist', '.copy', '.inc',
    ]
    
    COMMON_FILES_TO_CHECK = [
        'index', 'config', 'database', 'wp-config',
        'settings', '.env', '.htaccess', 'web.config',
        'composer', 'package', 'Gemfile', 'Dockerfile',
        'docker-compose', 'Makefile', 'README',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the backup finder.
        
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
        
        self.discovered_files: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def check_file(self, filename: str, extension: str = '') -> Optional[Dict[str, Any]]:
        """
        Check if a backup file exists.
        
        Args:
            filename: Base filename
            extension: Backup extension
            
        Returns:
            Dictionary with file info or None
        """
        full_filename = f"{filename}{extension}"
        url = urljoin(self.target, full_filename)
        
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                content_length = response.headers.get('Content-Length', '0')
                
                return {
                    'url': url,
                    'filename': full_filename,
                    'status_code': response.status_code,
                    'content_type': content_type,
                    'content_length': int(content_length) if content_length.isdigit() else 0,
                }
            
            return None
            
        except RequestException:
            return None
    
    def run(self) -> Dict[str, Any]:
        """
        Run backup file discovery.
        
        Returns:
            Dictionary with discovery results
        """
        discovered = []
        
        for base_file in self.COMMON_FILES_TO_CHECK:
            for ext in self.BACKUP_EXTENSIONS:
                result = self.check_file(base_file, ext)
                
                if result:
                    discovered.append(result)
                    self.discovered_files.append(result)
        
        findings = []
        
        if discovered:
            sensitive_files = [f for f in discovered if any(
                keyword in f['filename'].lower()
                for keyword in ['config', 'database', '.env', 'wp-config', 'settings', '.htaccess']
            )]
            
            if sensitive_files:
                findings.append({
                    'type': 'Sensitive Backup Files Exposed',
                    'severity': 'critical',
                    'target': self.target,
                    'description': f'Found {len(sensitive_files)} sensitive backup files publicly accessible',
                    'evidence': sensitive_files,
                    'remediation': 'Immediately remove backup files from web root. '
                                   'Store backups outside document root.',
                })
            
            findings.append({
                'type': 'Backup Files Discovered',
                'severity': 'high',
                'target': self.target,
                'description': f'Found {len(discovered)} backup/temporary files',
                'evidence': discovered,
                'remediation': 'Remove unnecessary backup files from public access',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'files': discovered,
            'total_discovered': len(discovered),
        }