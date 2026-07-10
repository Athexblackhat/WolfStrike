# modules/scanner/os_fingerprint.py

"""
Operating System Fingerprint Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Passive and active OS fingerprinting using TTL analysis,
TCP window size, and HTTP header patterns.
"""

import re
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class OSFingerprint:
    """
    Operating System fingerprinting engine.
    
    Determines target OS using TTL analysis, HTTP headers,
    and TCP/IP stack characteristics.
    """
    
    OS_TTL_MAP = {
        '64': ['Linux', 'FreeBSD', 'macOS', 'Android'],
        '128': ['Windows'],
        '255': ['Cisco', 'Solaris', 'AIX', 'Network Device'],
    }
    
    OS_HEADER_PATTERNS = {
        'Windows': [
            (r'Microsoft-IIS', 'IIS'),
            (r'ASP\.NET', 'ASP.NET'),
            (r'X-AspNet-Version', 'ASP.NET'),
        ],
        'Linux': [
            (r'Apache', 'Apache'),
            (r'nginx', 'Nginx'),
            (r'Ubuntu', 'Ubuntu'),
            (r'Debian', 'Debian'),
            (r'CentOS', 'CentOS'),
        ],
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the OS fingerprint module.
        
        Args:
            target: Target URL or IP
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        
        self.results: Dict[str, Any] = {}
        self.errors: List[str] = []
    
    def analyze_ttl(self) -> Dict[str, Any]:
        """
        Analyze TTL value for OS detection.
        
        Returns:
            Dictionary with TTL analysis
        """
        import subprocess
        import platform
        
        target_host = self.target
        
        if target_host.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(target_host)
            target_host = parsed.netloc
        
        ttl_value = None
        
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(
                    ['ping', '-n', '1', target_host],
                    capture_output=True, text=True, timeout=5
                )
                
                ttl_match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE)
                
                if ttl_match:
                    ttl_value = ttl_match.group(1)
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', target_host],
                    capture_output=True, text=True, timeout=5
                )
                
                ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                
                if ttl_match:
                    ttl_value = ttl_match.group(1)
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        if ttl_value:
            os_candidates = self.OS_TTL_MAP.get(ttl_value, ['Unknown'])
            
            return {
                'ttl': int(ttl_value),
                'possible_os': os_candidates,
                'confidence': 'medium' if len(os_candidates) == 1 else 'low',
            }
        
        return {'ttl': None, 'possible_os': [], 'confidence': 'none'}
    
    def analyze_http_headers(self) -> Dict[str, Any]:
        """
        Analyze HTTP headers for OS detection.
        
        Returns:
            Dictionary with HTTP header analysis
        """
        url = self.target if self.target.startswith('http') else f'https://{self.target}'
        
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            
            headers = dict(response.headers)
            server_header = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            detected_os = None
            evidence = []
            
            for os_name, patterns in self.OS_HEADER_PATTERNS.items():
                for pattern, detail in patterns:
                    if re.search(pattern, server_header, re.IGNORECASE):
                        detected_os = os_name
                        evidence.append(f'Server header: {detail}')
                        break
                    
                    if re.search(pattern, powered_by, re.IGNORECASE):
                        detected_os = os_name
                        evidence.append(f'X-Powered-By: {detail}')
                        break
            
            return {
                'server_header': server_header,
                'powered_by': powered_by,
                'detected_os': detected_os,
                'evidence': evidence,
                'confidence': 'medium' if evidence else 'none',
            }
            
        except RequestException as e:
            return {'server_header': '', 'powered_by': '', 'detected_os': None, 'evidence': [], 'confidence': 'none'}
    
    def run(self) -> Dict[str, Any]:
        """
        Run OS fingerprinting.
        
        Returns:
            Dictionary with fingerprint results
        """
        ttl_analysis = self.analyze_ttl()
        header_analysis = self.analyze_http_headers()
        
        possible_os_list = []
        
        if ttl_analysis.get('possible_os'):
            possible_os_list.extend(ttl_analysis['possible_os'])
        
        if header_analysis.get('detected_os'):
            possible_os_list.append(header_analysis['detected_os'])
        
        os_counts = {}
        for os_name in possible_os_list:
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        most_likely = max(os_counts, key=os_counts.get) if os_counts else 'Unknown'
        confidence = 'high' if os_counts.get(most_likely, 0) >= 2 else 'medium' if most_likely != 'Unknown' else 'low'
        
        findings = []
        
        if most_likely != 'Unknown':
            findings.append({
                'type': 'Operating System Detected',
                'severity': 'info',
                'target': self.target,
                'description': f'OS detected: {most_likely} (confidence: {confidence})',
                'evidence': {
                    'ttl_analysis': ttl_analysis,
                    'header_analysis': header_analysis,
                },
                'remediation': 'Ensure OS is patched and hardened according to security best practices',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'detected_os': most_likely,
            'confidence': confidence,
            'ttl_analysis': ttl_analysis,
            'header_analysis': header_analysis,
        }