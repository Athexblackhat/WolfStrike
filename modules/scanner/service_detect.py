# modules/scanner/service_detect.py

"""
Service Version Detector
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects service versions running on open ports through
banner grabbing and protocol-specific probes.
"""

import socket
import re
from typing import Dict, List, Any, Optional


class ServiceDetector:
    """
    Service version detection engine.
    
    Identifies service versions through banner analysis
    and protocol-specific fingerprinting.
    """
    
    VERSION_PATTERNS = {
        'SSH': [
            (r'SSH-([\d.]+)-(\S+)', 'version'),
            (r'OpenSSH[_ ]([\d.p]+)', 'openssh'),
        ],
        'FTP': [
            (r'([\d.]+)\s+vsFTPd', 'vsftpd'),
            (r'ProFTPD\s+([\d.]+)', 'proftpd'),
            (r'FileZilla Server\s+([\d.]+)', 'filezilla'),
        ],
        'HTTP': [
            (r'Server:\s*([^\r\n]+)', 'server'),
            (r'Apache/([\d.]+)', 'apache'),
            (r'nginx/([\d.]+)', 'nginx'),
            (r'Microsoft-IIS/([\d.]+)', 'iis'),
            (r'PHP/([\d.]+)', 'php'),
        ],
        'SMTP': [
            (r'([\d.]+)\s+ESMTP', 'version'),
            (r'Postfix\s*([\d.]+)?', 'postfix'),
            (r'Exim\s+([\d.]+)', 'exim'),
        ],
        'MySQL': [
            (r'([\d.]+)\S*\s+MySQL', 'version'),
            (r'mysql_native_password', 'mysql'),
        ],
        'PostgreSQL': [
            (r'PostgreSQL\s+([\d.]+)', 'version'),
        ],
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the service detector.
        
        Args:
            target: Target IP or hostname
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        
        self.timeout = self.config.get('timeout', 3)
        
        self.services: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Grab service banner from port.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            if port == 80 or port == 8080 or port == 443 or port == 8443:
                request = f'GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n'
                sock.send(request.encode())
            elif port == 25:
                pass
            
            banner = b''
            try:
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    banner += data
                    
                    if len(banner) > 4096:
                        break
            except socket.timeout:
                pass
            
            sock.close()
            
            return banner.decode('utf-8', errors='ignore')
            
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return None
    
    def parse_banner(self, service_type: str, banner: str) -> Dict[str, Any]:
        """
        Parse banner for version information.
        
        Args:
            service_type: Type of service
            banner: Banner text
            
        Returns:
            Dictionary with version info
        """
        info = {
            'service': service_type,
            'version': 'unknown',
            'product': 'unknown',
            'raw_banner': banner[:300],
        }
        
        patterns = self.VERSION_PATTERNS.get(service_type, [])
        
        for pattern, field in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            
            if match:
                if field == 'version':
                    info['version'] = match.group(1)
                else:
                    info['product'] = field
                    if match.lastindex and match.lastindex >= 1:
                        info['version'] = match.group(1)
        
        return info
    
    def detect_service(self, ip: str, port: int, service_name: str) -> Dict[str, Any]:
        """
        Detect service version on a specific port.
        
        Args:
            ip: Target IP address
            port: Port number
            service_name: Expected service name
            
        Returns:
            Dictionary with service details
        """
        banner = self.grab_banner(ip, port)
        
        if banner:
            return self.parse_banner(service_name, banner)
        
        return {
            'service': service_name,
            'version': 'unknown',
            'product': 'unknown',
            'raw_banner': '',
        }
    
    def run(self, open_ports: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Run service detection.
        
        Args:
            open_ports: List of open port dictionaries
            
        Returns:
            Dictionary with detection results
        """
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, self.target):
            ip = self.target
        else:
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.errors.append("DNS resolution failed")
                return {'findings': [], 'errors': self.errors}
        
        if open_ports is None:
            open_ports = []
        
        for port_info in open_ports:
            port = port_info.get('port', 0)
            service_name = port_info.get('service', 'unknown')
            
            service_info = self.detect_service(ip, port, service_name)
            service_info['port'] = port
            
            self.services.append(service_info)
        
        findings = []
        
        outdated_services = []
        for service in self.services:
            version = service.get('version', 'unknown')
            
            if version != 'unknown':
                findings.append({
                    'type': 'Service Version Detected',
                    'severity': 'info',
                    'target': self.target,
                    'description': f"Port {service['port']}: {service['service']} {version} ({service.get('product', 'unknown')})",
                    'evidence': service,
                    'remediation': 'Check for known vulnerabilities in detected versions',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'services': self.services,
            'total_detected': len(self.services),
        }