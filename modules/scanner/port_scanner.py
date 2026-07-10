# modules/scanner/port_scanner.py

"""
Port Scanner Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Multi-threaded TCP/UDP port scanner with service
identification and banner grabbing capabilities.
"""

import socket
import concurrent.futures
from typing import Dict, List, Any, Optional, Set, Tuple


class PortScanner:
    """
    High-performance port scanner.
    
    Scans target for open ports with configurable
    ranges, multi-threading, and service detection.
    """
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5900, 6379, 8080, 8443,
        1433, 1521, 27017, 11211, 9200, 5432, 25, 465, 587, 2525,
    ]
    
    SERVICE_NAMES = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MSRPC',
        139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
        1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the port scanner.
        
        Args:
            target: Target IP or hostname
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        
        self.timeout = self.config.get('timeout', 2)
        self.threads = self.config.get('threads', 100)
        self.ports = self.config.get('ports', [])
        
        self.open_ports: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def resolve_target(self) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Returns:
            IP address string or None
        """
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, self.target):
            return self.target
        
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as e:
            self.errors.append(f"DNS resolution failed: {str(e)}")
            return None
    
    def scan_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single port.
        
        Args:
            ip: Target IP address
            port: Port number
            
        Returns:
            Dictionary with port info or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = self.SERVICE_NAMES.get(port, 'unknown')
                
                banner = ''
                try:
                    sock.settimeout(1)
                    
                    if port == 80 or port == 8080:
                        sock.send(b'GET / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass
                except Exception:
                    pass
                
                sock.close()
                
                return {
                    'port': port,
                    'service': service,
                    'banner': banner[:200] if banner else '',
                    'state': 'open',
                }
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def scan_ports(self, ports: List[int]) -> List[Dict[str, Any]]:
        """
        Scan multiple ports concurrently.
        
        Args:
            ports: List of port numbers
            
        Returns:
            List of open port dictionaries
        """
        ip = self.resolve_target()
        
        if not ip:
            return []
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                
                if result:
                    open_ports.append(result)
        
        open_ports.sort(key=lambda x: x['port'])
        self.open_ports = open_ports
        
        return open_ports
    
    def scan_common_ports(self) -> List[Dict[str, Any]]:
        """
        Scan common service ports.
        
        Returns:
            List of open port dictionaries
        """
        return self.scan_ports(self.COMMON_PORTS)
    
    def scan_port_range(self, start: int, end: int) -> List[Dict[str, Any]]:
        """
        Scan a range of ports.
        
        Args:
            start: Start port number
            end: End port number
            
        Returns:
            List of open port dictionaries
        """
        ports = list(range(max(1, start), min(end + 1, 65536)))
        return self.scan_ports(ports)
    
    def run(self) -> Dict[str, Any]:
        """
        Run port scan.
        
        Returns:
            Dictionary with scan results
        """
        if self.ports:
            if isinstance(self.ports, str) and '-' in self.ports:
                start, end = self.ports.split('-')
                self.scan_port_range(int(start), int(end))
            elif isinstance(self.ports, list):
                self.scan_ports(self.ports)
            else:
                self.scan_common_ports()
        else:
            self.scan_common_ports()
        
        findings = []
        
        if self.open_ports:
            critical_ports = [p for p in self.open_ports if p['port'] in [21, 23, 135, 139, 445, 3389, 1433, 3306]]
            
            if critical_ports:
                findings.append({
                    'type': 'Critical Ports Open',
                    'severity': 'high',
                    'target': self.target,
                    'description': f'Found {len(critical_ports)} critical ports open',
                    'evidence': critical_ports,
                    'remediation': 'Close unnecessary ports or restrict access with firewall',
                })
            
            findings.append({
                'type': 'Port Scan Results',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(self.open_ports)} open ports',
                'evidence': self.open_ports,
                'remediation': 'Review open ports and services for security',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'open_ports': self.open_ports,
            'total_open': len(self.open_ports),
        }