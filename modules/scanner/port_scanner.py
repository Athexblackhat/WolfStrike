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
import re
import concurrent.futures
from typing import Dict, List, Any, Optional, Set, Tuple, Union


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
        self.target = target.strip() if target else ''
        self.config = config or {}
        
        self.timeout = self.config.get('timeout', 2)
        self.threads = self.config.get('threads', 100)
        self.ports = self.config.get('ports', [])
        self.max_ports = self.config.get('max_ports', 10000)
        
        self.open_ports: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
        self._resolved_ip: Optional[str] = None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format."""
        if len(hostname) > 253:
            return False
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(hostname_pattern, hostname))
    
    def _validate_target(self) -> Tuple[bool, str]:
        """
        Validate target before scanning.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.target:
            return False, "Target is empty"
        
        # Check if it's an IP
        if self._is_valid_ip(self.target):
            return True, ""
        
        # Check if it's a hostname
        if self._is_valid_hostname(self.target):
            return True, ""
        
        return False, f"Invalid target format: {self.target}"
    
    def _normalize_target(self) -> str:
        """Clean and normalize target string."""
        return self.target.strip()
    
    def _validate_ports(self, ports: List[int]) -> Tuple[bool, str]:
        """
        Validate port list.
        
        Args:
            ports: List of port numbers
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ports:
            return False, "Port list is empty"
        
        if len(ports) > self.max_ports:
            return False, f"Too many ports ({len(ports)} > {self.max_ports})"
        
        for port in ports:
            if not isinstance(port, int):
                return False, f"Invalid port: {port} (must be integer)"
            if port < 1 or port > 65535:
                return False, f"Invalid port: {port} (must be 1-65535)"
        
        return True, ""
    
    def _parse_port_range(self, port_range: str) -> Optional[List[int]]:
        """
        Parse port range string like "1-1000".
        
        Args:
            port_range: Port range string
            
        Returns:
            List of ports or None if invalid
        """
        try:
            if '-' in port_range:
                start_str, end_str = port_range.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                
                if start < 1 or end > 65535 or start > end:
                    return None
                
                return list(range(start, end + 1))
            else:
                # Single port
                port = int(port_range.strip())
                if 1 <= port <= 65535:
                    return [port]
        except (ValueError, TypeError):
            pass
        
        return None
    
    def _get_port_list(self) -> List[int]:
        """
        Get port list from configured ports.
        
        Returns:
            List of ports to scan
        """
        if not self.ports:
            return self.COMMON_PORTS
        
        if isinstance(self.ports, str):
            # Check if it's a range
            ports = self._parse_port_range(self.ports)
            if ports:
                return ports
            # Try comma-separated
            try:
                ports = [int(p.strip()) for p in self.ports.split(',') if p.strip()]
                valid, error = self._validate_ports(ports)
                if valid:
                    return ports
            except ValueError:
                pass
            return self.COMMON_PORTS
        
        if isinstance(self.ports, list):
            valid, error = self._validate_ports(self.ports)
            if valid:
                return self.ports
            self.errors.append(error)
            return self.COMMON_PORTS
        
        return self.COMMON_PORTS
    
    def resolve_target(self) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Returns:
            IP address string or None
        """
        # Check cache
        if self._resolved_ip:
            return self._resolved_ip
        
        # Validate target first
        valid, error = self._validate_target()
        if not valid:
            self.errors.append(error)
            return None
        
        # Check if it's already an IP
        if self._is_valid_ip(self.target):
            self._resolved_ip = self.target
            return self.target
        
        try:
            ip = socket.gethostbyname(self.target)
            self._resolved_ip = ip
            return ip
        except socket.gaierror as e:
            self.errors.append(f"DNS resolution failed for '{self.target}': {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"Unexpected error resolving '{self.target}': {str(e)}")
            return None
    
    def _format_port_result(self, port: int, ip: str, banner: str = '') -> Dict[str, Any]:
        """
        Format port scan result.
        
        Args:
            port: Port number
            ip: Target IP
            banner: Service banner
            
        Returns:
            Formatted result dictionary
        """
        return {
            'port': port,
            'service': self.SERVICE_NAMES.get(port, 'unknown'),
            'banner': banner[:200] if banner else '',
            'state': 'open',
            'ip': ip,
        }
    
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
                banner = ''
                try:
                    sock.settimeout(1)
                    
                    if port == 80 or port == 8080:
                        sock.send(b'GET / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                    elif port == 21:
                        pass  # FTP banner is sent automatically
                    elif port == 22:
                        pass  # SSH banner is sent automatically
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass
                except Exception:
                    pass
                
                sock.close()
                
                return self._format_port_result(port, ip, banner)
            
            sock.close()
            return None
            
        except socket.timeout:
            return None
        except socket.error as e:
            # Connection refused or other socket errors are expected
            return None
        except Exception as e:
            # Log unexpected errors but don't crash
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
            self.scan_status = 'failed'
            return []
        
        if not ports:
            self.scan_status = 'failed'
            self.errors.append("No ports to scan")
            return []
        
        open_ports = []
        scanned_count = 0
        total_ports = len(ports)
        
        # Use thread pool for scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                scanned_count += 1
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                except Exception:
                    # Individual port failures shouldn't stop the scan
                    pass
        
        open_ports.sort(key=lambda x: x['port'])
        self.open_ports = open_ports
        self.scan_status = 'completed' if scanned_count == total_ports else 'partial'
        
        if open_ports:
            self.errors.append(f"Scan completed: {len(open_ports)}/{total_ports} ports open")
        else:
            self.errors.append(f"Scan completed: 0/{total_ports} ports open")
        
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
        if start < 1:
            start = 1
        if end > 65535:
            end = 65535
        if start > end:
            self.errors.append(f"Invalid port range: {start} > {end}")
            return []
        
        ports = list(range(start, min(end + 1, 65536)))
        
        if len(ports) > self.max_ports:
            self.errors.append(f"Port range too large ({len(ports)} ports). Max: {self.max_ports}")
            ports = ports[:self.max_ports]
        
        return self.scan_ports(ports)
    
    def run(self) -> Dict[str, Any]:
        """
        Run port scan.
        
        Returns:
            Dictionary with scan results
        """
        # Validate target first
        valid, error = self._validate_target()
        if not valid:
            self.errors.append(error)
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'target': self.target,
                'open_ports': [],
                'total_open': 0,
                'scan_status': 'failed',
                'error': error,
            }
        
        # Get port list
        port_list = self._get_port_list()
        
        if not port_list:
            self.errors.append("No valid ports to scan")
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'target': self.target,
                'open_ports': [],
                'total_open': 0,
                'scan_status': 'failed',
                'error': 'No valid ports to scan',
            }
        
        # Run scan
        if isinstance(self.ports, str) and '-' in str(self.ports):
            try:
                start_str, end_str = self.ports.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                self.scan_port_range(start, end)
            except ValueError:
                self.errors.append(f"Invalid port range format: {self.ports}")
                self.scan_common_ports()
        else:
            self.scan_ports(port_list)
        
        # Generate findings
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
        else:
            if self.scan_status != 'failed':
                findings.append({
                    'type': 'Port Scan Results',
                    'severity': 'info',
                    'target': self.target,
                    'description': 'No open ports found',
                    'evidence': {'ports_scanned': len(port_list)},
                    'remediation': 'Continue with other reconnaissance',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'open_ports': self.open_ports,
            'total_open': len(self.open_ports),
            'scan_status': self.scan_status,
            'ports_scanned': len(port_list),
            'resolved_ip': self._resolved_ip,
        }
