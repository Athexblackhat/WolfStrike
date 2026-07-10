# modules/network/zone_transfer.py

"""
DNS Zone Transfer Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests for DNS zone transfer vulnerabilities
that could expose internal network information.
"""

from typing import Dict, List, Any, Optional
import dns.resolver
import dns.query
import dns.zone
import dns.name


class ZoneTransfer:
    """
    DNS zone transfer vulnerability tester.
    
    Attempts zone transfers from discovered name servers
    and analyzes exposed DNS records.
    """
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the zone transfer tester.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        self.resolver = dns.resolver.Resolver()
        
        self.name_servers: List[str] = []
        self.zone_data: Dict[str, List[str]] = {}
        self.errors: List[str] = []
    
    def get_name_servers(self) -> List[str]:
        """
        Get authoritative name servers for domain.
        
        Returns:
            List of name server hostnames
        """
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            
            for answer in answers:
                ns_name = answer.to_text().rstrip('.')
                self.name_servers.append(ns_name)
            
            return self.name_servers
            
        except dns.resolver.NoAnswer:
            self.errors.append('No NS records found')
            return []
        except Exception as e:
            self.errors.append(f"Name server lookup failed: {str(e)}")
            return []
    
    def attempt_zone_transfer(self, name_server: str) -> Optional[Dict[str, List[str]]]:
        """
        Attempt zone transfer from a name server.
        
        Args:
            name_server: Name server hostname
            
        Returns:
            Dictionary with zone data or None
        """
        try:
            ns_ip = None
            
            try:
                ip_answers = self.resolver.resolve(name_server, 'A')
                for answer in ip_answers:
                    ns_ip = answer.to_text()
                    break
            except Exception:
                import socket
                try:
                    ns_ip = socket.gethostbyname(name_server)
                except socket.gaierror:
                    pass
            
            if not ns_ip:
                return None
            
            domain_name = dns.name.from_text(self.domain)
            
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, self.domain, timeout=10)
            )
            
            records: Dict[str, List[str]] = {}
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    record_type = dns.rdatatype.to_text(rdataset.rdtype)
                    
                    if record_type not in records:
                        records[record_type] = []
                    
                    for rdata in rdataset:
                        records[record_type].append(f"{name}.{self.domain}. {rdataset.ttl} {record_type} {rdata}")
            
            return records
            
        except dns.query.TransferError:
            return None
        except dns.exception.Timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            self.errors.append(f"Zone transfer failed for {name_server}: {str(e)}")
            return None
    
    def analyze_zone_data(self, zone_data: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        Analyze transferred zone data for sensitive information.
        
        Args:
            zone_data: Zone transfer data
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'total_records': sum(len(v) for v in zone_data.values()),
            'record_types': list(zone_data.keys()),
            'sensitive_records': [],
            'internal_hosts': [],
            'all_hosts': [],
        }
        
        for record_type, records in zone_data.items():
            for record in records:
                if record_type == 'A':
                    parts = record.split()
                    if len(parts) >= 5:
                        hostname = parts[0]
                        ip = parts[4]
                        
                        analysis['all_hosts'].append({'hostname': hostname, 'ip': ip, 'type': 'A'})
                        
                        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')):
                            analysis['internal_hosts'].append({'hostname': hostname, 'ip': ip})
                
                if any(keyword in record.lower() for keyword in [
                    'admin', 'internal', 'vpn', 'db', 'database',
                    'backup', 'test', 'dev', 'staging', 'secret',
                    'password', 'credential', 'api',
                ]):
                    analysis['sensitive_records'].append(record)
        
        return analysis
    
    def run(self) -> Dict[str, Any]:
        """
        Run zone transfer tests.
        
        Returns:
            Dictionary with test results
        """
        name_servers = self.get_name_servers()
        
        all_zone_data = {}
        successful_transfers = []
        
        for ns in name_servers:
            zone_data = self.attempt_zone_transfer(ns)
            
            if zone_data:
                all_zone_data[ns] = zone_data
                successful_transfers.append(ns)
        
        findings = []
        
        if successful_transfers:
            for ns in successful_transfers:
                analysis = self.analyze_zone_data(all_zone_data[ns])
                
                findings.append({
                    'type': 'Zone Transfer Allowed',
                    'severity': 'high',
                    'domain': self.domain,
                    'name_server': ns,
                    'description': f'Zone transfer successful from {ns}. '
                                   f'Exposed {analysis["total_records"]} records.',
                    'evidence': {
                        'internal_hosts': analysis['internal_hosts'][:10],
                        'sensitive_records': analysis['sensitive_records'][:10],
                    },
                    'remediation': 'Restrict zone transfers to authorized servers only. '
                                   'Configure allow-transfer ACL on name servers.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'name_servers': name_servers,
            'successful_transfers': successful_transfers,
            'zone_data': all_zone_data,
        }