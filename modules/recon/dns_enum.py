# modules/recon/dns_enum.py

"""
DNS Record Enumerator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Enumerates all DNS record types for target domain
including A, AAAA, MX, NS, TXT, CNAME, SOA, and more.
"""

import concurrent.futures
from typing import Dict, List, Any, Optional, Set

import dns.resolver
import dns.rdatatype


class DNSEnumerator:
    """
    DNS record enumeration engine.
    
    Queries all common DNS record types for comprehensive
    domain intelligence gathering.
    """
    
    RECORD_TYPES = [
        'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA',
        'PTR', 'SRV', 'CAA', 'HINFO', 'RP', 'LOC',
    ]
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the DNS enumerator.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        self.resolver = dns.resolver.Resolver()
        
        self.timeout = self.config.get('timeout', 5)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        self.records: Dict[str, List[str]] = {}
        self.errors: List[str] = []
    
    def query_record_type(self, record_type: str) -> List[str]:
        """
        Query a specific DNS record type.
        
        Args:
            record_type: DNS record type
            
        Returns:
            List of record values as strings
        """
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            
            results = []
            for answer in answers:
                results.append(answer.to_text())
            
            return results
            
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            self.errors.append(f"Domain {self.domain} does not exist")
            return []
        except dns.exception.Timeout:
            self.errors.append(f"Timeout querying {record_type} records")
            return []
        except Exception as e:
            self.errors.append(f"Failed to query {record_type}: {str(e)}")
            return []
    
    def enumerate_all(self) -> Dict[str, List[str]]:
        """
        Enumerate all configured DNS record types.
        
        Returns:
            Dictionary mapping record types to values
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.RECORD_TYPES)) as executor:
            future_to_type = {
                executor.submit(self.query_record_type, record_type): record_type
                for record_type in self.RECORD_TYPES
            }
            
            for future in concurrent.futures.as_completed(future_to_type):
                record_type = future_to_type[future]
                
                try:
                    results = future.result()
                    if results:
                        self.records[record_type] = results
                except Exception as e:
                    self.errors.append(f"Error processing {record_type}: {str(e)}")
        
        return self.records
    
    def analyze_findings(self) -> List[Dict[str, Any]]:
        """
        Analyze DNS records for security issues.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        if 'SOA' in self.records:
            soa_record = self.records['SOA'][0]
            
            import re
            email_match = re.search(r'(\S+@\S+)', soa_record.replace('.', '@', 1))
            if email_match:
                findings.append({
                    'type': 'SOA Email Disclosure',
                    'severity': 'low',
                    'detail': f'Admin email found in SOA record',
                    'evidence': soa_record,
                })
        
        if 'TXT' in self.records:
            for txt_record in self.records['TXT']:
                txt_lower = txt_record.lower()
                
                if 'v=spf1' in txt_lower:
                    if '+all' in txt_lower:
                        findings.append({
                            'type': 'Weak SPF Record',
                            'severity': 'high',
                            'detail': 'SPF allows all senders (+all)',
                            'evidence': txt_record,
                        })
                
                if 'v=DMARC1' in txt_lower:
                    if 'p=none' in txt_lower:
                        findings.append({
                            'type': 'Weak DMARC Policy',
                            'severity': 'medium',
                            'detail': 'DMARC policy set to none',
                            'evidence': txt_record,
                        })
        
        return findings
    
    def run(self) -> Dict[str, Any]:
        """
        Run DNS enumeration.
        
        Returns:
            Dictionary with enumeration results
        """
        records = self.enumerate_all()
        analysis = self.analyze_findings()
        
        findings = [
            {
                'type': 'DNS Records Enumerated',
                'severity': 'info',
                'domain': self.domain,
                'description': f'Enumerated {len(records)} DNS record types',
                'evidence': {
                    record_type: values[:5]
                    for record_type, values in records.items()
                },
                'remediation': 'Review DNS records for security',
            }
        ]
        
        findings.extend(analysis)
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'records': records,
            'record_types_found': len(records),
        }