# modules/recon/whois_lookup.py

"""
WHOIS Information Lookup
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Retrieves WHOIS information for domains including
registrar details, nameservers, and dates.
"""

import re
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime


class WhoisLookup:
    """
    WHOIS information retriever.
    
    Gets domain registration details, nameserver info,
    and historical WHOIS data for target domains.
    """
    
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
    }
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the WHOIS lookup.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        
        self.errors: List[str] = []
    
    def _get_tld(self) -> str:
        """
        Get the top-level domain.
        
        Returns:
            TLD string
        """
        parts = self.domain.split('.')
        if len(parts) >= 2:
            return parts[-1].lower()
        return 'com'
    
    def _query_whois_server(self, server: str, query: str, port: int = 43) -> Optional[str]:
        """
        Query a WHOIS server directly.
        
        Args:
            server: WHOIS server hostname
            query: Query string
            port: Server port
            
        Returns:
            Raw WHOIS response text
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            
            sock.send(f"{query}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except socket.timeout:
            self.errors.append(f"WHOIS query timed out for {server}")
            return None
        except socket.gaierror:
            self.errors.append(f"WHOIS server not found: {server}")
            return None
        except Exception as e:
            self.errors.append(f"WHOIS query failed: {str(e)}")
            return None
    
    def parse_whois_response(self, raw_data: str) -> Dict[str, Any]:
        """
        Parse raw WHOIS response into structured data.
        
        Args:
            raw_data: Raw WHOIS response text
            
        Returns:
            Dictionary with parsed WHOIS data
        """
        info = {
            'domain': self.domain,
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'updated_date': '',
            'name_servers': [],
            'status': [],
            'registrant': '',
            'registrant_email': '',
            'admin_email': '',
            'tech_email': '',
            'raw': raw_data[:1000],
        }
        
        patterns = {
            'registrar': [
                r'Registrar:\s*(.+)',
                r'Sponsoring Registrar:\s*(.+)',
            ],
            'creation_date': [
                r'Creation Date:\s*(.+)',
                r'Created on:\s*(.+)',
                r'Registration Time:\s*(.+)',
            ],
            'expiration_date': [
                r'Registry Expiry Date:\s*(.+)',
                r'Expiry Date:\s*(.+)',
                r'Expiration Date:\s*(.+)',
            ],
            'updated_date': [
                r'Updated Date:\s*(.+)',
                r'Last Updated:\s*(.+)',
            ],
        }
        
        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, raw_data, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if value:
                        info[field] = value
                        break
        
        ns_pattern = r'Name Server:\s*(.+)'
        for match in re.finditer(ns_pattern, raw_data, re.IGNORECASE):
            ns = match.group(1).strip().lower()
            if ns and ns not in info['name_servers']:
                info['name_servers'].append(ns)
        
        status_pattern = r'Domain Status:\s*(.+)'
        for match in re.finditer(status_pattern, raw_data, re.IGNORECASE):
            status = match.group(1).strip()
            if status and status not in info['status']:
                info['status'].append(status)
        
        email_patterns = [
            r'Registrant Email:\s*(\S+@\S+)',
            r'Admin Email:\s*(\S+@\S+)',
            r'Tech Email:\s*(\S+@\S+)',
        ]
        
        for pattern in email_patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                email = match.group(1).strip()
                if 'registrant' in pattern.lower():
                    info['registrant_email'] = email
                elif 'admin' in pattern.lower():
                    info['admin_email'] = email
                elif 'tech' in pattern.lower():
                    info['tech_email'] = email
        
        return info
    
    def lookup(self) -> Optional[Dict[str, Any]]:
        """
        Perform WHOIS lookup for domain.
        
        Returns:
            Dictionary with WHOIS information
        """
        tld = self._get_tld()
        whois_server = self.WHOIS_SERVERS.get(tld, 'whois.iana.org')
        
        raw_data = self._query_whois_server(whois_server, self.domain)
        
        if not raw_data:
            return None
        
        return self.parse_whois_response(raw_data)
    
    def run(self) -> Dict[str, Any]:
        """
        Run WHOIS lookup.
        
        Returns:
            Dictionary with lookup results
        """
        whois_info = self.lookup()
        
        findings = []
        
        if whois_info:
            findings.append({
                'type': 'WHOIS Information',
                'severity': 'info',
                'domain': self.domain,
                'description': f'Registrar: {whois_info.get("registrar", "Unknown")}',
                'evidence': {
                    'registrar': whois_info.get('registrar'),
                    'creation_date': whois_info.get('creation_date'),
                    'expiration_date': whois_info.get('expiration_date'),
                    'name_servers': whois_info.get('name_servers', []),
                },
                'remediation': 'Review WHOIS information. Consider using WHOIS privacy protection.',
            })
            
            if whois_info.get('registrant_email'):
                findings.append({
                    'type': 'Registrant Email Exposed',
                    'severity': 'low',
                    'domain': self.domain,
                    'description': f'Registrant email visible in WHOIS: {whois_info["registrant_email"]}',
                    'remediation': 'Enable WHOIS privacy protection to hide contact details',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': self.domain,
            'whois_info': whois_info,
        }