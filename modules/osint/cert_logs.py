# modules/osint/cert_logs.py

"""
Certificate Transparency Log Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Searches Certificate Transparency logs for SSL certificates
to discover subdomains and domain history.
"""

import json
from typing import Dict, List, Any, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import URLError


class CertLogs:
    """
    Certificate Transparency log analyzer.
    
    Queries crt.sh for SSL certificate data to discover
    subdomains and domain history without API key.
    """
    
    CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the cert log analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        self.errors: List[str] = []
    
    def search_certificates(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        """
        Search Certificate Transparency logs for domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of certificate dictionaries
        """
        url = self.CRTSH_URL.format(domain=domain)
        
        try:
            request = Request(url)
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            
            with urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if isinstance(data, list):
                    return data
            
            return None
            
        except URLError as e:
            self.errors.append(f"crt.sh query failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from crt.sh")
            return None
        except Exception as e:
            self.errors.append(f"Certificate search failed: {str(e)}")
            return None
    
    def extract_subdomains(self, certificates: List[Dict[str, Any]], domain: str) -> Set[str]:
        """
        Extract unique subdomains from certificate data.
        
        Args:
            certificates: List of certificate dictionaries
            domain: Base domain
            
        Returns:
            Set of unique subdomain strings
        """
        subdomains = set()
        
        for cert in certificates:
            name_value = cert.get('name_value', '')
            
            names = name_value.split('\n')
            
            for name in names:
                name = name.strip().lower()
                name = name.replace('*.', '')
                
                if name and name != domain:
                    if name.endswith('.' + domain):
                        subdomains.add(name)
                    elif name == domain:
                        pass
        
        return subdomains
    
    def analyze_certificates(self, certificates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze certificate data for patterns.
        
        Args:
            certificates: List of certificate dictionaries
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'total_certificates': len(certificates),
            'issuers': set(),
            'valid_certificates': 0,
            'expired_certificates': 0,
            'wildcard_certificates': 0,
        }
        
        for cert in certificates:
            issuer = cert.get('issuer_name', '')
            if issuer:
                analysis['issuers'].add(issuer)
            
            name_value = cert.get('name_value', '')
            if '*.' in name_value:
                analysis['wildcard_certificates'] += 1
            
            not_after = cert.get('not_after', '')
            if not_after:
                from datetime import datetime
                try:
                    expiry = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                    if expiry > datetime.now():
                        analysis['valid_certificates'] += 1
                    else:
                        analysis['expired_certificates'] += 1
                except ValueError:
                    pass
        
        analysis['issuers'] = list(analysis['issuers'])
        return analysis
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run certificate transparency analysis.
        
        Args:
            target: Target domain
            
        Returns:
            Dictionary with analysis results
        """
        certificates = self.search_certificates(target)
        
        if not certificates:
            return {
                'findings': [],
                'errors': self.errors,
                'domain': target,
            }
        
        subdomains = self.extract_subdomains(certificates, target)
        analysis = self.analyze_certificates(certificates)
        
        findings = []
        
        if subdomains:
            findings.append({
                'type': 'Subdomains from Certificate Transparency',
                'severity': 'info',
                'target': target,
                'description': f'Found {len(subdomains)} subdomains via certificate transparency logs',
                'evidence': {
                    'subdomains': list(subdomains)[:30],
                    'total_subdomains': len(subdomains),
                },
                'remediation': 'Review discovered subdomains for security and remove unnecessary certificates',
            })
        
        if analysis['expired_certificates'] > 0:
            findings.append({
                'type': 'Expired Certificates',
                'severity': 'low',
                'target': target,
                'description': f'Found {analysis["expired_certificates"]} expired certificates',
                'evidence': {
                    'expired_count': analysis['expired_certificates'],
                    'total': analysis['total_certificates'],
                },
                'remediation': 'Remove or renew expired certificates',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': target,
            'subdomains': list(subdomains),
            'analysis': analysis,
        }