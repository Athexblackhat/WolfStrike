# modules/osint/breach_check.py

"""
Data Breach Checker
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Checks if domain or email addresses appear in known
data breaches using public breach databases.
"""

import json
import hashlib
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class BreachCheck:
    """
    Data breach verification module.
    
    Checks domains and emails against known breach
    databases to identify compromised accounts.
    """
    
    HIBP_API = "https://haveibeenpwned.com/api/v3"
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the breach checker.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        self.errors: List[str] = []
    
    def check_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Check if email appears in data breaches.
        
        Args:
            email: Email address to check
            
        Returns:
            Dictionary with breach information
        """
        url = f"{self.HIBP_API}/breachedaccount/{email}"
        
        try:
            request = Request(url)
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            request.add_header('hibp-api-key', '')
            
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                breaches = []
                for breach in data:
                    breaches.append({
                        'name': breach.get('Name', ''),
                        'title': breach.get('Title', ''),
                        'domain': breach.get('Domain', ''),
                        'date': breach.get('BreachDate', ''),
                        'data_classes': breach.get('DataClasses', []),
                        'description': breach.get('Description', ''),
                    })
                
                return {
                    'email': email,
                    'breach_count': len(breaches),
                    'breaches': breaches,
                }
                
        except HTTPError as e:
            if e.code == 404:
                return {'email': email, 'breach_count': 0, 'breaches': []}
            self.errors.append(f"HIBP API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"HIBP API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from HIBP")
            return None
    
    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Check for breaches associated with domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with domain breach information
        """
        url = f"{self.HIBP_API}/breaches?domain={domain}"
        
        try:
            request = Request(url)
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                breaches = []
                for breach in data:
                    breaches.append({
                        'name': breach.get('Name', ''),
                        'title': breach.get('Title', ''),
                        'date': breach.get('BreachDate', ''),
                        'pwn_count': breach.get('PwnCount', 0),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified', False),
                        'is_sensitive': breach.get('IsSensitive', False),
                    })
                
                return {
                    'domain': domain,
                    'breach_count': len(breaches),
                    'total_pwn_count': sum(b.get('pwn_count', 0) for b in breaches),
                    'breaches': breaches,
                }
                
        except HTTPError as e:
            self.errors.append(f"HIBP API error: {e.code}")
            return None
        except URLError as e:
            self.errors.append(f"HIBP API connection failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            self.errors.append("Invalid JSON response from HIBP")
            return None
    
    def check_password_pwned(self, password: str) -> Optional[Dict[str, Any]]:
        """
        Check if password appears in breaches (k-anonymity).
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with password check results
        """
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        try:
            request = Request(url)
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            
            with urlopen(request, timeout=10) as response:
                text = response.read().decode('utf-8')
                
                for line in text.split('\n'):
                    if line.strip():
                        hash_suffix, count = line.split(':')
                        if hash_suffix == suffix:
                            return {
                                'password_hash': sha1_hash,
                                'pwned': True,
                                'count': int(count),
                            }
                
                return {
                    'password_hash': sha1_hash,
                    'pwned': False,
                    'count': 0,
                }
                
        except Exception as e:
            self.errors.append(f"Password check failed: {str(e)}")
            return None
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run breach check on target domain.
        
        Args:
            target: Target domain
            
        Returns:
            Dictionary with breach check results
        """
        domain = target.replace('https://', '').replace('http://', '').rstrip('/')
        
        domain_result = self.check_domain(domain)
        
        findings = []
        
        if domain_result and domain_result.get('breach_count', 0) > 0:
            sensitive_breaches = [b for b in domain_result['breaches'] if b.get('is_sensitive')]
            
            severity = 'critical' if sensitive_breaches else 'high'
            
            findings.append({
                'type': 'Domain Data Breaches',
                'severity': severity,
                'target': domain,
                'description': f'Domain found in {domain_result["breach_count"]} data breaches '
                               f'with {domain_result["total_pwn_count"]} total compromised accounts',
                'evidence': {
                    'breach_count': domain_result['breach_count'],
                    'total_pwn_count': domain_result['total_pwn_count'],
                    'breaches': domain_result['breaches'][:10],
                },
                'remediation': 'Investigate breaches and reset compromised account passwords. '
                               'Implement multi-factor authentication. Monitor for credential stuffing.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'domain': domain,
            'domain_result': domain_result,
        }