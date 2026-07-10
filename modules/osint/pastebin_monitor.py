# modules/osint/pastebin_monitor.py

"""
Pastebin Monitor
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Searches Pastebin and similar sites for leaked credentials,
API keys, and sensitive information related to target domain.
"""

import json
import re
from typing import Dict, List, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import quote


class PastebinMonitor:
    """
    Pastebin and public paste site monitor.
    
    Searches public paste sites for domain-related
    leaked data, credentials, and sensitive information.
    """
    
    PSBDMP_URL = "https://psbdmp.cc/api/v3/search/{domain}"
    
    CREDENTIAL_PATTERNS = [
        r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'&]+)["\']?',
        r'(?:email|username|login)\s*[:=]\s*["\']?([^\s"\'&]+@[^\s"\'&]+)["\']?',
        r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        r'(?:secret|token)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
        r'(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)',
    ]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Pastebin monitor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        self.errors: List[str] = []
    
    def search_psbdmp(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        """
        Search PSBDMP for domain-related pastes.
        
        Args:
            domain: Target domain
            
        Returns:
            List of paste dictionaries
        """
        url = self.PSBDMP_URL.format(domain=domain)
        
        try:
            request = Request(url)
            request.add_header('User-Agent', 'WOLFSTRIKE/1.0')
            
            with urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if isinstance(data, list):
                    return data
            
            return None
            
        except URLError as e:
            self.errors.append(f"PSBDMP query failed: {str(e)}")
            return None
        except json.JSONDecodeError:
            return None
        except Exception as e:
            self.errors.append(f"Pastebin search failed: {str(e)}")
            return None
    
    def analyze_paste(self, paste_content: str) -> Dict[str, Any]:
        """
        Analyze paste content for sensitive information.
        
        Args:
            paste_content: Raw paste content
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'has_credentials': False,
            'has_api_keys': False,
            'has_private_keys': False,
            'has_emails': False,
            'credentials_found': [],
            'api_keys_found': [],
            'emails_found': [],
        }
        
        for pattern in self.CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, paste_content, re.IGNORECASE | re.MULTILINE)
            
            if matches:
                if 'password' in pattern or 'passwd' in pattern:
                    analysis['has_credentials'] = True
                    analysis['credentials_found'].extend(matches[:5])
                
                if 'api' in pattern or 'token' in pattern or 'secret' in pattern:
                    analysis['has_api_keys'] = True
                    analysis['api_keys_found'].extend(matches[:5])
                
                if 'email' in pattern or 'username' in pattern:
                    analysis['has_emails'] = True
                    analysis['emails_found'].extend(matches[:5])
                
                if 'PRIVATE KEY' in pattern:
                    analysis['has_private_keys'] = True
        
        return analysis
    
    def run(self, target: str) -> Dict[str, Any]:
        """
        Run Pastebin monitoring on target.
        
        Args:
            target: Target domain
            
        Returns:
            Dictionary with monitoring results
        """
        domain = target.replace('https://', '').replace('http://', '').rstrip('/')
        
        pastes = self.search_psbdmp(domain)
        
        findings = []
        
        if pastes:
            total_pastes = len(pastes)
            sensitive_pastes = []
            
            for paste in pastes[:20]:
                content = paste.get('content', '')
                
                if content:
                    analysis = self.analyze_paste(content)
                    
                    if analysis['has_credentials'] or analysis['has_api_keys'] or analysis['has_private_keys']:
                        sensitive_pastes.append({
                            'id': paste.get('id', ''),
                            'title': paste.get('title', ''),
                            'date': paste.get('date', ''),
                            'analysis': analysis,
                        })
            
            if sensitive_pastes:
                findings.append({
                    'type': 'Sensitive Data in Pastes',
                    'severity': 'critical',
                    'target': domain,
                    'description': f'Found {len(sensitive_pastes)} pastes containing sensitive information',
                    'evidence': sensitive_pastes[:5],
                    'remediation': 'Investigate and request removal of sensitive pastes. '
                                   'Rotate any exposed credentials immediately.',
                })
            
            findings.append({
                'type': 'Pastebin Mentions',
                'severity': 'info',
                'target': domain,
                'description': f'Found {total_pastes} pastes mentioning domain',
                'evidence': {'total_pastes': total_pastes},
                'remediation': 'Review pastes for sensitive information disclosure',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'total_pastes': len(pastes) if pastes else 0,
        }