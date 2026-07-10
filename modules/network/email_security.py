# modules/network/email_security.py

"""
Email Security Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests email security configurations including SPF, DKIM,
DMARC records, and mail server security settings.
"""

import re
import socket
from typing import Dict, List, Any, Optional, Tuple

import dns.resolver


class EmailSecurity:
    """
    Email security configuration tester.
    
    Checks SPF, DKIM, DMARC, and MX records for
    common misconfigurations and security issues.
    """
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the email security tester.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        
        self.results: Dict[str, Any] = {}
        self.errors: List[str] = []
    
    def check_spf(self) -> Dict[str, Any]:
        """
        Check SPF record configuration.
        
        Returns:
            Dictionary with SPF check results
        """
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            
            spf_records = []
            for answer in answers:
                txt_string = answer.to_text().strip('"')
                if 'v=spf1' in txt_string.lower():
                    spf_records.append(txt_string)
            
            if not spf_records:
                return {
                    'has_spf': False,
                    'records': [],
                    'issues': ['No SPF record found'],
                    'severity': 'high',
                }
            
            issues = []
            
            if len(spf_records) > 1:
                issues.append('Multiple SPF records found (only one allowed)')
            
            for record in spf_records:
                if '+all' in record.lower():
                    issues.append('SPF record ends with +all (allows all senders)')
                
                if '?all' in record.lower():
                    issues.append('SPF record uses ?all (neutral, not recommended)')
                
                if '~all' not in record.lower() and '-all' not in record.lower():
                    issues.append('SPF record missing strict ~all or -all mechanism')
                
                include_count = record.lower().count('include:')
                if include_count > 10:
                    issues.append(f'SPF has {include_count} includes (DNS lookup limit is 10)')
                
                if 'ptr' in record.lower():
                    issues.append('SPF uses PTR mechanism (deprecated, not recommended)')
            
            return {
                'has_spf': True,
                'records': spf_records,
                'issues': issues,
                'severity': 'high' if issues else 'info',
            }
            
        except dns.resolver.NXDOMAIN:
            return {'has_spf': False, 'records': [], 'issues': ['Domain not found'], 'severity': 'high'}
        except Exception as e:
            self.errors.append(f"SPF check failed: {str(e)}")
            return {'has_spf': False, 'records': [], 'issues': [str(e)], 'severity': 'error'}
    
    def check_dmarc(self) -> Dict[str, Any]:
        """
        Check DMARC record configuration.
        
        Returns:
            Dictionary with DMARC check results
        """
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            dmarc_records = []
            for answer in answers:
                txt_string = answer.to_text().strip('"')
                if 'v=DMARC1' in txt_string:
                    dmarc_records.append(txt_string)
            
            if not dmarc_records:
                return {
                    'has_dmarc': False,
                    'records': [],
                    'issues': ['No DMARC record found'],
                    'severity': 'medium',
                }
            
            issues = []
            
            for record in dmarc_records:
                record_lower = record.lower()
                
                if 'p=none' in record_lower:
                    issues.append('DMARC policy set to none (monitoring only)')
                
                if 'p=quarantine' in record_lower:
                    pass
                elif 'p=reject' in record_lower:
                    pass
                else:
                    issues.append('DMARC policy missing or invalid')
                
                pct_match = re.search(r'pct=(\d+)', record_lower)
                if pct_match:
                    pct = int(pct_match.group(1))
                    if pct < 100:
                        issues.append(f'DMARC applies to only {pct}% of emails')
                
                if 'rua=' not in record_lower:
                    issues.append('No aggregate reporting URI (rua) configured')
                
                if 'ruf=' not in record_lower:
                    pass
            
            return {
                'has_dmarc': True,
                'records': dmarc_records,
                'issues': issues,
                'severity': 'medium' if issues else 'info',
            }
            
        except dns.resolver.NXDOMAIN:
            return {'has_dmarc': False, 'records': [], 'issues': ['No DMARC record found'], 'severity': 'medium'}
        except dns.resolver.NoAnswer:
            return {'has_dmarc': False, 'records': [], 'issues': ['No DMARC record found'], 'severity': 'medium'}
        except Exception as e:
            self.errors.append(f"DMARC check failed: {str(e)}")
            return {'has_dmarc': False, 'records': [], 'issues': [str(e)], 'severity': 'error'}
    
    def check_dkim(self, selector: str = 'default') -> Dict[str, Any]:
        """
        Check DKIM record configuration.
        
        Args:
            selector: DKIM selector to check
            
        Returns:
            Dictionary with DKIM check results
        """
        try:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            
            dkim_records = []
            for answer in answers:
                txt_string = answer.to_text().strip('"')
                if 'v=DKIM1' in txt_string or 'k=rsa' in txt_string.lower():
                    dkim_records.append(txt_string)
            
            if not dkim_records:
                return {
                    'has_dkim': False,
                    'selector': selector,
                    'records': [],
                    'issues': [f'No DKIM record found for selector: {selector}'],
                    'severity': 'low',
                }
            
            issues = []
            
            for record in dkim_records:
                if 'k=rsa' in record.lower():
                    key_match = re.search(r'p=([A-Za-z0-9+/=]+)', record)
                    if key_match:
                        key = key_match.group(1)
                        key_length = len(key) * 6 // 8
                        if key_length < 1024:
                            issues.append(f'Weak DKIM key: ~{key_length} bits (minimum 1024)')
                        elif key_length < 2048:
                            issues.append(f'DKIM key length: ~{key_length} bits (2048 recommended)')
            
            return {
                'has_dkim': True,
                'selector': selector,
                'records': dkim_records,
                'issues': issues,
                'severity': 'low' if issues else 'info',
            }
            
        except dns.resolver.NXDOMAIN:
            return {'has_dkim': False, 'selector': selector, 'records': [], 'issues': ['No DKIM record found'], 'severity': 'low'}
        except Exception as e:
            self.errors.append(f"DKIM check failed: {str(e)}")
            return {'has_dkim': False, 'selector': selector, 'records': [], 'issues': [str(e)], 'severity': 'error'}
    
    def check_mx(self) -> Dict[str, Any]:
        """
        Check MX record configuration.
        
        Returns:
            Dictionary with MX check results
        """
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            
            mx_records = []
            for answer in answers:
                mx_records.append({
                    'preference': answer.preference,
                    'exchange': answer.exchange.to_text().rstrip('.'),
                })
            
            mx_records.sort(key=lambda x: x['preference'])
            
            issues = []
            
            if not mx_records:
                issues.append('No MX records found')
            
            backup_servers = [mx for mx in mx_records if mx['preference'] > 10]
            if not backup_servers:
                pass
            
            return {
                'has_mx': len(mx_records) > 0,
                'records': mx_records,
                'issues': issues,
                'severity': 'info' if mx_records else 'high',
            }
            
        except dns.resolver.NoAnswer:
            return {'has_mx': False, 'records': [], 'issues': ['No MX records found'], 'severity': 'high'}
        except Exception as e:
            self.errors.append(f"MX check failed: {str(e)}")
            return {'has_mx': False, 'records': [], 'issues': [str(e)], 'severity': 'error'}
    
    def check_bimi(self) -> Dict[str, Any]:
        """
        Check BIMI record configuration.
        
        Returns:
            Dictionary with BIMI check results
        """
        try:
            bimi_domain = f"default._bimi.{self.domain}"
            answers = dns.resolver.resolve(bimi_domain, 'TXT')
            
            bimi_records = []
            for answer in answers:
                txt_string = answer.to_text().strip('"')
                if 'v=BIMI1' in txt_string:
                    bimi_records.append(txt_string)
            
            return {
                'has_bimi': len(bimi_records) > 0,
                'records': bimi_records,
                'issues': [],
                'severity': 'info',
            }
            
        except dns.resolver.NXDOMAIN:
            return {'has_bimi': False, 'records': [], 'issues': [], 'severity': 'info'}
        except Exception:
            return {'has_bimi': False, 'records': [], 'issues': [], 'severity': 'info'}
    
    def run(self) -> Dict[str, Any]:
        """
        Run all email security checks.
        
        Returns:
            Dictionary with check results
        """
        spf_result = self.check_spf()
        dmarc_result = self.check_dmarc()
        dkim_result = self.check_dkim()
        mx_result = self.check_mx()
        bimi_result = self.check_bimi()
        
        findings = []
        
        if spf_result.get('issues'):
            findings.append({
                'type': 'SPF Misconfiguration',
                'severity': spf_result.get('severity', 'info'),
                'domain': self.domain,
                'description': ', '.join(spf_result['issues']),
                'evidence': spf_result.get('records', []),
                'remediation': 'Configure proper SPF record with -all mechanism',
            })
        
        if dmarc_result.get('issues'):
            findings.append({
                'type': 'DMARC Misconfiguration',
                'severity': dmarc_result.get('severity', 'info'),
                'domain': self.domain,
                'description': ', '.join(dmarc_result['issues']),
                'evidence': dmarc_result.get('records', []),
                'remediation': 'Configure DMARC with p=reject and reporting addresses',
            })
        
        if dkim_result.get('issues'):
            findings.append({
                'type': 'DKIM Issues',
                'severity': dkim_result.get('severity', 'info'),
                'domain': self.domain,
                'description': ', '.join(dkim_result['issues']),
                'evidence': dkim_result.get('records', []),
                'remediation': 'Configure DKIM with 2048-bit RSA keys',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'spf': spf_result,
            'dmarc': dmarc_result,
            'dkim': dkim_result,
            'mx': mx_result,
            'bimi': bimi_result,
        }