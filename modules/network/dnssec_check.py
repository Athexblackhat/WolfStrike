# modules/network/dnssec_check.py

"""
DNSSEC Validation Checker
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Validates DNSSEC configuration for domains,
checking DNSKEY, DS, RRSIG records and chain of trust.
"""

from typing import Dict, List, Any, Optional
import dns.resolver
import dns.name
import dns.rdatatype


class DNSSECCheck:
    """
    DNSSEC configuration validator.
    
    Checks DNSSEC implementation status and validates
    DNSKEY, DS, and RRSIG record configurations.
    """
    
    def __init__(
        self,
        domain: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the DNSSEC checker.
        
        Args:
            domain: Target domain
            config: Configuration dictionary
        """
        self.domain = domain.lower().strip()
        self.config = config or {}
        self.resolver = dns.resolver.Resolver()
        
        self.errors: List[str] = []
    
    def check_dnssec_status(self) -> Dict[str, Any]:
        """
        Check if DNSSEC is enabled for domain.
        
        Returns:
            Dictionary with DNSSEC status
        """
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            
            is_signed = False
            
            try:
                rrsig_answers = self.resolver.resolve(
                    self.domain,
                    'RRSIG',
                    raise_on_no_answer=False
                )
                
                for answer in rrsig_answers:
                    if answer.rdtype == dns.rdatatype.RRSIG:
                        is_signed = True
                        break
                        
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                pass
            
            return {
                'domain': self.domain,
                'dnssec_enabled': is_signed,
                'has_a_record': len(answers) > 0,
            }
            
        except dns.resolver.NXDOMAIN:
            return {'domain': self.domain, 'dnssec_enabled': False, 'has_a_record': False, 'error': 'Domain not found'}
        except Exception as e:
            self.errors.append(f"DNSSEC status check failed: {str(e)}")
            return {'domain': self.domain, 'dnssec_enabled': False, 'error': str(e)}
    
    def check_dnskey(self) -> Dict[str, Any]:
        """
        Check DNSKEY records for the domain.
        
        Returns:
            Dictionary with DNSKEY information
        """
        try:
            answers = self.resolver.resolve(self.domain, 'DNSKEY')
            
            keys = []
            for answer in answers:
                key_data = {
                    'flags': answer.flags,
                    'protocol': answer.protocol,
                    'algorithm': answer.algorithm,
                    'algorithm_name': self._get_algorithm_name(answer.algorithm),
                    'key_length': len(answer.key) * 8,
                    'is_zsk': answer.flags == 256,
                    'is_ksk': answer.flags == 257,
                }
                keys.append(key_data)
            
            issues = []
            
            zsk_count = sum(1 for k in keys if k['is_zsk'])
            ksk_count = sum(1 for k in keys if k['is_ksk'])
            
            if zsk_count == 0:
                issues.append('No Zone Signing Key (ZSK) found')
            if ksk_count == 0:
                issues.append('No Key Signing Key (KSK) found')
            
            for key in keys:
                if key['algorithm'] in [1, 3, 5, 6, 7]:
                    issues.append(f'Deprecated algorithm: {key["algorithm_name"]}')
                if key['key_length'] < 2048 and not key['algorithm'] in [13, 14, 15, 16]:
                    issues.append(f'Weak key length: {key["key_length"]} bits')
            
            return {
                'keys_found': len(keys),
                'keys': keys,
                'issues': issues,
            }
            
        except dns.resolver.NoAnswer:
            return {'keys_found': 0, 'keys': [], 'issues': ['No DNSKEY records found']}
        except Exception as e:
            self.errors.append(f"DNSKEY check failed: {str(e)}")
            return {'keys_found': 0, 'keys': [], 'issues': [str(e)]}
    
    def check_ds_record(self) -> Dict[str, Any]:
        """
        Check DS records (must check from parent zone).
        
        Returns:
            Dictionary with DS record information
        """
        try:
            labels = self.domain.split('.')
            
            if len(labels) < 2:
                return {'ds_found': False, 'issues': ['Cannot determine parent zone']}
            
            parent_domain = '.'.join(labels[1:])
            
            answers = self.resolver.resolve(
                dns.name.from_text(self.domain),
                'DS',
                raise_on_no_answer=False
            )
            
            ds_records = []
            for answer in answers:
                if answer.rdtype == dns.rdatatype.DS:
                    ds_records.append({
                        'key_tag': answer.key_tag,
                        'algorithm': answer.algorithm,
                        'algorithm_name': self._get_algorithm_name(answer.algorithm),
                        'digest_type': answer.digest_type,
                        'digest': answer.digest.hex(),
                    })
            
            return {
                'ds_found': len(ds_records) > 0,
                'records': ds_records,
                'issues': [] if ds_records else ['No DS records found at parent zone'],
            }
            
        except Exception as e:
            self.errors.append(f"DS record check failed: {str(e)}")
            return {'ds_found': False, 'records': [], 'issues': [str(e)]}
    
    def _get_algorithm_name(self, algorithm: int) -> str:
        """
        Get algorithm name from number.
        
        Args:
            algorithm: Algorithm number
            
        Returns:
            Algorithm name string
        """
        algorithms = {
            1: 'RSA/MD5',
            2: 'Diffie-Hellman',
            3: 'DSA/SHA1',
            5: 'RSA/SHA-1',
            6: 'DSA-NSEC3-SHA1',
            7: 'RSASHA1-NSEC3-SHA1',
            8: 'RSA/SHA-256',
            10: 'RSA/SHA-512',
            12: 'GOST R 34.10-2001',
            13: 'ECDSA Curve P-256 with SHA-256',
            14: 'ECDSA Curve P-384 with SHA-384',
            15: 'Ed25519',
            16: 'Ed448',
        }
        return algorithms.get(algorithm, f'Unknown ({algorithm})')
    
    def check_nsec_nsec3(self) -> Dict[str, Any]:
        """
        Check NSEC/NSEC3 records for zone walking protection.
        
        Returns:
            Dictionary with NSEC/NSEC3 information
        """
        try:
            has_nsec = False
            has_nsec3 = False
            
            try:
                nsec_answers = self.resolver.resolve(
                    self.domain,
                    'NSEC',
                    raise_on_no_answer=False
                )
                has_nsec = len(list(nsec_answers)) > 0
            except Exception:
                pass
            
            try:
                nsec3_answers = self.resolver.resolve(
                    self.domain,
                    'NSEC3',
                    raise_on_no_answer=False
                )
                has_nsec3 = len(list(nsec3_answers)) > 0
            except Exception:
                pass
            
            issues = []
            
            if has_nsec and not has_nsec3:
                issues.append('Using NSEC without NSEC3 (zone walking possible)')
            
            return {
                'has_nsec': has_nsec,
                'has_nsec3': has_nsec3,
                'zone_walking_protected': has_nsec3,
                'issues': issues,
            }
            
        except Exception as e:
            self.errors.append(f"NSEC/NSEC3 check failed: {str(e)}")
            return {'has_nsec': False, 'has_nsec3': False, 'issues': [str(e)]}
    
    def run(self) -> Dict[str, Any]:
        """
        Run all DNSSEC checks.
        
        Returns:
            Dictionary with check results
        """
        status = self.check_dnssec_status()
        dnskey = self.check_dnskey()
        ds_record = self.check_ds_record()
        nsec = self.check_nsec_nsec3()
        
        findings = []
        
        if not status.get('dnssec_enabled', False):
            findings.append({
                'type': 'DNSSEC Not Enabled',
                'severity': 'medium',
                'domain': self.domain,
                'description': 'DNSSEC is not enabled for this domain',
                'remediation': 'Enable DNSSEC for domain and configure DS records at registrar',
            })
        
        if dnskey.get('issues'):
            findings.append({
                'type': 'DNSSEC Key Issues',
                'severity': 'high',
                'domain': self.domain,
                'description': ', '.join(dnskey['issues']),
                'evidence': dnskey.get('keys', []),
                'remediation': 'Update DNSSEC keys with strong algorithms and key lengths',
            })
        
        if nsec.get('issues'):
            findings.append({
                'type': 'DNSSEC Zone Walking',
                'severity': 'low',
                'domain': self.domain,
                'description': ', '.join(nsec['issues']),
                'remediation': 'Implement NSEC3 with opt-out for zone walking protection',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'status': status,
            'dnskey': dnskey,
            'ds_record': ds_record,
            'nsec': nsec,
        }