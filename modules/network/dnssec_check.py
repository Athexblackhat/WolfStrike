# modules/network/dnssec_check.py

"""
DNSSEC Validation Checker
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Validates DNSSEC configuration for domains,
checking DNSKEY, DS, RRSIG records and chain of trust.
"""

import re
from typing import Dict, List, Any, Optional, Tuple

import dns.resolver
import dns.name
import dns.rdatatype
import dns.exception


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
        self.domain = domain.lower().strip() if domain else ''
        self.config = config or {}
        self.resolver = dns.resolver.Resolver()
        
        # Set timeout from config
        self.timeout = self.config.get('timeout', 10)
        self._set_resolver_timeout()
        
        self.errors: List[str] = []
        self.scan_status: str = 'initialized'
    
    def _set_resolver_timeout(self) -> None:
        """Set resolver timeout values."""
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain string
            
        Returns:
            True if domain is valid
        """
        if not domain:
            return False
        
        if len(domain) > 253:
            return False
        
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def _validate_domain(self) -> Tuple[bool, str]:
        """
        Validate domain before processing.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.domain:
            return False, "Domain is empty"
        
        if not self._is_valid_domain(self.domain):
            return False, f"Invalid domain format: {self.domain}"
        
        return True, ""
    
    def _safe_resolve(self, domain: str, record_type: str, raise_on_no_answer: bool = True) -> Optional[dns.resolver.Answer]:
        """
        Safely resolve DNS records with timeout.
        
        Args:
            domain: Domain to resolve
            record_type: DNS record type
            raise_on_no_answer: Whether to raise on NoAnswer
            
        Returns:
            DNS answer or None
        """
        try:
            return self.resolver.resolve(domain, record_type, raise_on_no_answer=raise_on_no_answer)
        except dns.resolver.NXDOMAIN:
            self.errors.append(f"Domain {domain} does not exist")
            return None
        except dns.resolver.NoAnswer:
            if raise_on_no_answer:
                self.errors.append(f"No {record_type} records found for {domain}")
            return None
        except dns.exception.Timeout:
            self.errors.append(f"DNS resolution timed out for {domain} ({record_type})")
            return None
        except dns.resolver.NoNameservers:
            self.errors.append(f"No nameservers available for {domain}")
            return None
        except Exception as e:
            self.errors.append(f"DNS resolution failed for {domain} ({record_type}): {str(e)}")
            return None
    
    def _check_resolver_response(self, answer: Optional[dns.resolver.Answer]) -> bool:
        """
        Check if resolver response is valid.
        
        Args:
            answer: DNS answer
            
        Returns:
            True if response is valid
        """
        if answer is None:
            return False
        if not hasattr(answer, 'response'):
            return False
        return True
    
    def _get_domain_labels(self, domain: str) -> List[str]:
        """
        Get domain labels.
        
        Args:
            domain: Domain string
            
        Returns:
            List of labels
        """
        if not domain:
            return []
        return domain.split('.')
    
    def _handle_resolver_error(self, error: Exception, record_type: str) -> Dict[str, Any]:
        """
        Handle resolver errors consistently.
        
        Args:
            error: Exception raised
            record_type: DNS record type
            
        Returns:
            Error dictionary
        """
        error_msg = str(error)
        self.errors.append(f"{record_type} check failed: {error_msg}")
        return {
            'error': error_msg,
            'status': 'failed',
            'record_type': record_type,
        }
    
    def check_dnssec_status(self) -> Dict[str, Any]:
        """
        Check if DNSSEC is enabled for domain.
        
        Returns:
            Dictionary with DNSSEC status
        """
        # First validate domain
        valid, error = self._validate_domain()
        if not valid:
            self.errors.append(error)
            return {
                'domain': self.domain,
                'dnssec_enabled': False,
                'has_a_record': False,
                'error': error,
            }
        
        # Check A record
        a_answer = self._safe_resolve(self.domain, 'A', raise_on_no_answer=False)
        has_a_record = a_answer is not None and len(a_answer) > 0
        
        # Check for RRSIG (DNSSEC signature)
        is_signed = False
        rrsig_answer = self._safe_resolve(self.domain, 'RRSIG', raise_on_no_answer=False)
        
        if rrsig_answer is not None and hasattr(rrsig_answer, 'response'):
            try:
                for answer in rrsig_answer:
                    if answer.rdtype == dns.rdatatype.RRSIG:
                        is_signed = True
                        break
            except Exception:
                pass
        
        return {
            'domain': self.domain,
            'dnssec_enabled': is_signed,
            'has_a_record': has_a_record,
            'status': 'completed' if (has_a_record or is_signed) else 'no_records',
        }
    
    def check_dnskey(self) -> Dict[str, Any]:
        """
        Check DNSKEY records for the domain.
        
        Returns:
            Dictionary with DNSKEY information
        """
        try:
            answers = self._safe_resolve(self.domain, 'DNSKEY', raise_on_no_answer=False)
            
            if not answers or not self._check_resolver_response(answers):
                return {
                    'keys_found': 0,
                    'keys': [],
                    'issues': ['No DNSKEY records found'],
                    'status': 'no_keys',
                }
            
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
                if key['key_length'] < 2048 and key['algorithm'] not in [13, 14, 15, 16]:
                    issues.append(f'Weak key length: {key["key_length"]} bits')
            
            return {
                'keys_found': len(keys),
                'keys': keys,
                'issues': issues,
                'status': 'completed',
            }
            
        except Exception as e:
            return self._handle_resolver_error(e, 'DNSKEY')
    
    def check_ds_record(self) -> Dict[str, Any]:
        """
        Check DS records (must check from parent zone).
        
        Returns:
            Dictionary with DS record information
        """
        try:
            labels = self._get_domain_labels(self.domain)
            
            if len(labels) < 2:
                return {
                    'ds_found': False,
                    'records': [],
                    'issues': ['Cannot determine parent zone - domain has no TLD'],
                    'status': 'invalid_domain',
                }
            
            ds_answer = self._safe_resolve(self.domain, 'DS', raise_on_no_answer=False)
            
            if not ds_answer or not self._check_resolver_response(ds_answer):
                return {
                    'ds_found': False,
                    'records': [],
                    'issues': ['No DS records found at parent zone'],
                    'status': 'no_records',
                }
            
            ds_records = []
            for answer in ds_answer:
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
                'status': 'completed',
            }
            
        except Exception as e:
            return self._handle_resolver_error(e, 'DS')
    
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
            
            # Check NSEC
            nsec_answer = self._safe_resolve(self.domain, 'NSEC', raise_on_no_answer=False)
            if nsec_answer and self._check_resolver_response(nsec_answer):
                try:
                    has_nsec = len(list(nsec_answer)) > 0
                except Exception:
                    pass
            
            # Check NSEC3
            nsec3_answer = self._safe_resolve(self.domain, 'NSEC3', raise_on_no_answer=False)
            if nsec3_answer and self._check_resolver_response(nsec3_answer):
                try:
                    has_nsec3 = len(list(nsec3_answer)) > 0
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
                'status': 'completed',
            }
            
        except Exception as e:
            return self._handle_resolver_error(e, 'NSEC/NSEC3')
    
    def run(self) -> Dict[str, Any]:
        """
        Run all DNSSEC checks.
        
        Returns:
            Dictionary with check results
        """
        # Reset state
        self.errors.clear()
        self.scan_status = 'running'
        
        # Validate domain
        valid, error = self._validate_domain()
        if not valid:
            self.errors.append(error)
            self.scan_status = 'failed'
            return {
                'findings': [],
                'errors': self.errors,
                'status': {},
                'dnskey': {},
                'ds_record': {},
                'nsec': {},
                'scan_status': 'failed',
                'error': error,
            }
        
        # Run checks
        status = self.check_dnssec_status()
        dnskey = self.check_dnskey()
        ds_record = self.check_ds_record()
        nsec = self.check_nsec_nsec3()
        
        self.scan_status = 'completed'
        
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
                'type': 'DNSSEC Zone Walking Risk',
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
            'scan_status': self.scan_status,
            'domain': self.domain,
        }
