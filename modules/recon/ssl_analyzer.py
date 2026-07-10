# modules/recon/ssl_analyzer.py

"""
SSL/TLS Security Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Analyzes SSL/TLS configuration for vulnerabilities
including weak ciphers, expired certificates, and misconfigurations.
"""

import ssl
import socket
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class SSLAnalyzer:
    """
    SSL/TLS configuration analyzer.
    
    Checks SSL certificates and TLS configuration
    for security weaknesses and compliance issues.
    """
    
    TLS_VERSIONS = {
        'TLS 1.0': ssl.TLSVersion.TLSv1 if hasattr(ssl, 'TLSVersion') else None,
        'TLS 1.1': ssl.TLSVersion.TLSv1_1 if hasattr(ssl, 'TLSVersion') else None,
        'TLS 1.2': ssl.TLSVersion.TLSv1_2 if hasattr(ssl, 'TLSVersion') else None,
    }
    
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'anon',
        'EXPORT', 'PSK', 'SRP',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the SSL analyzer.
        
        Args:
            target: Target domain
            config: Configuration dictionary
        """
        self.target = target.strip()
        self.config = config or {}
        
        self.hostname = self._extract_hostname()
        self.port = self.config.get('port', 443)
        
        self.certificate_info: Dict[str, Any] = {}
        self.errors: List[str] = []
    
    def _extract_hostname(self) -> str:
        """
        Extract hostname from target.
        
        Returns:
            Hostname string
        """
        if self.target.startswith('https://'):
            return self.target[8:].split('/')[0]
        elif self.target.startswith('http://'):
            return self.target[7:].split('/')[0]
        return self.target
    
    def get_certificate(self) -> Optional[Dict[str, Any]]:
        """
        Get SSL certificate information.
        
        Returns:
            Dictionary with certificate details
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            wrapped_sock = context.wrap_socket(sock, server_hostname=self.hostname)
            wrapped_sock.connect((self.hostname, self.port))
            
            cert = wrapped_sock.getpeercert()
            cipher = wrapped_sock.cipher()
            
            wrapped_sock.close()
            
            if not cert:
                return None
            
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            expiry_date = None
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                except ValueError:
                    try:
                        expiry_date = datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        pass
            
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            san_list = []
            for san in cert.get('subjectAltName', []):
                san_list.append(san[1])
            
            return {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'expiry_date': expiry_date,
                'serial_number': cert.get('serialNumber', ''),
                'version': cert.get('version', 0),
                'subject_alt_names': san_list,
                'cipher': {
                    'name': cipher[0] if cipher else '',
                    'version': cipher[1] if cipher else '',
                    'bits': cipher[2] if cipher else 0,
                },
            }
            
        except socket.timeout:
            self.errors.append("SSL connection timed out")
            return None
        except ssl.SSLError as e:
            self.errors.append(f"SSL error: {str(e)}")
            return None
        except Exception as e:
            self.errors.append(f"SSL analysis failed: {str(e)}")
            return None
    
    def analyze_certificate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze certificate for security issues.
        
        Args:
            cert_info: Certificate information dictionary
            
        Returns:
            Dictionary with analysis results
        """
        issues = []
        
        if cert_info.get('expiry_date'):
            expiry = cert_info['expiry_date']
            now = datetime.now()
            days_remaining = (expiry - now).days
            
            if days_remaining < 0:
                issues.append({
                    'type': 'Expired Certificate',
                    'severity': 'critical',
                    'detail': f'Certificate expired {abs(days_remaining)} days ago',
                })
            elif days_remaining < 30:
                issues.append({
                    'type': 'Certificate Expiring Soon',
                    'severity': 'high',
                    'detail': f'Certificate expires in {days_remaining} days',
                })
            elif days_remaining < 90:
                issues.append({
                    'type': 'Certificate Expiring',
                    'severity': 'low',
                    'detail': f'Certificate expires in {days_remaining} days',
                })
        
        cipher_name = cert_info.get('cipher', {}).get('name', '').upper()
        
        for weak_cipher in self.WEAK_CIPHERS:
            if weak_cipher in cipher_name:
                issues.append({
                    'type': 'Weak Cipher Suite',
                    'severity': 'high',
                    'detail': f'Weak cipher detected: {cipher_name}',
                })
                break
        
        key_bits = cert_info.get('cipher', {}).get('bits', 0)
        
        if key_bits > 0 and key_bits < 128:
            issues.append({
                'type': 'Weak Encryption Key',
                'severity': 'high',
                'detail': f'Encryption key strength: {key_bits} bits',
            })
        
        san_list = cert_info.get('subject_alt_names', [])
        
        if san_list:
            wildcard_sans = [san for san in san_list if san.startswith('*.')]
            
            if wildcard_sans:
                issues.append({
                    'type': 'Wildcard Certificate',
                    'severity': 'low',
                    'detail': f'Wildcard SANs found: {", ".join(wildcard_sans[:5])}',
                })
        
        return {
            'issues': issues,
            'total_issues': len(issues),
            'days_remaining': (cert_info['expiry_date'] - datetime.now()).days if cert_info.get('expiry_date') else None,
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Run SSL/TLS analysis.
        
        Returns:
            Dictionary with analysis results
        """
        cert_info = self.get_certificate()
        
        if not cert_info:
            return {
                'findings': [{
                    'type': 'SSL Connection Failed',
                    'severity': 'high',
                    'target': self.hostname,
                    'description': 'Could not establish SSL connection or retrieve certificate',
                    'remediation': 'Ensure SSL/TLS is properly configured on the server',
                }],
                'errors': self.errors,
            }
        
        analysis = self.analyze_certificate(cert_info)
        
        findings = []
        
        for issue in analysis.get('issues', []):
            findings.append({
                'type': issue['type'],
                'severity': issue['severity'],
                'target': self.hostname,
                'description': issue['detail'],
                'remediation': 'Renew certificate' if 'expir' in issue['type'].lower() else 'Update SSL/TLS configuration',
            })
        
        if not findings:
            findings.append({
                'type': 'SSL/TLS Configuration',
                'severity': 'info',
                'target': self.hostname,
                'description': 'SSL/TLS configuration appears secure',
                'remediation': 'Continue monitoring certificate expiration',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'hostname': self.hostname,
            'certificate': {
                'subject': cert_info.get('subject', {}),
                'issuer': cert_info.get('issuer', {}),
                'not_before': cert_info.get('not_before'),
                'not_after': cert_info.get('not_after'),
                'cipher': cert_info.get('cipher', {}).get('name'),
                'key_bits': cert_info.get('cipher', {}).get('bits'),
                'subject_alt_names': cert_info.get('subject_alt_names', []),
            },
            'analysis': analysis,
        }