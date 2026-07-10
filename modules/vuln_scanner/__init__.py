# modules/vuln_scanner/__init__.py

"""
WOLFSTRIKE Vulnerability Scanner Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Comprehensive vulnerability scanning engine for detecting
XSS, SQLi, LFI/RFI, CSRF, SSRF, SSTI, and other web vulnerabilities.
"""

from typing import Dict, List, Any, Optional

from modules.vuln_scanner.xss_scanner import XSSScanner
from modules.vuln_scanner.sqli_scanner import SQLiScanner
from modules.vuln_scanner.nosqli_scanner import NoSQLiScanner
from modules.vuln_scanner.command_injection import CommandInjectionScanner
from modules.vuln_scanner.ldap_injection import LDAPInjectionScanner
from modules.vuln_scanner.xpath_injection import XPathInjectionScanner
from modules.vuln_scanner.ssti_scanner import SSTIScanner
from modules.vuln_scanner.ssrf_scanner import SSRFScanner
from modules.vuln_scanner.lfi_rfi_scanner import LFIRFIScanner
from modules.vuln_scanner.csrf_detect import CSRFDetector
from modules.vuln_scanner.open_redirect import OpenRedirectScanner
from modules.vuln_scanner.file_upload import FileUploadTester
from modules.vuln_scanner.clickjacking import ClickjackingDetector
from modules.vuln_scanner.cors_misconfig import CORSMisconfigScanner
from modules.vuln_scanner.security_misconfig import SecurityMisconfigScanner

__all__ = [
    'XSSScanner',
    'SQLiScanner',
    'NoSQLiScanner',
    'CommandInjectionScanner',
    'LDAPInjectionScanner',
    'XPathInjectionScanner',
    'SSTIScanner',
    'SSRFScanner',
    'LFIRFIScanner',
    'CSRFDetector',
    'OpenRedirectScanner',
    'FileUploadTester',
    'ClickjackingDetector',
    'CORSMisconfigScanner',
    'SecurityMisconfigScanner',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


def run(target: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run all vulnerability scanner modules.
    
    Args:
        target: Target URL
        config: Configuration dictionary
        
    Returns:
        Dictionary with findings and errors
    """
    all_findings = []
    all_errors = []
    
    vuln_modules = [
        ('xss', XSSScanner),
        ('sqli', SQLiScanner),
        ('nosqli', NoSQLiScanner),
        ('command_injection', CommandInjectionScanner),
        ('ldap_injection', LDAPInjectionScanner),
        ('xpath_injection', XPathInjectionScanner),
        ('ssti', SSTIScanner),
        ('ssrf', SSRFScanner),
        ('lfi_rfi', LFIRFIScanner),
        ('csrf', CSRFDetector),
        ('open_redirect', OpenRedirectScanner),
        ('file_upload', FileUploadTester),
        ('clickjacking', ClickjackingDetector),
        ('cors', CORSMisconfigScanner),
        ('security_misconfig', SecurityMisconfigScanner),
    ]
    
    for name, module_class in vuln_modules:
        try:
            instance = module_class(target, config or {})
            result = instance.run()
            
            if isinstance(result, dict):
                all_findings.extend(result.get('findings', []))
                all_errors.extend(result.get('errors', []))
        except Exception as e:
            all_errors.append(f"Error in vuln_scanner/{name}: {str(e)}")
    
    return {
        'findings': all_findings,
        'errors': all_errors,
    }