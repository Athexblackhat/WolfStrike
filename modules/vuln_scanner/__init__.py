# modules/vuln_scanner/__init__.py

"""
WOLFSTRIKE Vulnerability Scanner Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Comprehensive vulnerability scanning engine for detecting
XSS, SQLi, LFI/RFI, CSRF, SSRF, SSTI, and other web vulnerabilities.
"""

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