# modules/__init__.py

"""
WOLFSTRIKE Modules Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Root package for all WOLFSTRIKE scanning, attack,
and reconnaissance modules. Provides unified access
to all module components and shared utilities.
"""

from modules.recon import (
    SubdomainEnumerator,
    WhoisLookup,
    DNSEnumerator,
    ReverseIPLookup,
    EmailHarvester,
    SocialDiscovery,
    CloudStorageFinder,
    TechDetector,
    WAFDetector,
    CDNDetector,
    SSLAnalyzer,
    RobotsSitemap,
)

from modules.scanner import (
    PortScanner,
    ServiceDetector,
    OSFingerprint,
    HTTPMethods,
    HeaderAnalyzer,
    CookieAnalyzer,
    JSAnalyzer,
    HiddenForms,
    APIDiscovery,
    BackupFinder,
)

from modules.vuln_scanner import (
    XSSScanner,
    SQLiScanner,
    NoSQLiScanner,
    CommandInjectionScanner,
    LDAPInjectionScanner,
    XPathInjectionScanner,
    SSTIScanner,
    SSRFScanner,
    LFIRFIScanner,
    CSRFDetector,
    OpenRedirectScanner,
    FileUploadTester,
    ClickjackingDetector,
    CORSMisconfigScanner,
    SecurityMisconfigScanner,
)

from modules.attacks import (
    SQLiExploit,
    XSSExploit,
    JWTAttacker,
    DeserializationAttacker,
    RaceConditionTester,
    HostHeaderAttacker,
    CRLFInjection,
    CachePoison,
    PrototypePollution,
    CSSInjection,
)

from modules.auth_tester import (
    BruteForceTester,
    PasswordPolicyTester,
    SessionTester,
    JWTAnalyzer,
    OAuthTester,
    MFATester,
)

from modules.crawler import (
    WebSpider,
    AjaxCrawler,
    SitemapGenerator,
    LinkChecker,
    WaybackMachine,
)

from modules.api_tester import (
    RESTTester,
    GraphQLTester,
    SOAPTester,
    RateLimitTester,
    MassAssignmentTester,
    BOLATester,
    BFLATester,
)

from modules.network import (
    EmailSecurity,
    DNSSECCheck,
    ZoneTransfer,
    ASNLookup,
    BGPInfo,
)

from modules.osint import (
    ShodanAPI,
    CensysAPI,
    SecurityTrails,
    CertLogs,
    GitHubDorks,
    PastebinMonitor,
    BreachCheck,
)


__all__ = [
    # Recon
    'SubdomainEnumerator',
    'WhoisLookup',
    'DNSEnumerator',
    'ReverseIPLookup',
    'EmailHarvester',
    'SocialDiscovery',
    'CloudStorageFinder',
    'TechDetector',
    'WAFDetector',
    'CDNDetector',
    'SSLAnalyzer',
    'RobotsSitemap',
    # Scanner
    'PortScanner',
    'ServiceDetector',
    'OSFingerprint',
    'HTTPMethods',
    'HeaderAnalyzer',
    'CookieAnalyzer',
    'JSAnalyzer',
    'HiddenForms',
    'APIDiscovery',
    'BackupFinder',
    # Vulnerability Scanner
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
    # Attacks
    'SQLiExploit',
    'XSSExploit',
    'JWTAttacker',
    'DeserializationAttacker',
    'RaceConditionTester',
    'HostHeaderAttacker',
    'CRLFInjection',
    'CachePoison',
    'PrototypePollution',
    'CSSInjection',
    # Auth Tester
    'BruteForceTester',
    'PasswordPolicyTester',
    'SessionTester',
    'JWTAnalyzer',
    'OAuthTester',
    'MFATester',
    # Crawler
    'WebSpider',
    'AjaxCrawler',
    'SitemapGenerator',
    'LinkChecker',
    'WaybackMachine',
    # API Tester
    'RESTTester',
    'GraphQLTester',
    'SOAPTester',
    'RateLimitTester',
    'MassAssignmentTester',
    'BOLATester',
    'BFLATester',
    # Network
    'EmailSecurity',
    'DNSSECCheck',
    'ZoneTransfer',
    'ASNLookup',
    'BGPInfo',
    # OSINT
    'ShodanAPI',
    'CensysAPI',
    'SecurityTrails',
    'CertLogs',
    'GitHubDorks',
    'PastebinMonitor',
    'BreachCheck',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'


MODULE_CATEGORIES = {
    'recon': 'Reconnaissance',
    'scanner': 'Network & Web Scanner',
    'vuln_scanner': 'Vulnerability Scanner',
    'attacks': 'Attack & Exploitation',
    'auth_tester': 'Authentication Testing',
    'crawler': 'Web Crawler & Spider',
    'api_tester': 'API Security Testing',
    'network': 'Network Security',
    'osint': 'Open Source Intelligence',
}


def get_module_count() -> Dict[str, int]:
    """
    Get count of modules per category.
    
    Returns:
        Dictionary with category counts
    """
    return {
        'recon': 12,
        'scanner': 10,
        'vuln_scanner': 15,
        'attacks': 10,
        'auth_tester': 6,
        'crawler': 5,
        'api_tester': 7,
        'network': 5,
        'osint': 7,
    }


def get_total_modules() -> int:
    """
    Get total number of modules.
    
    Returns:
        Total module count
    """
    return sum(get_module_count().values())


def list_modules() -> Dict[str, List[str]]:
    """
    List all available modules by category.
    
    Returns:
        Dictionary with categorized module lists
    """
    return {
        'Reconnaissance': [
            'subdomain_enum', 'whois_lookup', 'dns_enum',
            'reverse_ip', 'email_harvest', 'social_discovery',
            'cloud_storage', 'tech_detect', 'waf_detect',
            'cdn_detect', 'ssl_analyzer', 'robots_sitemap',
        ],
        'Scanner': [
            'port_scanner', 'service_detect', 'os_fingerprint',
            'http_methods', 'header_analyzer', 'cookie_analyzer',
            'js_analyzer', 'hidden_forms', 'api_discovery',
            'backup_finder',
        ],
        'Vulnerability Scanner': [
            'xss_scanner', 'sqli_scanner', 'nosqli_scanner',
            'command_injection', 'ldap_injection', 'xpath_injection',
            'ssti_scanner', 'ssrf_scanner', 'lfi_rfi_scanner',
            'csrf_detect', 'open_redirect', 'file_upload',
            'clickjacking', 'cors_misconfig', 'security_misconfig',
        ],
        'Attacks': [
            'sqli_exploit', 'xss_exploit', 'jwt_attacks',
            'deserialization', 'race_condition', 'host_header',
            'crlf_injection', 'cache_poison', 'prototype_pollution',
            'css_injection',
        ],
        'Authentication Testing': [
            'brute_force', 'password_policy', 'session_tester',
            'jwt_analyzer', 'oauth_tester', 'mfa_tester',
        ],
        'Crawler': [
            'spider', 'ajax_crawler', 'sitemap_gen',
            'link_checker', 'wayback_machine',
        ],
        'API Testing': [
            'rest_tester', 'graphql_tester', 'soap_tester',
            'rate_limit', 'mass_assignment', 'bola_tester',
            'bfla_tester',
        ],
        'Network Security': [
            'email_security', 'dnssec_check', 'zone_transfer',
            'asn_lookup', 'bgp_info',
        ],
        'OSINT': [
            'shodan_api', 'censys_api', 'securitytrails',
            'cert_logs', 'github_dorks', 'pastebin_monitor',
            'breach_check',
        ],
    }