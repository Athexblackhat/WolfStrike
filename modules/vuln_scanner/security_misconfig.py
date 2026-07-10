# modules/vuln_scanner/security_misconfig.py

"""
Security Misconfiguration Scanner
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Detects common security misconfigurations including
default credentials, debug modes, and exposed admin panels.
"""

import re
from typing import Dict, List, Any, Optional

import requests
from requests.exceptions import RequestException


class SecurityMisconfigScanner:
    """
    Security misconfiguration scanner.
    
    Detects common security misconfigurations
    across web applications and servers.
    """
    
    COMMON_ADMIN_PATHS = [
        '/admin', '/administrator', '/wp-admin',
        '/phpmyadmin', '/phpMyAdmin', '/pma',
        '/manager/html', '/host-manager/html',
        '/jenkins', '/grafana', '/kibana',
        '/solr', '/solr/admin', '/actuator',
        '/swagger-ui.html', '/api-docs',
        '/.env', '/.git/config', '/.git/HEAD',
        '/server-status', '/server-info',
        '/console', '/web-console',
    ]
    
    DEBUG_INDICATORS = [
        (r'DEBUG\s*=\s*True', 'Django Debug Mode'),
        (r'APP_DEBUG\s*=\s*true', 'Laravel Debug Mode'),
        (r'Whoops, looks like something went wrong', 'Laravel Debug'),
        (r'Stack trace:', 'Stack Trace'),
        (r'Traceback \(most recent call last\):', 'Python Traceback'),
        (r'Fatal error:', 'PHP Error'),
        (r'Exception in', 'Exception Details'),
        (r'at \S+\.\w+:\d+', 'Source Reference'),
    ]
    
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('user', 'user'),
        ('guest', 'guest'),
        ('test', 'test'),
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the security misconfig scanner.
        
        Args:
            target: Target URL
            config: Configuration dictionary
        """
        self.target = target.rstrip('/')
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def check_admin_panels(self) -> List[Dict[str, Any]]:
        """
        Check for exposed admin panels.
        
        Returns:
            List of discovered admin panel dictionaries
        """
        discovered = []
        
        for path in self.COMMON_ADMIN_PATHS:
            url = f"{self.target}{path}"
            
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 301, 302, 401, 403]:
                    discovered.append({
                        'url': url,
                        'path': path,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                    })
                    
            except RequestException:
                continue
        
        return discovered
    
    def check_debug_mode(self) -> List[Dict[str, Any]]:
        """
        Check for debug mode indicators.
        
        Returns:
            List of debug mode findings
        """
        findings = []
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            for pattern, description in self.DEBUG_INDICATORS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    findings.append({
                        'url': self.target,
                        'debug_type': description,
                        'pattern': pattern,
                    })
                    
        except RequestException:
            pass
        
        return findings
    
    def check_default_credentials(self, login_url: str) -> List[Dict[str, Any]]:
        """
        Check for default credentials on login page.
        
        Args:
            login_url: Login page URL
            
        Returns:
            List of credential findings
        """
        findings = []
        
        from bs4 import BeautifulSoup
        
        try:
            response = self.session.get(login_url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input')
                username_field = ''
                password_field = ''
                
                for inp in inputs:
                    inp_type = inp.get('type', 'text')
                    inp_name = inp.get('name', '')
                    
                    if inp_type in ['text', 'email'] and not username_field:
                        username_field = inp_name
                    elif inp_type == 'password' and not password_field:
                        password_field = inp_name
                
                if username_field and password_field:
                    action = form.get('action', '')
                    form_url = login_url if not action else (
                        action if action.startswith('http') else login_url.rstrip('/') + '/' + action.lstrip('/')
                    )
                    
                    for username, password in self.DEFAULT_CREDENTIALS[:3]:
                        data = {username_field: username, password_field: password}
                        
                        try:
                            login_response = self.session.post(
                                form_url,
                                data=data,
                                timeout=self.timeout,
                                verify=self.verify_ssl,
                                allow_redirects=False
                            )
                            
                            if login_response.status_code in [200, 302]:
                                success_indicators = [
                                    'welcome', 'dashboard', 'logout',
                                    'successfully logged', 'profile',
                                ]
                                
                                if any(ind in login_response.text.lower() for ind in success_indicators):
                                    findings.append({
                                        'url': form_url,
                                        'username': username,
                                        'password': password,
                                    })
                                    break
                                    
                        except RequestException:
                            continue
        
        except RequestException:
            pass
        
        return findings
    
    def run(self) -> Dict[str, Any]:
        """
        Run security misconfiguration scan.
        
        Returns:
            Dictionary with scan results
        """
        admin_panels = self.check_admin_panels()
        debug_modes = self.check_debug_mode()
        
        login_urls = [
            f"{self.target}/login",
            f"{self.target}/admin/login",
        ]
        
        cred_findings = []
        for login_url in login_urls:
            findings = self.check_default_credentials(login_url)
            cred_findings.extend(findings)
        
        findings = []
        
        if admin_panels:
            findings.append({
                'type': 'Exposed Admin Panels',
                'severity': 'high',
                'target': self.target,
                'description': f'Found {len(admin_panels)} exposed admin/management panels',
                'evidence': admin_panels,
                'remediation': 'Restrict access to admin panels. Use IP whitelisting and VPN.',
            })
        
        if debug_modes:
            findings.append({
                'type': 'Debug Mode Enabled',
                'severity': 'high',
                'target': self.target,
                'description': f'Debug mode or error reporting enabled: {debug_modes[0]["debug_type"]}',
                'evidence': debug_modes,
                'remediation': 'Disable debug mode in production. Configure custom error pages.',
            })
        
        if cred_findings:
            findings.append({
                'type': 'Default Credentials',
                'severity': 'critical',
                'target': self.target,
                'description': f'Login successful with default credentials: '
                               f'{cred_findings[0]["username"]}:{cred_findings[0]["password"]}',
                'evidence': cred_findings,
                'remediation': 'Change default credentials immediately. Implement strong password policy.',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'admin_panels': len(admin_panels),
            'debug_modes': len(debug_modes),
            'default_creds': len(cred_findings),
            'vulnerabilities_found': len(findings),
        }