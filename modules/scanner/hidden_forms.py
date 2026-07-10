# modules/scanner/hidden_forms.py

"""
Hidden Form Field Analyzer
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Discovers hidden form fields that may contain sensitive
information or reveal internal application logic.
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


class HiddenForms:
    """
    Hidden form field analyzer.
    
    Discovers hidden inputs in HTML forms that may
    expose sensitive data or internal parameters.
    """
    
    SENSITIVE_FIELD_NAMES = [
        'admin', 'role', 'level', 'price', 'cost',
        'discount', 'credit', 'token', 'csrf',
        'user_id', 'account_id', 'debug', 'test',
        'internal', 'secret', 'key', 'hash',
        'return_url', 'redirect', 'callback',
    ]
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the hidden form analyzer.
        
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
        
        self.forms: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def analyze_page(self, url: str) -> List[Dict[str, Any]]:
        """
        Analyze a page for hidden form fields.
        
        Args:
            url: Page URL
            
        Returns:
            List of form dictionaries with hidden fields
        """
        forms = []
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'page_url': url,
                    'hidden_fields': [],
                    'sensitive_fields': [],
                }
                
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', 'text').lower()
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')
                    
                    if input_type == 'hidden':
                        field_info = {
                            'name': input_name,
                            'value': input_value,
                            'value_length': len(input_value),
                        }
                        
                        form_data['hidden_fields'].append(field_info)
                        
                        for sensitive_name in self.SENSITIVE_FIELD_NAMES:
                            if sensitive_name in input_name.lower():
                                form_data['sensitive_fields'].append(field_info)
                                break
                        
                        if len(input_value) > 32:
                            form_data['sensitive_fields'].append(field_info)
                
                if form_data['hidden_fields']:
                    forms.append(form_data)
            
        except RequestException as e:
            self.errors.append(f"Page analysis failed: {str(e)}")
        
        return forms
    
    def run(self) -> Dict[str, Any]:
        """
        Run hidden form analysis.
        
        Returns:
            Dictionary with analysis results
        """
        common_paths = [
            self.target,
            f"{self.target}/login",
            f"{self.target}/register",
            f"{self.target}/checkout",
            f"{self.target}/cart",
        ]
        
        for path in common_paths:
            forms = self.analyze_page(path)
            self.forms.extend(forms)
        
        findings = []
        
        all_hidden_fields = []
        all_sensitive_fields = []
        
        for form in self.forms:
            all_hidden_fields.extend(form['hidden_fields'])
            all_sensitive_fields.extend(form['sensitive_fields'])
        
        if all_sensitive_fields:
            findings.append({
                'type': 'Sensitive Hidden Form Fields',
                'severity': 'medium',
                'target': self.target,
                'description': f'Found {len(all_sensitive_fields)} potentially sensitive hidden fields',
                'evidence': all_sensitive_fields[:10],
                'remediation': 'Do not rely on hidden fields for security. Validate all input server-side.',
            })
        
        if all_hidden_fields:
            findings.append({
                'type': 'Hidden Form Fields Discovered',
                'severity': 'info',
                'target': self.target,
                'description': f'Found {len(all_hidden_fields)} hidden form fields across {len(self.forms)} forms',
                'evidence': self.forms[:5],
                'remediation': 'Review hidden fields for security implications',
            })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'target': self.target,
            'forms': self.forms,
            'total_forms': len(self.forms),
            'total_hidden_fields': len(all_hidden_fields),
        }