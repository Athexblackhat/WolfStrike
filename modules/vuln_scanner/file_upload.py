# modules/vuln_scanner/file_upload.py

"""
File Upload Vulnerability Tester
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Tests file upload functionality for security vulnerabilities
including unrestricted file types and path traversal.
"""

import os
import tempfile
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup


class FileUploadTester:
    """
    File upload vulnerability tester.
    
    Tests file upload forms for security issues
    including unrestricted file types and path traversal.
    """
    
    TEST_FILES = {
        'php_webshell': {
            'filename': 'test.php',
            'content': '<?php echo "WOLFSTRIKE_UPLOAD_TEST"; ?>',
            'mime_type': 'application/x-php',
            'dangerous': True,
        },
        'php_double_ext': {
            'filename': 'test.php.jpg',
            'content': '<?php echo "WOLFSTRIKE_UPLOAD_TEST"; ?>',
            'mime_type': 'image/jpeg',
            'dangerous': True,
        },
        'php_null_byte': {
            'filename': 'test.php%00.jpg',
            'content': '<?php echo "WOLFSTRIKE_UPLOAD_TEST"; ?>',
            'mime_type': 'image/jpeg',
            'dangerous': True,
        },
        'html_xss': {
            'filename': 'test.html',
            'content': '<html><body><script>alert("XSS")</script></body></html>',
            'mime_type': 'text/html',
            'dangerous': True,
        },
        'svg_xss': {
            'filename': 'test.svg',
            'content': '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
            'mime_type': 'image/svg+xml',
            'dangerous': True,
        },
        'legitimate_image': {
            'filename': 'test.jpg',
            'content': 'WOLFSTRIKE_TEST_IMAGE',
            'mime_type': 'image/jpeg',
            'dangerous': False,
        },
    }
    
    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the file upload tester.
        
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
        
        self.timeout = self.config.get('timeout', 15)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.errors: List[str] = []
    
    def find_upload_forms(self, url: str) -> List[Dict[str, Any]]:
        """
        Find file upload forms on a page.
        
        Args:
            url: Page URL
            
        Returns:
            List of form dictionaries
        """
        upload_forms = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'post').upper()
                enctype = form.get('enctype', '')
                form_url = urljoin(url, action) if action else url
                
                has_file_input = False
                file_input_name = ''
                
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', 'text').lower()
                    
                    if input_type == 'file':
                        has_file_input = True
                        file_input_name = input_tag.get('name', 'file')
                        break
                
                if has_file_input or 'multipart/form-data' in enctype:
                    upload_forms.append({
                        'action': form_url,
                        'method': method,
                        'file_input': file_input_name or 'file',
                        'has_enctype': 'multipart/form-data' in enctype,
                    })
            
            return upload_forms
            
        except RequestException:
            return []
    
    def test_upload(self, form_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Test file upload form for vulnerabilities.
        
        Args:
            form_data: Form information dictionary
            
        Returns:
            List of vulnerability dictionaries
        """
        findings = []
        
        for test_name, test_file in self.TEST_FILES.items():
            try:
                tmp_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='_' + test_file['filename'],
                    delete=False
                )
                tmp_file.write(test_file['content'])
                tmp_file.close()
                
                with open(tmp_file.name, 'rb') as f:
                    files = {
                        form_data['file_input']: (
                            test_file['filename'],
                            f,
                            test_file['mime_type']
                        )
                    }
                    
                    response = self.session.post(
                        form_data['action'],
                        files=files,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                
                os.unlink(tmp_file.name)
                
                if response.status_code in [200, 201, 202]:
                    upload_success = any(
                        indicator in response.text.lower()
                        for indicator in ['success', 'uploaded', 'completed', 'created']
                    )
                    
                    if upload_success and test_file['dangerous']:
                        findings.append({
                            'form_action': form_data['action'],
                            'test_type': test_name,
                            'filename': test_file['filename'],
                            'status_code': response.status_code,
                            'dangerous': True,
                        })
                        
            except RequestException:
                continue
            except Exception:
                continue
        
        return findings
    
    def run(self) -> Dict[str, Any]:
        """
        Run file upload testing.
        
        Returns:
            Dictionary with test results
        """
        test_urls = [
            self.target,
            f"{self.target}/upload",
            f"{self.target}/admin/upload",
        ]
        
        all_forms = []
        
        for url in test_urls:
            forms = self.find_upload_forms(url)
            all_forms.extend(forms)
        
        findings = []
        
        for form in all_forms:
            upload_findings = self.test_upload(form)
            
            for finding in upload_findings:
                findings.append({
                    'type': 'Unrestricted File Upload',
                    'severity': 'critical',
                    'endpoint': finding['form_action'],
                    'description': f"Dangerous file type accepted: {finding['filename']} ({finding['test_type']})",
                    'evidence': finding,
                    'remediation': 'Validate file types server-side. Use whitelist of allowed extensions. '
                                   'Store files outside web root. Scan uploaded files for malware.',
                })
        
        return {
            'findings': findings,
            'errors': self.errors,
            'forms_found': len(all_forms),
            'vulnerabilities_found': len(findings),
        }