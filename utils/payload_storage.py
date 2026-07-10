# utils/payload_storage.py

"""
Payload Storage Manager
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Manages payload collections for various vulnerability
types with categorization and retrieval functions.
"""

import json
import os
from typing import Dict, List, Any, Optional, Set


class PayloadStorage:
    """
    Payload storage and management utility.
    
    Organizes payloads by vulnerability type with
    functions for loading, saving, and retrieval.
    """
    
    PAYLOAD_CATEGORIES = [
        'xss', 'sqli', 'nosqli', 'lfi', 'rfi',
        'ssrf', 'ssti', 'xxe', 'command_injection',
        'ldap_injection', 'xpath_injection',
        'crlf_injection', 'header_injection',
        'file_upload', 'open_redirect',
        'jwt_attacks', 'deserialization',
        'prototype_pollution', 'css_injection',
    ]
    
    DEFAULT_PAYLOADS = {
        'xss': [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ],
        'sqli': [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL--",
        ],
        'lfi': [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
        ],
    }
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the payload storage.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.payloads: Dict[str, List[str]] = {}
        self.payload_dir = self.config.get('payload_dir', 'wordlists')
        
        self._load_defaults()
        self._load_from_files()
    
    def _load_defaults(self) -> None:
        """Load default payload collections."""
        for category, payload_list in self.DEFAULT_PAYLOADS.items():
            if category not in self.payloads:
                self.payloads[category] = []
            self.payloads[category].extend(payload_list)
    
    def _load_from_files(self) -> None:
        """Load payloads from wordlist files."""
        if not os.path.isdir(self.payload_dir):
            return
        
        for category in self.PAYLOAD_CATEGORIES:
            filename = os.path.join(self.payload_dir, f'{category}_payloads.txt')
            
            if os.path.isfile(filename):
                try:
                    with open(filename, 'r') as f:
                        lines = [
                            line.strip()
                            for line in f
                            if line.strip() and not line.strip().startswith('#')
                        ]
                        
                        if category not in self.payloads:
                            self.payloads[category] = []
                        
                        self.payloads[category].extend(lines)
                except (IOError, UnicodeDecodeError):
                    pass
    
    def get_payloads(self, category: str) -> List[str]:
        """
        Get payloads for a category.
        
        Args:
            category: Payload category name
            
        Returns:
            List of payload strings
        """
        return self.payloads.get(category, [])
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """
        Get all payloads.
        
        Returns:
            Dictionary of all payloads by category
        """
        return self.payloads.copy()
    
    def add_payload(self, category: str, payload: str) -> bool:
        """
        Add a payload to a category.
        
        Args:
            category: Payload category
            payload: Payload string
            
        Returns:
            True if added
        """
        if category not in self.payloads:
            self.payloads[category] = []
        
        if payload not in self.payloads[category]:
            self.payloads[category].append(payload)
            return True
        
        return False
    
    def add_payloads(self, category: str, payloads: List[str]) -> int:
        """
        Add multiple payloads to a category.
        
        Args:
            category: Payload category
            payloads: List of payload strings
            
        Returns:
            Number of payloads added
        """
        added = 0
        
        for payload in payloads:
            if self.add_payload(category, payload):
                added += 1
        
        return added
    
    def remove_payload(self, category: str, payload: str) -> bool:
        """
        Remove a payload from a category.
        
        Args:
            category: Payload category
            payload: Payload to remove
            
        Returns:
            True if removed
        """
        if category in self.payloads and payload in self.payloads[category]:
            self.payloads[category].remove(payload)
            return True
        
        return False
    
    def clear_category(self, category: str) -> None:
        """
        Clear all payloads in a category.
        
        Args:
            category: Payload category to clear
        """
        if category in self.payloads:
            self.payloads[category] = []
    
    def save_to_file(self, category: str, filename: Optional[str] = None) -> bool:
        """
        Save payloads for a category to file.
        
        Args:
            category: Payload category
            filename: Output filename
            
        Returns:
            True if saved successfully
        """
        if filename is None:
            filename = os.path.join(self.payload_dir, f'{category}_payloads.txt')
        
        if category not in self.payloads:
            return False
        
        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, 'w') as f:
                f.write(f'# WOLFSTRIKE {category.upper()} Payloads\n')
                f.write(f'# Total: {len(self.payloads[category])}\n\n')
                
                for payload in self.payloads[category]:
                    f.write(f'{payload}\n')
            
            return True
            
        except IOError:
            return False
    
    def export_json(self, filename: str) -> bool:
        """
        Export all payloads to JSON file.
        
        Args:
            filename: Output JSON filename
            
        Returns:
            True if exported successfully
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.payloads, f, indent=2)
            
            return True
            
        except IOError:
            return False
    
    def import_json(self, filename: str) -> bool:
        """
        Import payloads from JSON file.
        
        Args:
            filename: Input JSON filename
            
        Returns:
            True if imported successfully
        """
        try:
            with open(filename, 'r') as f:
                imported = json.load(f)
            
            for category, payloads in imported.items():
                if isinstance(payloads, list):
                    self.add_payloads(category, payloads)
            
            return True
            
        except (IOError, json.JSONDecodeError):
            return False
    
    def get_categories(self) -> List[str]:
        """
        Get list of available categories.
        
        Returns:
            List of category names
        """
        return list(self.payloads.keys())
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get payload storage statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_payloads = sum(len(v) for v in self.payloads.values())
        
        return {
            'total_categories': len(self.payloads),
            'total_payloads': total_payloads,
            'categories': {
                cat: len(payloads)
                for cat, payloads in self.payloads.items()
            },
        }