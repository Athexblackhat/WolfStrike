# ai_engine/false_positive.py

"""
False Positive Detection and Filtering Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Intelligent false positive detection system that validates
vulnerability findings through multiple verification methods
to ensure high accuracy reporting.
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class VerificationMethod(Enum):
    """Methods for verifying vulnerability findings."""
    RESPONSE_COMPARISON = "response_comparison"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PATTERN_REPETITION = "pattern_repetition"
    CONTEXT_VALIDATION = "context_validation"
    HEADER_ANALYSIS = "header_analysis"
    STATUS_CODE_CHECK = "status_code_check"
    CONTENT_TYPE_CHECK = "content_type_check"
    ERROR_CORRELATION = "error_correlation"
    HEURISTIC_SCORING = "heuristic_scoring"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Finding:
    """Represents a vulnerability finding before verification."""
    finding_id: str
    vulnerability_type: str
    severity: Severity
    description: str
    endpoint: str
    payload: str
    response_text: str
    status_code: int
    headers: Dict[str, str]
    confidence_score: float
    verification_results: Dict[str, Any] = field(default_factory=dict)
    is_validated: bool = False
    validation_notes: List[str] = field(default_factory=list)


@dataclass
class VerifiedFinding:
    """Represents a verified vulnerability finding."""
    original_finding: Finding
    is_false_positive: bool
    adjusted_severity: Severity
    confidence_score: float
    verification_evidence: List[str]
    recommendation: str


class FalsePositiveFilter:
    """
    Advanced false positive detection and filtering engine.
    
    Validates vulnerability findings using multiple verification
    methods to minimize false positives and ensure accurate results.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the false positive filter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.strict_mode = self.config.get('strict_mode', False)
        self.min_confidence_threshold = self.config.get('min_confidence', 0.7)
        self.verification_attempts = self.config.get('verification_attempts', 3)
        self.enable_learning = self.config.get('enable_learning', True)
        
        self.verified_findings: List[VerifiedFinding] = []
        self.false_positive_patterns: List[Dict[str, Any]] = []
        self.verification_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        self._initialize_false_positive_patterns()
    
    def _initialize_false_positive_patterns(self) -> None:
        """Initialize known false positive patterns."""
        
        self.false_positive_patterns = [
            {
                'type': 'error_page_template',
                'pattern': r'(?:error|exception|warning).*?(?:occurred|encountered)',
                'context_required': True,
                'description': 'Generic error page template'
            },
            {
                'type': 'debug_disabled',
                'pattern': r'debug\s*=\s*false|display_errors\s*=\s*off',
                'context_required': False,
                'description': 'Debug mode is actually disabled'
            },
            {
                'type': 'sanitized_output',
                'pattern': r'&lt;script&gt;|&amp;lt;script&amp;gt;',
                'context_required': False,
                'description': 'Output is properly sanitized'
            },
            {
                'type': 'static_error_page',
                'pattern': r'The page you are looking for.*?cannot be found',
                'context_required': True,
                'description': 'Static 404 error page'
            },
            {
                'type': 'echo_back_safe',
                'pattern': r'Your search for &quot;.*?&quot; returned',
                'context_required': True,
                'description': 'Safe echo back in search results'
            },
        ]
    
    def verify_finding(
        self,
        finding: Finding,
        original_response: str,
        test_response: str,
        test_headers: Dict[str, str],
        test_status: int
    ) -> VerifiedFinding:
        """
        Verify a single vulnerability finding.
        
        Args:
            finding: The vulnerability finding to verify
            original_response: Response before payload injection
            test_response: Response after payload injection
            test_headers: Response headers after injection
            test_status: Status code after injection
            
        Returns:
            VerifiedFinding with validation results
        """
        is_false_positive = False
        verification_evidence: List[str] = []
        confidence_adjustment = 0.0
        
        response_check = self._verify_response_comparison(
            original_response, test_response, finding
        )
        verification_evidence.append(f"Response comparison: {response_check['result']}")
        if response_check['is_suspicious']:
            confidence_adjustment -= 0.15
        
        status_check = self._verify_status_code(test_status, finding)
        verification_evidence.append(f"Status code check: {status_check['result']}")
        if status_check['is_suspicious']:
            confidence_adjustment -= 0.10
        
        header_check = self._verify_headers(test_headers, finding)
        verification_evidence.append(f"Header analysis: {header_check['result']}")
        if header_check['is_suspicious']:
            confidence_adjustment -= 0.10
        
        content_check = self._verify_content_type(test_headers, finding)
        verification_evidence.append(f"Content type check: {content_check['result']}")
        if content_check['is_suspicious']:
            confidence_adjustment -= 0.05
        
        pattern_check = self._verify_pattern_repetition(test_response, finding)
        verification_evidence.append(f"Pattern repetition: {pattern_check['result']}")
        if pattern_check['is_suspicious']:
            confidence_adjustment -= 0.10
        
        context_check = self._verify_context(test_response, finding)
        verification_evidence.append(f"Context validation: {context_check['result']}")
        if context_check['is_suspicious']:
            confidence_adjustment -= 0.15
        
        heuristic_check = self._heuristic_scoring(
            finding, response_check, status_check, header_check,
            content_check, pattern_check, context_check
        )
        verification_evidence.append(f"Heuristic scoring: {heuristic_check['result']}")
        
        adjusted_confidence = finding.confidence_score + confidence_adjustment
        adjusted_confidence = max(0.0, min(1.0, adjusted_confidence))
        
        if adjusted_confidence < self.min_confidence_threshold or heuristic_check['is_false_positive']:
            is_false_positive = True
        
        adjusted_severity = self._adjust_severity(
            finding.severity,
            adjusted_confidence,
            is_false_positive
        )
        
        verified = VerifiedFinding(
            original_finding=finding,
            is_false_positive=is_false_positive,
            adjusted_severity=adjusted_severity,
            confidence_score=adjusted_confidence,
            verification_evidence=verification_evidence,
            recommendation=self._generate_recommendation(finding, is_false_positive)
        )
        
        self.verified_findings.append(verified)
        
        if self.enable_learning:
            self._record_verification(finding.vulnerability_type, is_false_positive)
        
        return verified
    
    def _verify_response_comparison(
        self,
        original: str,
        test: str,
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Compare original and test responses for significant differences.
        
        Args:
            original: Original response text
            test: Test response text after payload
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        if not original or not test:
            return {
                'result': 'Cannot compare - missing response data',
                'is_suspicious': True
            }
        
        original_length = len(original)
        test_length = len(test)
        
        if original_length == 0:
            return {
                'result': 'Original response empty',
                'is_suspicious': True
            }
        
        length_diff_percent = abs(test_length - original_length) / original_length * 100
        
        if length_diff_percent < 1.0:
            return {
                'result': f'Minimal difference ({length_diff_percent:.1f}%)',
                'is_suspicious': True,
                'detail': 'Responses are nearly identical - possible false positive'
            }
        elif length_diff_percent > 90.0:
            return {
                'result': f'Excessive difference ({length_diff_percent:.1f}%)',
                'is_suspicious': False,
                'detail': 'Significant response change indicates real vulnerability'
            }
        else:
            return {
                'result': f'Moderate difference ({length_diff_percent:.1f}%)',
                'is_suspicious': False,
                'detail': 'Expected response variation'
            }
    
    def _verify_status_code(
        self,
        status_code: int,
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Verify if status code indicates a real vulnerability.
        
        Args:
            status_code: HTTP status code from test
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        if status_code == 200:
            return {
                'result': 'Status 200 OK - potential valid finding',
                'is_suspicious': False
            }
        elif status_code in [301, 302, 303, 307, 308]:
            return {
                'result': f'Redirect status {status_code} - possible filter evasion',
                'is_suspicious': True
            }
        elif status_code == 403:
            return {
                'result': '403 Forbidden - payload blocked by WAF',
                'is_suspicious': True
            }
        elif status_code == 404:
            return {
                'result': '404 Not Found - endpoint does not process input',
                'is_suspicious': True
            }
        elif status_code >= 500:
            return {
                'result': f'Server error {status_code} - potential successful injection',
                'is_suspicious': False
            }
        else:
            return {
                'result': f'Unexpected status {status_code}',
                'is_suspicious': False
            }
    
    def _verify_headers(
        self,
        headers: Dict[str, str],
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Analyze response headers for verification clues.
        
        Args:
            headers: Response headers
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        suspicious_headers = 0
        
        waf_headers = ['x-sucuri-id', 'x-cdn', 'cf-ray', 'x-amz-cf-id', 'x-waf']
        for header in waf_headers:
            if header.lower() in [k.lower() for k in headers.keys()]:
                suspicious_headers += 1
        
        error_headers = ['x-debug-token', 'x-debug-token-link', 'x-exception']
        for header in error_headers:
            if header.lower() in [k.lower() for k in headers.keys()]:
                suspicious_headers -= 1
        
        if suspicious_headers > 0:
            return {
                'result': f'WAF/security headers detected ({suspicious_headers})',
                'is_suspicious': True
            }
        elif suspicious_headers < 0:
            return {
                'result': 'Debug/error headers detected - likely real vulnerability',
                'is_suspicious': False
            }
        else:
            return {
                'result': 'No suspicious headers detected',
                'is_suspicious': False
            }
    
    def _verify_content_type(
        self,
        headers: Dict[str, str],
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Verify content type matches expected vulnerability output.
        
        Args:
            headers: Response headers
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        content_type = headers.get('content-type', '').lower()
        
        error_content_types = ['text/html', 'application/json', 'text/plain']
        
        if not content_type:
            return {
                'result': 'No content type header',
                'is_suspicious': True
            }
        
        if content_type in error_content_types:
            return {
                'result': f'Standard content type: {content_type}',
                'is_suspicious': False
            }
        else:
            return {
                'result': f'Unusual content type: {content_type}',
                'is_suspicious': True
            }
    
    def _verify_pattern_repetition(
        self,
        response: str,
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Check if finding appears multiple times (common false positive).
        
        Args:
            response: Test response text
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        for fp_pattern in self.false_positive_patterns:
            pattern = fp_pattern['pattern']
            try:
                matches = re.findall(pattern, response, re.IGNORECASE)
                if len(matches) > 5:
                    return {
                        'result': f'Pattern repeated {len(matches)} times - likely template',
                        'is_suspicious': True,
                        'matched_pattern': fp_pattern['description']
                    }
            except re.error:
                continue
        
        return {
            'result': 'No suspicious pattern repetition detected',
            'is_suspicious': False
        }
    
    def _verify_context(
        self,
        response: str,
        finding: Finding
    ) -> Dict[str, Any]:
        """
        Verify the context of the finding in the response.
        
        Args:
            response: Test response text
            finding: The vulnerability finding
            
        Returns:
            Dictionary with verification result
        """
        payload_escaped = re.escape(finding.payload[:50])
        
        try:
            if re.search(payload_escaped, response, re.IGNORECASE):
                return {
                    'result': 'Payload reflected in response - potential real finding',
                    'is_suspicious': False
                }
        except re.error:
            pass
        
        error_indicators = [
            r'(?:error|exception|warning|notice|fatal)',
            r'(?:stack trace|traceback)',
            r'(?:syntax error|parse error)',
            r'(?:undefined|unexpected|unrecognized)',
        ]
        
        indicator_count = 0
        for indicator in error_indicators:
            try:
                if re.search(indicator, response, re.IGNORECASE):
                    indicator_count += 1
            except re.error:
                continue
        
        if indicator_count >= 2:
            return {
                'result': f'Multiple error indicators found ({indicator_count})',
                'is_suspicious': False
            }
        
        return {
            'result': 'No contextual indicators of vulnerability',
            'is_suspicious': True
        }
    
    def _heuristic_scoring(
        self,
        finding: Finding,
        response_check: Dict[str, Any],
        status_check: Dict[str, Any],
        header_check: Dict[str, Any],
        content_check: Dict[str, Any],
        pattern_check: Dict[str, Any],
        context_check: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply heuristic scoring to determine if finding is false positive.
        
        Args:
            finding: The vulnerability finding
            response_check: Response comparison results
            status_check: Status code check results
            header_check: Header analysis results
            content_check: Content type check results
            pattern_check: Pattern repetition results
            context_check: Context validation results
            
        Returns:
            Dictionary with heuristic scoring result
        """
        suspicious_score = 0
        
        if response_check.get('is_suspicious', False):
            suspicious_score += 2
        if status_check.get('is_suspicious', False):
            suspicious_score += 2
        if header_check.get('is_suspicious', False):
            suspicious_score += 1
        if content_check.get('is_suspicious', False):
            suspicious_score += 1
        if pattern_check.get('is_suspicious', False):
            suspicious_score += 2
        if context_check.get('is_suspicious', False):
            suspicious_score += 2
        
        is_false_positive = suspicious_score >= 6 if self.strict_mode else suspicious_score >= 8
        
        return {
            'result': f'Heuristic score: {suspicious_score}/10',
            'suspicious_score': suspicious_score,
            'is_false_positive': is_false_positive
        }
    
    def _adjust_severity(
        self,
        original_severity: Severity,
        confidence: float,
        is_false_positive: bool
    ) -> Severity:
        """
        Adjust severity based on verification results.
        
        Args:
            original_severity: Original severity level
            confidence: Adjusted confidence score
            is_false_positive: Whether finding is false positive
            
        Returns:
            Adjusted severity level
        """
        if is_false_positive:
            return Severity.FALSE_POSITIVE
        
        if confidence < 0.5:
            return Severity.INFO
        elif confidence < 0.7:
            return Severity.LOW
        elif confidence < 0.85:
            return Severity.MEDIUM
        elif confidence < 0.95:
            return Severity.HIGH
        else:
            return Severity.CRITICAL
    
    def _generate_recommendation(
        self,
        finding: Finding,
        is_false_positive: bool
    ) -> str:
        """
        Generate recommendation based on verification result.
        
        Args:
            finding: The vulnerability finding
            is_false_positive: Whether finding is false positive
            
        Returns:
            Recommendation string
        """
        if is_false_positive:
            return f"Finding flagged as false positive. No action required for {finding.vulnerability_type}."
        
        recommendations = {
            'sqli': "Implement parameterized queries and input validation.",
            'xss': "Implement output encoding and Content-Security-Policy headers.",
            'lfi': "Use whitelist for file inclusion and validate user input.",
            'rfi': "Disable remote file inclusion in PHP configuration.",
            'command_injection': "Use parameterized system calls and input sanitization.",
            'csrf': "Implement anti-CSRF tokens on all state-changing requests.",
            'ssrf': "Implement URL whitelist and disable internal network access.",
            'ssti': "Use sandboxed template engines and avoid user input in templates.",
            'xxe': "Disable external entity processing in XML parsers.",
            'idor': "Implement proper access controls and use indirect references.",
        }
        
        for key, recommendation in recommendations.items():
            if key in finding.vulnerability_type.lower():
                return recommendation
        
        return "Review and fix the identified vulnerability following security best practices."
    
    def _record_verification(
        self,
        vulnerability_type: str,
        is_false_positive: bool
    ) -> None:
        """
        Record verification result for learning.
        
        Args:
            vulnerability_type: Type of vulnerability
            is_false_positive: Whether it was false positive
        """
        self.verification_history[vulnerability_type].append({
            'is_false_positive': is_false_positive,
            'timestamp': None
        })
    
    def get_false_positive_rate(self) -> Dict[str, float]:
        """
        Calculate false positive rate by vulnerability type.
        
        Returns:
            Dictionary with false positive rates
        """
        rates: Dict[str, float] = {}
        
        for vuln_type, history in self.verification_history.items():
            if not history:
                continue
            
            total = len(history)
            false_positives = sum(1 for h in history if h['is_false_positive'])
            rates[vuln_type] = (false_positives / total) * 100
        
        return rates
    
    def get_verified_findings(
        self,
        include_false_positives: bool = False
    ) -> List[VerifiedFinding]:
        """
        Get all verified findings.
        
        Args:
            include_false_positives: Whether to include false positives
            
        Returns:
            List of verified findings
        """
        if include_false_positives:
            return self.verified_findings
        
        return [
            finding for finding in self.verified_findings
            if not finding.is_false_positive
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get verification statistics.
        
        Returns:
            Dictionary with statistics
        """
        total = len(self.verified_findings)
        if total == 0:
            return {
                'total_verified': 0,
                'false_positives': 0,
                'confirmed_vulnerabilities': 0,
                'false_positive_rate': 0.0,
                'by_severity': {}
            }
        
        false_positives = sum(1 for f in self.verified_findings if f.is_false_positive)
        confirmed = total - false_positives
        
        severity_counts = defaultdict(int)
        for finding in self.verified_findings:
            severity_counts[finding.adjusted_severity.value] += 1
        
        return {
            'total_verified': total,
            'false_positives': false_positives,
            'confirmed_vulnerabilities': confirmed,
            'false_positive_rate': (false_positives / total) * 100 if total > 0 else 0,
            'by_severity': dict(severity_counts)
        }
    
    def reset(self) -> None:
        """Reset all verification data."""
        self.verified_findings.clear()
        self.verification_history.clear()