# ai_engine/pattern_recognition.py

"""
Pattern Recognition Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Machine learning based pattern detection for identifying
vulnerability signatures in HTTP responses.
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class PatternType(Enum):
    """Types of patterns that can be detected."""
    ERROR_MESSAGE = "error_message"
    FILE_PATH = "file_path"
    SQL_FRAGMENT = "sql_fragment"
    CODE_SNIPPET = "code_snippet"
    STACK_TRACE = "stack_trace"
    DATABASE_OUTPUT = "database_output"
    DEBUG_INFO = "debug_info"
    CONFIG_LEAK = "config_leak"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    API_KEY = "api_key"


@dataclass
class PatternMatch:
    """Represents a matched pattern in response data."""
    pattern_type: PatternType
    pattern_name: str
    matched_text: str
    confidence: float
    line_number: Optional[int] = None
    context: Optional[str] = None
    suggestion: Optional[str] = None


@dataclass
class PatternSignature:
    """Defines a pattern signature for detection."""
    name: str
    pattern_type: PatternType
    regex: str
    confidence: float
    description: str
    suggestion: str
    case_sensitive: bool = False


class PatternRecognition:
    """
    Advanced pattern recognition engine for vulnerability detection.
    
    Uses regex-based pattern matching combined with heuristics
    to identify potential security issues in HTTP responses.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the pattern recognition engine.
        
        Args:
            config: Configuration dictionary with optional settings
        """
        self.config = config or {}
        self.min_confidence = self.config.get('min_confidence', 0.6)
        self.max_context_lines = self.config.get('max_context_lines', 3)
        self.enable_learning = self.config.get('enable_learning', True)
        
        self.patterns: List[PatternSignature] = []
        self.match_history: List[PatternMatch] = []
        self.learned_patterns: Dict[str, int] = defaultdict(int)
        
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize the built-in pattern signatures."""
        
        self.patterns = [
            PatternSignature(
                name="mysql_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"MySQL\s+(error|Exception|Warning).*?:\s*(.+)",
                confidence=0.95,
                description="MySQL database error detected",
                suggestion="Check for SQL injection vulnerability"
            ),
            PatternSignature(
                name="postgresql_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"PostgreSQL.*?ERROR:?\s*(.+)",
                confidence=0.95,
                description="PostgreSQL database error detected",
                suggestion="Check for SQL injection vulnerability"
            ),
            PatternSignature(
                name="mssql_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"Microsoft OLE DB Provider for (SQL Server|ODBC Drivers).*?error",
                confidence=0.95,
                description="MSSQL database error detected",
                suggestion="Check for SQL injection vulnerability"
            ),
            PatternSignature(
                name="oracle_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"ORA-\d{5}.*?:?\s*(.+)",
                confidence=0.95,
                description="Oracle database error detected",
                suggestion="Check for SQL injection vulnerability"
            ),
            PatternSignature(
                name="sqlite_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"SQLite.*?error.*?:?\s*(.+)",
                confidence=0.90,
                description="SQLite database error detected",
                suggestion="Check for SQL injection vulnerability"
            ),
            PatternSignature(
                name="sql_syntax_error",
                pattern_type=PatternType.SQL_FRAGMENT,
                regex=r"You have an error in your SQL syntax.*?near\s+['\"](.+?)['\"]",
                confidence=0.98,
                description="SQL syntax error detected",
                suggestion="Strong indicator of SQL injection vulnerability"
            ),
            PatternSignature(
                name="stack_trace_python",
                pattern_type=PatternType.STACK_TRACE,
                regex=r"Traceback\s+\(most recent call last\):",
                confidence=0.95,
                description="Python stack trace detected",
                suggestion="Information disclosure - debug mode may be enabled"
            ),
            PatternSignature(
                name="stack_trace_java",
                pattern_type=PatternType.STACK_TRACE,
                regex=r"(java\.\w+\.\w+Exception|Caused by:.*?\n\s+at\s+\w+)",
                confidence=0.95,
                description="Java stack trace detected",
                suggestion="Information disclosure - debug mode may be enabled"
            ),
            PatternSignature(
                name="stack_trace_php",
                pattern_type=PatternType.STACK_TRACE,
                regex=r"Fatal error:.*?in\s+(.+?\.php)\s+on line\s+(\d+)",
                confidence=0.95,
                description="PHP fatal error detected",
                suggestion="Information disclosure - error reporting may be enabled"
            ),
            PatternSignature(
                name="file_path_unix",
                pattern_type=PatternType.FILE_PATH,
                regex=r"(?:/[\w.-]+)+\.\w{2,4}",
                confidence=0.70,
                description="Unix file path detected",
                suggestion="Possible path disclosure vulnerability"
            ),
            PatternSignature(
                name="file_path_windows",
                pattern_type=PatternType.FILE_PATH,
                regex=r"[A-Za-z]:\\(?:[\w\s.-]+\\)*[\w\s.-]+\.\w{2,4}",
                confidence=0.75,
                description="Windows file path detected",
                suggestion="Possible path disclosure vulnerability"
            ),
            PatternSignature(
                name="aws_access_key",
                pattern_type=PatternType.API_KEY,
                regex=r"AKIA[0-9A-Z]{16}",
                confidence=0.99,
                description="AWS Access Key ID detected",
                suggestion="Critical - API key exposure"
            ),
            PatternSignature(
                name="aws_secret_key",
                pattern_type=PatternType.API_KEY,
                regex=r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\s=:]+['\"]?([A-Za-z0-9/+]{40})",
                confidence=0.99,
                description="AWS Secret Access Key detected",
                suggestion="Critical - API key exposure"
            ),
            PatternSignature(
                name="google_api_key",
                pattern_type=PatternType.API_KEY,
                regex=r"AIza[0-9A-Za-z\-_]{35}",
                confidence=0.95,
                description="Google API Key detected",
                suggestion="API key exposure"
            ),
            PatternSignature(
                name="github_token",
                pattern_type=PatternType.API_KEY,
                regex=r"gh[pousr]_[A-Za-z0-9_]{36,}",
                confidence=0.95,
                description="GitHub Personal Access Token detected",
                suggestion="Critical - API key exposure"
            ),
            PatternSignature(
                name="jwt_token",
                pattern_type=PatternType.API_KEY,
                regex=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.?[A-Za-z0-9._-]*",
                confidence=0.85,
                description="JWT token detected in response",
                suggestion="Possible token leakage"
            ),
            PatternSignature(
                name="private_key_pem",
                pattern_type=PatternType.CREDENTIAL_EXPOSURE,
                regex=r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
                confidence=1.0,
                description="Private key in PEM format detected",
                suggestion="Critical - Private key exposure"
            ),
            PatternSignature(
                name="password_in_response",
                pattern_type=PatternType.CREDENTIAL_EXPOSURE,
                regex=r"(?:password|passwd|pwd)[\s:=]+['\"]?([^'\"\s&]{6,})",
                confidence=0.85,
                description="Password field detected in response",
                suggestion="Possible credential exposure"
            ),
            PatternSignature(
                name="connection_string",
                pattern_type=PatternType.CONFIG_LEAK,
                regex=r"(?:jdbc|mongodb|mysql|postgresql|redis)://[^/\s]+:[^/\s]+@",
                confidence=0.98,
                description="Database connection string detected",
                suggestion="Critical - Configuration leak"
            ),
            PatternSignature(
                name="debug_info_php",
                pattern_type=PatternType.DEBUG_INFO,
                regex=r"(?:phpinfo\(\)|PHP Version [\d.]+)",
                confidence=0.95,
                description="PHP debug information detected",
                suggestion="Remove debug pages in production"
            ),
            PatternSignature(
                name="debug_info_django",
                pattern_type=PatternType.DEBUG_INFO,
                regex=r"DJANGO_SETTINGS_MODULE|DEBUG\s*=\s*True",
                confidence=0.90,
                description="Django debug configuration detected",
                suggestion="Disable debug mode in production"
            ),
            PatternSignature(
                name="server_version",
                pattern_type=PatternType.DEBUG_INFO,
                regex=r"(?:Server|X-Powered-By):\s*(.+?)(?:\r?\n|$)",
                confidence=0.80,
                description="Server version header detected",
                suggestion="Hide server version information"
            ),
            PatternSignature(
                name="directory_listing",
                pattern_type=PatternType.DEBUG_INFO,
                regex=r"Index of\s+/[\w/.-]+",
                confidence=0.95,
                description="Directory listing detected",
                suggestion="Disable directory listing"
            ),
            PatternSignature(
                name="php_errors",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"(?:Notice|Warning|Parse error|Deprecated):\s*(.+?)\s+in\s+",
                confidence=0.90,
                description="PHP error messages detected",
                suggestion="Disable error display in production"
            ),
            PatternSignature(
                name="laravel_debug",
                pattern_type=PatternType.DEBUG_INFO,
                regex=r"Whoops, looks like something went wrong",
                confidence=0.95,
                description="Laravel debug page detected",
                suggestion="Disable APP_DEBUG in production"
            ),
            PatternSignature(
                name="aspnet_error",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"Server Error in '/' Application",
                confidence=0.95,
                description="ASP.NET error page detected",
                suggestion="Configure custom error pages"
            ),
            PatternSignature(
                name="nginx_error",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"(?:nginx|openresty)[/\d.]*\s+(?:error|404|502|503)",
                confidence=0.85,
                description="Nginx error page detected",
                suggestion="Configure custom error pages"
            ),
            PatternSignature(
                name="apache_error",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"Apache[/\d.]*\s+(?:Server at|Port \d+)",
                confidence=0.85,
                description="Apache error page detected",
                suggestion="Configure custom error pages"
            ),
            PatternSignature(
                name="xml_parsing_error",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"XML Parsing Error:.*?Location:",
                confidence=0.85,
                description="XML parsing error detected",
                suggestion="Check for XXE or XPath injection"
            ),
            PatternSignature(
                name="json_parse_error",
                pattern_type=PatternType.ERROR_MESSAGE,
                regex=r"(?:JSON\.parse|SyntaxError):.*?at position \d+",
                confidence=0.80,
                description="JSON parse error detected",
                suggestion="Check for JSON injection"
            ),
            PatternSignature(
                name="command_output",
                pattern_type=PatternType.CODE_SNIPPET,
                regex=r"(?:uid=\d+|gid=\d+|groups=\d+)",
                confidence=0.90,
                description="Command execution output detected",
                suggestion="Possible command injection vulnerability"
            ),
            PatternSignature(
                name="etc_passwd_content",
                pattern_type=PatternType.FILE_PATH,
                regex=r"root:.:0:0:.*?:/root:/bin/(?:bash|sh)",
                confidence=0.99,
                description="/etc/passwd file content detected",
                suggestion="Critical - LFI vulnerability confirmed"
            ),
        ]
    
    def analyze_response(self, response_text: str) -> List[PatternMatch]:
        """
        Analyze HTTP response text for known vulnerability patterns.
        
        Args:
            response_text: The HTTP response body text to analyze
            
        Returns:
            List of PatternMatch objects for detected patterns
        """
        if not response_text:
            return []
        
        matches: List[PatternMatch] = []
        
        for pattern in self.patterns:
            try:
                flags = 0 if pattern.case_sensitive else re.IGNORECASE
                compiled_regex = re.compile(pattern.regex, flags | re.MULTILINE | re.DOTALL)
                
                for match in compiled_regex.finditer(response_text):
                    matched_text = match.group(0)
                    
                    if len(matched_text) > 500:
                        matched_text = matched_text[:500] + "..."
                    
                    line_number = response_text[:match.start()].count('\n') + 1
                    
                    context = self._extract_context(
                        response_text,
                        match.start(),
                        match.end()
                    )
                    
                    pattern_match = PatternMatch(
                        pattern_type=pattern.pattern_type,
                        pattern_name=pattern.name,
                        matched_text=matched_text,
                        confidence=pattern.confidence,
                        line_number=line_number,
                        context=context,
                        suggestion=pattern.suggestion
                    )
                    
                    matches.append(pattern_match)
                    
                    if self.enable_learning:
                        self.learned_patterns[pattern.name] += 1
                    
            except re.error as e:
                continue
        
        self.match_history.extend(matches)
        return self._deduplicate_matches(matches)
    
    def _extract_context(self, text: str, start: int, end: int, lines: Optional[int] = None) -> str:
        """
        Extract surrounding context around a match.
        
        Args:
            text: Full response text
            start: Start position of match
            end: End position of match
            lines: Number of context lines to include
            
        Returns:
            Context string around the match
        """
        if lines is None:
            lines = self.max_context_lines
        
        text_lines = text.split('\n')
        current_line = text[:start].count('\n')
        
        start_line = max(0, current_line - lines)
        end_line = min(len(text_lines), current_line + lines + 1)
        
        context_lines = text_lines[start_line:end_line]
        return '\n'.join(context_lines)
    
    def _deduplicate_matches(self, matches: List[PatternMatch]) -> List[PatternMatch]:
        """
        Remove duplicate pattern matches.
        
        Args:
            matches: List of pattern matches potentially containing duplicates
            
        Returns:
            Deduplicated list of pattern matches
        """
        seen: Set[str] = set()
        unique_matches: List[PatternMatch] = []
        
        for match in matches:
            match_hash = hashlib.md5(
                f"{match.pattern_name}:{match.matched_text}".encode()
            ).hexdigest()
            
            if match_hash not in seen:
                seen.add(match_hash)
                unique_matches.append(match)
        
        return unique_matches
    
    def get_high_confidence_matches(self, threshold: Optional[float] = None) -> List[PatternMatch]:
        """
        Filter matches above a confidence threshold.
        
        Args:
            threshold: Minimum confidence threshold (defaults to min_confidence config)
            
        Returns:
            List of high confidence pattern matches
        """
        if threshold is None:
            threshold = self.min_confidence
        
        return [
            match for match in self.match_history
            if match.confidence >= threshold
        ]
    
    def get_critical_findings(self) -> List[PatternMatch]:
        """
        Get only critical severity findings (confidence >= 0.95).
        
        Returns:
            List of critical pattern matches
        """
        return self.get_high_confidence_matches(threshold=0.95)
    
    def get_matches_by_type(self, pattern_type: PatternType) -> List[PatternMatch]:
        """
        Filter matches by pattern type.
        
        Args:
            pattern_type: The type of pattern to filter by
            
        Returns:
            List of pattern matches of the specified type
        """
        return [
            match for match in self.match_history
            if match.pattern_type == pattern_type
        ]
    
    def add_custom_pattern(self, pattern: PatternSignature) -> None:
        """
        Add a custom detection pattern.
        
        Args:
            pattern: PatternSignature object defining the new pattern
        """
        if not isinstance(pattern, PatternSignature):
            raise TypeError("pattern must be a PatternSignature instance")
        
        try:
            re.compile(pattern.regex)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {str(e)}")
        
        existing_names = [p.name for p in self.patterns]
        if pattern.name in existing_names:
            for i, existing_pattern in enumerate(self.patterns):
                if existing_pattern.name == pattern.name:
                    self.patterns[i] = pattern
                    return
        
        self.patterns.append(pattern)
    
    def remove_pattern(self, pattern_name: str) -> bool:
        """
        Remove a pattern by name.
        
        Args:
            pattern_name: Name of the pattern to remove
            
        Returns:
            True if pattern was removed, False if not found
        """
        for i, pattern in enumerate(self.patterns):
            if pattern.name == pattern_name:
                self.patterns.pop(i)
                return True
        return False
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about learned patterns.
        
        Returns:
            Dictionary containing learning statistics
        """
        if not self.learned_patterns:
            return {
                'total_learned': 0,
                'top_patterns': [],
                'unique_patterns_detected': 0
            }
        
        sorted_patterns = sorted(
            self.learned_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            'total_learned': sum(self.learned_patterns.values()),
            'top_patterns': sorted_patterns[:10],
            'unique_patterns_detected': len(self.learned_patterns),
            'pattern_details': dict(sorted_patterns)
        }
    
    def reset_history(self) -> None:
        """Reset match history and learned patterns."""
        self.match_history.clear()
        self.learned_patterns.clear()
    
    def export_findings(self, format_type: str = 'json') -> str:
        """
        Export findings in specified format.
        
        Args:
            format_type: Output format ('json' or 'text')
            
        Returns:
            String representation of findings
        """
        if format_type == 'json':
            findings = []
            for match in self.match_history:
                findings.append({
                    'pattern_type': match.pattern_type.value,
                    'pattern_name': match.pattern_name,
                    'matched_text': match.matched_text,
                    'confidence': match.confidence,
                    'line_number': match.line_number,
                    'suggestion': match.suggestion
                })
            return json.dumps(findings, indent=2)
        
        elif format_type == 'text':
            lines = []
            lines.append("=" * 80)
            lines.append("PATTERN RECOGNITION FINDINGS")
            lines.append("=" * 80)
            
            for match in self.match_history:
                lines.append(f"\n[{match.pattern_type.value.upper()}] {match.pattern_name}")
                lines.append(f"Confidence: {match.confidence:.2%}")
                if match.line_number:
                    lines.append(f"Line: {match.line_number}")
                lines.append(f"Match: {match.matched_text[:200]}")
                if match.suggestion:
                    lines.append(f"Fix: {match.suggestion}")
                lines.append("-" * 40)
            
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported format type: {format_type}")