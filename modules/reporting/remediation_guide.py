# modules/reporting/remediation_guide.py

"""
Remediation Guide Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates detailed remediation guidance for each
vulnerability type with step-by-step fix instructions.
"""

from typing import Dict, List, Any, Optional


class RemediationGuide:
    """
    Remediation guidance generator.
    
    Provides detailed fix recommendations for
    each vulnerability type discovered.
    """
    
    REMEDIATION_GUIDES = {
        'SQL Injection': {
            'priority': 'Immediate',
            'difficulty': 'Medium',
            'steps': [
                'Use parameterized queries (prepared statements) for all database operations',
                'Implement input validation and sanitization',
                'Use ORM frameworks with built-in SQL injection protection',
                'Apply principle of least privilege for database accounts',
                'Conduct code review focusing on dynamic SQL construction',
                'Deploy Web Application Firewall (WAF) as compensating control',
            ],
            'references': [
                'OWASP SQL Injection Prevention Cheat Sheet',
                'OWASP Query Parameterization Cheat Sheet',
            ],
        },
        'Cross-Site Scripting (XSS)': {
            'priority': 'Immediate',
            'difficulty': 'Medium',
            'steps': [
                'Implement context-appropriate output encoding (HTML, JavaScript, CSS, URL)',
                'Use Content-Security-Policy (CSP) headers',
                'Validate and sanitize all user input',
                'Use secure frameworks with auto-escaping (React, Angular, Vue)',
                'Set HttpOnly flag on session cookies',
                'Implement X-XSS-Protection header',
            ],
            'references': [
                'OWASP XSS Prevention Cheat Sheet',
                'OWASP DOM based XSS Prevention Cheat Sheet',
            ],
        },
        'Command Injection': {
            'priority': 'Immediate',
            'difficulty': 'Medium',
            'steps': [
                'Avoid using system calls with user input',
                'Use parameterized APIs instead of shell commands',
                'Implement strict input validation with whitelist approach',
                'Run application with least privilege',
                'Escape special characters if system calls are unavoidable',
                'Use security-focused libraries for process execution',
            ],
            'references': [
                'OWASP Command Injection Defense Cheat Sheet',
            ],
        },
        'SSRF': {
            'priority': 'High',
            'difficulty': 'Medium',
            'steps': [
                'Implement URL whitelist for allowed destinations',
                'Validate and sanitize user-supplied URLs',
                'Use network segmentation to restrict internal access',
                'Disable unused URL schemes (file://, gopher://, dict://)',
                'Implement DNS resolution restrictions',
                'Use firewall rules to prevent internal network access',
            ],
            'references': [
                'OWASP SSRF Prevention Cheat Sheet',
            ],
        },
        'LFI': {
            'priority': 'Immediate',
            'difficulty': 'Easy',
            'steps': [
                'Use whitelist of allowed files for inclusion',
                'Validate and sanitize file path input',
                'Disable allow_url_include in PHP configuration',
                'Use indirect file references instead of user-supplied paths',
                'Set open_basedir restriction in PHP',
                'Implement proper access controls on file system',
            ],
            'references': [
                'OWASP File Inclusion Prevention Cheat Sheet',
            ],
        },
        'CSRF': {
            'priority': 'High',
            'difficulty': 'Easy',
            'steps': [
                'Implement anti-CSRF tokens in all state-changing forms',
                'Use SameSite=Strict or Lax cookie attribute',
                'Validate Origin and Referer headers',
                'Use custom request headers for API calls',
                'Implement user interaction for sensitive operations',
                'Use double submit cookie pattern',
            ],
            'references': [
                'OWASP CSRF Prevention Cheat Sheet',
            ],
        },
        'SSTI': {
            'priority': 'Immediate',
            'difficulty': 'Hard',
            'steps': [
                'Use sandboxed template engine with restricted functionality',
                'Avoid passing user input directly to templates',
                'Use logic-less templates when possible',
                'Implement strict input validation',
                'Keep template engines updated to latest version',
                'Consider using static content instead of dynamic templates',
            ],
            'references': [
                'PortSwigger Server-Side Template Injection',
            ],
        },
        'CORS Misconfiguration': {
            'priority': 'High',
            'difficulty': 'Easy',
            'steps': [
                'Configure Access-Control-Allow-Origin with specific whitelist',
                'Do not use wildcard (*) with Access-Control-Allow-Credentials: true',
                'Validate Origin header against whitelist',
                'Use Vary: Origin header',
                'Implement proper preflight request handling',
                'Review CORS policy for each API endpoint',
            ],
            'references': [
                'OWASP CORS Security Guide',
            ],
        },
        'Clickjacking': {
            'priority': 'Medium',
            'difficulty': 'Easy',
            'steps': [
                'Add X-Frame-Options: DENY or SAMEORIGIN header',
                'Implement Content-Security-Policy with frame-ancestors directive',
                'Use framebusting JavaScript as additional protection',
                'Implement SameSite cookie attribute',
            ],
            'references': [
                'OWASP Clickjacking Defense Cheat Sheet',
            ],
        },
        'Open Redirect': {
            'priority': 'Medium',
            'difficulty': 'Easy',
            'steps': [
                'Avoid user-controlled redirects when possible',
                'Use relative paths instead of absolute URLs',
                'Implement whitelist of allowed redirect URLs',
                'Use indirect references with server-side mapping',
                'Validate redirect URLs against whitelist',
                'Display intermediate page before redirecting',
            ],
            'references': [
                'OWASP Unvalidated Redirects and Forwards Cheat Sheet',
            ],
        },
        'File Upload': {
            'priority': 'Immediate',
            'difficulty': 'Hard',
            'steps': [
                'Use whitelist of allowed file extensions',
                'Validate file type server-side (not just MIME type)',
                'Limit maximum file size',
                'Scan uploaded files for malware',
                'Store files outside web root with random names',
                'Set proper permissions on upload directory',
                'Use CDN or separate domain for serving uploaded files',
            ],
            'references': [
                'OWASP File Upload Cheat Sheet',
            ],
        },
        'Default Credentials': {
            'priority': 'Immediate',
            'difficulty': 'Easy',
            'steps': [
                'Change all default passwords immediately',
                'Implement strong password policy',
                'Disable default accounts if not needed',
                'Implement multi-factor authentication',
                'Conduct regular credential audits',
            ],
            'references': [
                'OWASP Authentication Cheat Sheet',
            ],
        },
        'Exposed Admin Panel': {
            'priority': 'High',
            'difficulty': 'Easy',
            'steps': [
                'Restrict admin panel access by IP whitelist',
                'Implement VPN requirement for admin access',
                'Use non-standard URLs for admin interfaces',
                'Implement strong authentication for admin panels',
                'Enable audit logging for admin access',
                'Use certificate-based authentication',
            ],
            'references': [
                'OWASP Administrative Interface Security',
            ],
        },
        'Debug Mode': {
            'priority': 'High',
            'difficulty': 'Easy',
            'steps': [
                'Disable debug mode in production environment',
                'Configure custom error pages',
                'Log errors server-side only',
                'Use environment-specific configuration',
                'Implement proper error handling',
                'Remove stack traces from production responses',
            ],
            'references': [
                'OWASP Error Handling Cheat Sheet',
            ],
        },
    }
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the remediation guide generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def get_remediation(self, finding_type: str) -> Optional[Dict[str, Any]]:
        """
        Get remediation guide for a finding type.
        
        Args:
            finding_type: Type of vulnerability finding
            
        Returns:
            Dictionary with remediation steps
        """
        for vuln_key, guide in self.REMEDIATION_GUIDES.items():
            if vuln_key.lower() in finding_type.lower():
                return guide
        
        return {
            'priority': 'Medium',
            'difficulty': 'Unknown',
            'steps': [
                'Review and fix the identified vulnerability',
                'Follow security best practices',
                'Conduct thorough testing after fixes',
                'Implement defense in depth',
            ],
            'references': [
                'OWASP Top 10 Web Application Security Risks',
            ],
        }
    
    def generate_remediation_report(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Generate remediation report for all findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of findings with remediation guidance
        """
        report = []
        
        for finding in findings:
            finding_type = finding.get('type', '')
            guide = self.get_remediation(finding_type)
            
            report.append({
                'finding_type': finding_type,
                'severity': finding.get('severity', 'info'),
                'endpoint': finding.get('endpoint', ''),
                'priority': guide.get('priority', 'Medium'),
                'difficulty': guide.get('difficulty', 'Unknown'),
                'steps': guide.get('steps', []),
                'references': guide.get('references', []),
                'original_description': finding.get('description', ''),
            })
        
        report.sort(key=lambda x: {
            'Immediate': 0, 'High': 1, 'Medium': 2, 'Low': 3
        }.get(x.get('priority', 'Medium'), 2))
        
        return report
    
    def get_priority_actions(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Get prioritized action items.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of priority action items
        """
        report = self.generate_remediation_report(findings)
        
        immediate = [r for r in report if r['priority'] == 'Immediate']
        high = [r for r in report if r['priority'] == 'High']
        
        return immediate + high