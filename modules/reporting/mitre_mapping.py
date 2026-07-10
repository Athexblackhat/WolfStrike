# modules/reporting/mitre_mapping.py

"""
MITRE ATT&CK Mapper
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Maps vulnerability findings to MITRE ATT&CK framework
for standardized threat classification.
"""

from typing import Dict, List, Any, Optional


class MITREMapper:
    """
    MITRE ATT&CK framework mapper.
    
    Maps vulnerabilities to MITRE ATT&CK techniques
    for enterprise security reporting.
    """
    
    VULN_TO_MITRE = {
        'SQL Injection': {
            'tactic': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'description': 'SQL injection can be used to gain initial access through web applications',
        },
        'Cross-Site Scripting (XSS)': {
            'tactic': 'Execution',
            'technique_id': 'T1059.007',
            'technique_name': 'Command and Scripting Interpreter: JavaScript',
            'description': 'XSS allows execution of malicious scripts in victim browser',
        },
        'Command Injection': {
            'tactic': 'Execution',
            'technique_id': 'T1059.004',
            'technique_name': 'Command and Scripting Interpreter: Unix Shell',
            'description': 'OS command injection allows arbitrary command execution',
        },
        'SSRF': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1213',
            'technique_name': 'Exploitation of Remote Services',
            'description': 'SSRF can be used to access internal services and move laterally',
        },
        'LFI': {
            'tactic': 'Collection',
            'technique_id': 'T1005',
            'technique_name': 'Data from Local System',
            'description': 'Local file inclusion allows reading sensitive files from server',
        },
        'CSRF': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1204',
            'technique_name': 'User Execution',
            'description': 'CSRF tricks users into executing unwanted actions',
        },
        'SSTI': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'description': 'Template injection can lead to remote code execution',
        },
        'CORS Misconfiguration': {
            'tactic': 'Collection',
            'technique_id': 'T1539',
            'technique_name': 'Steal Web Session Cookie',
            'description': 'CORS misconfiguration enables cross-origin data theft',
        },
        'Clickjacking': {
            'tactic': 'Collection',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'description': 'Clickjacking tricks users into clicking hidden elements',
        },
        'Open Redirect': {
            'tactic': 'Initial Access',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'description': 'Open redirects can be used in phishing campaigns',
        },
        'File Upload': {
            'tactic': 'Execution',
            'technique_id': 'T1105',
            'technique_name': 'Ingress Tool Transfer',
            'description': 'Unrestricted file upload allows malicious file transfer',
        },
        'NoSQL Injection': {
            'tactic': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'description': 'NoSQL injection can bypass authentication',
        },
        'LDAP Injection': {
            'tactic': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application',
            'description': 'LDAP injection can bypass authentication',
        },
        'XPath Injection': {
            'tactic': 'Collection',
            'technique_id': 'T1213',
            'technique_name': 'Data from Information Repositories',
            'description': 'XPath injection allows unauthorized data access',
        },
        'Brute Force': {
            'tactic': 'Credential Access',
            'technique_id': 'T1110',
            'technique_name': 'Brute Force',
            'description': 'Brute force attack against authentication',
        },
        'Default Credentials': {
            'tactic': 'Initial Access',
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts',
            'description': 'Default credentials provide unauthorized access',
        },
        'Exposed Admin Panel': {
            'tactic': 'Discovery',
            'technique_id': 'T1046',
            'technique_name': 'Network Service Scanning',
            'description': 'Exposed admin panels reveal management interfaces',
        },
        'Debug Mode': {
            'tactic': 'Discovery',
            'technique_id': 'T1082',
            'technique_name': 'System Information Discovery',
            'description': 'Debug mode reveals system and application details',
        },
    }
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the MITRE mapper.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def map_finding(self, finding_type: str) -> Optional[Dict[str, Any]]:
        """
        Map a finding type to MITRE ATT&CK.
        
        Args:
            finding_type: Type of vulnerability finding
            
        Returns:
            Dictionary with MITRE mapping or None
        """
        for vuln_key, mitre_data in self.VULN_TO_MITRE.items():
            if vuln_key.lower() in finding_type.lower():
                return mitre_data
        
        return None
    
    def map_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Map all findings to MITRE ATT&CK.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of mapped findings with MITRE data
        """
        mapped = []
        
        for finding in findings:
            finding_type = finding.get('type', '')
            mitre_data = self.map_finding(finding_type)
            
            mapped_finding = finding.copy()
            
            if mitre_data:
                mapped_finding['mitre_tactic'] = mitre_data['tactic']
                mapped_finding['mitre_technique_id'] = mitre_data['technique_id']
                mapped_finding['mitre_technique_name'] = mitre_data['technique_name']
                mapped_finding['mitre_description'] = mitre_data['description']
            else:
                mapped_finding['mitre_tactic'] = 'Unknown'
                mapped_finding['mitre_technique_id'] = 'N/A'
                mapped_finding['mitre_technique_name'] = 'N/A'
                mapped_finding['mitre_description'] = 'No MITRE mapping available'
            
            mapped.append(mapped_finding)
        
        return mapped
    
    def get_tactic_summary(self, mapped_findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get summary of MITRE tactics used.
        
        Args:
            mapped_findings: MITRE-mapped findings
            
        Returns:
            Dictionary with tactic counts
        """
        tactics = {}
        
        for finding in mapped_findings:
            tactic = finding.get('mitre_tactic', 'Unknown')
            tactics[tactic] = tactics.get(tactic, 0) + 1
        
        return tactics
    
    def generate_mitre_report(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate MITRE ATT&CK report.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary with MITRE report data
        """
        mapped = self.map_findings(findings)
        tactics = self.get_tactic_summary(mapped)
        
        return {
            'total_findings': len(findings),
            'mapped_findings': len(mapped),
            'tactics_used': list(tactics.keys()),
            'tactic_counts': tactics,
            'techniques': [
                {
                    'technique_id': f.get('mitre_technique_id'),
                    'technique_name': f.get('mitre_technique_name'),
                    'tactic': f.get('mitre_tactic'),
                }
                for f in mapped
                if f.get('mitre_technique_id') != 'N/A'
            ],
        }