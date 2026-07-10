# modules/reporting/json_export.py

"""
JSON Report Exporter
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Exports scan results in structured JSON format
for integration with other tools and systems.
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime


class JSONExporter:
    """
    JSON report exporter.
    
    Creates structured JSON output of scan results
    for machine processing and tool integration.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the JSON exporter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.output_dir = self.config.get('output_dir', 'reports')
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def export(
        self,
        target: str,
        scan_data: Dict[str, Any],
        filename: Optional[str] = None,
        pretty: bool = True
    ) -> str:
        """
        Export scan results to JSON file.
        
        Args:
            target: Target URL or domain
            scan_data: Complete scan results data
            filename: Output filename
            pretty: Whether to format with indentation
            
        Returns:
            Path to generated JSON file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wolfstrike_results_{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report = self._build_report_structure(target, scan_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(report, f, indent=2, ensure_ascii=False)
            else:
                json.dump(report, f, ensure_ascii=False)
        
        return filepath
    
    def _build_report_structure(
        self,
        target: str,
        scan_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build structured report JSON.
        
        Args:
            target: Target URL
            scan_data: Scan results data
            
        Returns:
            Structured report dictionary
        """
        findings = scan_data.get('findings', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        report = {
            'report_metadata': {
                'tool': 'WOLFSTRIKE',
                'version': '1.0.0',
                'codename': 'Shadowfang',
                'author': 'ATHEX BLACK HAT',
                'team': 'Wolf Intelligence PK',
                'generated_at': datetime.now().isoformat(),
                'report_format_version': '1.0',
            },
            'scan_info': {
                'target': target,
                'scan_date': scan_data.get('scan_date', datetime.now().isoformat()),
                'scan_duration': scan_data.get('scan_duration', 0),
                'modules_executed': scan_data.get('modules_executed', []),
            },
            'summary': {
                'total_vulnerabilities': len(findings),
                'severity_counts': severity_counts,
                'overall_risk': 'critical' if severity_counts['critical'] > 0 else
                               'high' if severity_counts['high'] > 3 else
                               'medium' if severity_counts['medium'] > 5 else
                               'low' if len(findings) > 0 else 'none',
            },
            'findings': [],
        }
        
        for finding in findings:
            report['findings'].append({
                'type': finding.get('type', 'Unknown'),
                'severity': finding.get('severity', 'info'),
                'endpoint': finding.get('endpoint', ''),
                'parameter': finding.get('parameter', ''),
                'description': finding.get('description', ''),
                'evidence': finding.get('evidence', {}),
                'remediation': finding.get('remediation', ''),
                'references': finding.get('references', []),
            })
        
        return report
    
    def export_findings_only(
        self,
        findings: List[Dict[str, Any]],
        filename: Optional[str] = None
    ) -> str:
        """
        Export only findings to JSON file.
        
        Args:
            findings: List of finding dictionaries
            filename: Output filename
            
        Returns:
            Path to generated JSON file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wolfstrike_findings_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        
        return filepath