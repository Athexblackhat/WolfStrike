# modules/reporting/pdf_generator.py

"""
PDF Report Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates professional PDF security assessment reports
with findings, charts, and remediation guidance.
"""

import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from fpdf import FPDF


class PDFGenerator:
    """
    Professional PDF report generator.
    
    Creates comprehensive security assessment reports
    in PDF format with findings, severity charts,
    evidence, and remediation recommendations.
    """
    
    SEVERITY_COLORS = {
        'critical': (220, 53, 69),
        'high': (255, 138, 0),
        'medium': (255, 193, 7),
        'low': (40, 167, 69),
        'info': (13, 110, 253),
    }
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the PDF generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.output_dir = self.config.get('output_dir', 'reports')
        
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=20)
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(
        self,
        target: str,
        scan_data: Dict[str, Any],
        filename: Optional[str] = None
    ) -> str:
        """
        Generate PDF report.
        
        Args:
            target: Target URL or domain
            scan_data: Complete scan results data
            filename: Output filename
            
        Returns:
            Path to generated PDF file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wolfstrike_report_{target.replace('://', '_').replace('/', '_')}_{timestamp}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        
        self._add_cover_page(target, scan_data)
        self._add_executive_summary(scan_data)
        self._add_findings_detail(scan_data)
        self._add_remediation_section(scan_data)
        self._add_appendix(scan_data)
        
        self.pdf.output(filepath)
        
        return filepath
    
    def _add_cover_page(self, target: str, scan_data: Dict[str, Any]) -> None:
        """
        Add report cover page.
        
        Args:
            target: Target URL
            scan_data: Scan data
        """
        self.pdf.add_page()
        
        self.pdf.ln(40)
        
        self.pdf.set_font('Helvetica', 'B', 28)
        self.pdf.cell(0, 15, 'WOLFSTRIKE', ln=True, align='C')
        
        self.pdf.set_font('Helvetica', '', 16)
        self.pdf.cell(0, 10, 'Security Assessment Report', ln=True, align='C')
        
        self.pdf.ln(20)
        
        self.pdf.set_draw_color(100, 100, 100)
        self.pdf.line(30, self.pdf.get_y(), 180, self.pdf.get_y())
        self.pdf.ln(10)
        
        self.pdf.set_font('Helvetica', '', 12)
        self.pdf.cell(0, 8, f'Target: {target}', ln=True, align='C')
        
        scan_date = scan_data.get('scan_date', datetime.now().strftime('%Y-%m-%d'))
        self.pdf.cell(0, 8, f'Date: {scan_date}', ln=True, align='C')
        
        self.pdf.cell(0, 8, f'Tool Version: 1.0.0 (Shadowfang)', ln=True, align='C')
        self.pdf.cell(0, 8, 'Author: ATHEX BLACK HAT', ln=True, align='C')
        self.pdf.cell(0, 8, 'Team: Wolf Intelligence PK', ln=True, align='C')
    
    def _add_executive_summary(self, scan_data: Dict[str, Any]) -> None:
        """
        Add executive summary section.
        
        Args:
            scan_data: Scan data
        """
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, 'Executive Summary', ln=True)
        self.pdf.ln(5)
        
        findings = scan_data.get('findings', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        self.pdf.set_font('Helvetica', '', 11)
        
        total_vulns = len(findings)
        
        self.pdf.cell(0, 7, f'Total Vulnerabilities Found: {total_vulns}', ln=True)
        self.pdf.cell(0, 7, f'Critical: {severity_counts["critical"]}', ln=True)
        self.pdf.cell(0, 7, f'High: {severity_counts["high"]}', ln=True)
        self.pdf.cell(0, 7, f'Medium: {severity_counts["medium"]}', ln=True)
        self.pdf.cell(0, 7, f'Low: {severity_counts["low"]}', ln=True)
        self.pdf.cell(0, 7, f'Info: {severity_counts["info"]}', ln=True)
        
        self.pdf.ln(10)
        
        overall_risk = 'Critical' if severity_counts['critical'] > 0 else \
                       'High' if severity_counts['high'] > 3 else \
                       'Medium' if severity_counts['medium'] > 5 else \
                       'Low' if total_vulns > 0 else 'None'
        
        self.pdf.set_font('Helvetica', 'B', 14)
        self.pdf.cell(0, 10, f'Overall Risk Level: {overall_risk}', ln=True)
    
    def _add_findings_detail(self, scan_data: Dict[str, Any]) -> None:
        """
        Add detailed findings section.
        
        Args:
            scan_data: Scan data
        """
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, 'Detailed Findings', ln=True)
        self.pdf.ln(5)
        
        findings = scan_data.get('findings', [])
        
        findings.sort(key=lambda x: {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }.get(x.get('severity', 'info'), 4))
        
        for i, finding in enumerate(findings[:50], 1):
            severity = finding.get('severity', 'info')
            
            if self.pdf.get_y() > 240:
                self.pdf.add_page()
            
            color = self.SEVERITY_COLORS.get(severity, (100, 100, 100))
            self.pdf.set_fill_color(*color)
            self.pdf.set_text_color(255, 255, 255)
            self.pdf.set_font('Helvetica', 'B', 10)
            self.pdf.cell(0, 7, f'  #{i}  {finding.get("type", "Unknown")}  -  {severity.upper()}', ln=True, fill=True)
            
            self.pdf.set_text_color(0, 0, 0)
            self.pdf.set_font('Helvetica', '', 9)
            
            self.pdf.cell(0, 6, f'Endpoint: {finding.get("endpoint", "N/A")}', ln=True)
            
            description = finding.get('description', 'No description')
            self.pdf.multi_cell(0, 5, f'Description: {description}')
            
            remediation = finding.get('remediation', 'No remediation provided')
            self.pdf.multi_cell(0, 5, f'Remediation: {remediation}')
            
            self.pdf.ln(3)
    
    def _add_remediation_section(self, scan_data: Dict[str, Any]) -> None:
        """
        Add remediation recommendations section.
        
        Args:
            scan_data: Scan data
        """
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, 'Remediation Recommendations', ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', '', 10)
        
        recommendations = [
            'Address all critical and high severity findings immediately',
            'Implement input validation and output encoding for all user inputs',
            'Use parameterized queries to prevent SQL injection',
            'Enable HTTPS with HSTS headers for all connections',
            'Implement Content Security Policy (CSP) headers',
            'Regular security assessments and penetration testing',
            'Keep all software and dependencies updated',
            'Implement proper access controls and authentication',
            'Use Web Application Firewall (WAF) for additional protection',
            'Conduct security awareness training for developers',
        ]
        
        for rec in recommendations:
            self.pdf.cell(5, 7, '-', ln=False)
            self.pdf.cell(0, 7, rec, ln=True)
        
        self.pdf.ln(10)
        
        self.pdf.set_font('Helvetica', 'B', 14)
        self.pdf.cell(0, 10, 'Priority Actions', ln=True)
        
        findings = scan_data.get('findings', [])
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        
        if critical_findings:
            for finding in critical_findings[:5]:
                self.pdf.set_font('Helvetica', '', 10)
                self.pdf.cell(0, 7, f'[CRITICAL] {finding.get("type", "Unknown")} - {finding.get("endpoint", "N/A")}', ln=True)
    
    def _add_appendix(self, scan_data: Dict[str, Any]) -> None:
        """
        Add appendix with scan details.
        
        Args:
            scan_data: Scan data
        """
        self.pdf.add_page()
        
        self.pdf.set_font('Helvetica', 'B', 18)
        self.pdf.cell(0, 12, 'Appendix - Scan Details', ln=True)
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', '', 10)
        
        self.pdf.cell(0, 7, f'Scan Date: {scan_data.get("scan_date", "N/A")}', ln=True)
        self.pdf.cell(0, 7, f'Scan Duration: {scan_data.get("scan_duration", "N/A")}', ln=True)
        self.pdf.cell(0, 7, f'Target: {scan_data.get("target", "N/A")}', ln=True)
        self.pdf.cell(0, 7, f'Tool Version: 1.0.0 (Shadowfang)', ln=True)
        
        self.pdf.ln(5)
        
        modules = scan_data.get('modules_executed', [])
        if modules:
            self.pdf.cell(0, 7, f'Modules Executed: {len(modules)}', ln=True)
            for module in modules[:20]:
                self.pdf.cell(0, 6, f'  - {module}', ln=True)