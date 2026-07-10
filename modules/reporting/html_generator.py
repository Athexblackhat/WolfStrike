# modules/reporting/html_generator.py

"""
HTML Report Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates interactive HTML security assessment reports
with collapsible findings, severity filters, and charts.
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime


class HTMLGenerator:
    """
    Interactive HTML report generator.
    
    Creates responsive HTML security reports with
    filtering, sorting, and visual charts.
    """
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WOLFSTRIKE Security Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #16213e, #0f3460); padding: 40px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; color: #e94560; }}
        .header p {{ color: #a0a0b0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #e94560; }}
        .summary-card h3 {{ font-size: 2em; color: #e94560; }}
        .summary-card p {{ color: #a0a0b0; }}
        .severity-critical {{ border-left-color: #dc3545; }}
        .severity-high {{ border-left-color: #ff8c00; }}
        .severity-medium {{ border-left-color: #ffc107; }}
        .severity-low {{ border-left-color: #28a745; }}
        .severity-info {{ border-left-color: #0d6efd; }}
        .finding {{ background: #16213e; margin-bottom: 15px; border-radius: 8px; overflow: hidden; }}
        .finding-header {{ padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
        .finding-header:hover {{ background: #1a2744; }}
        .finding-title {{ font-weight: bold; font-size: 1.1em; }}
        .finding-severity {{ padding: 4px 12px; border-radius: 4px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }}
        .severity-badge-critical {{ background: #dc3545; color: #fff; }}
        .severity-badge-high {{ background: #ff8c00; color: #fff; }}
        .severity-badge-medium {{ background: #ffc107; color: #000; }}
        .severity-badge-low {{ background: #28a745; color: #fff; }}
        .severity-badge-info {{ background: #0d6efd; color: #fff; }}
        .finding-body {{ padding: 20px; display: none; border-top: 1px solid #0f3460; }}
        .finding-body.active {{ display: block; }}
        .finding-detail {{ margin-bottom: 10px; }}
        .finding-detail strong {{ color: #e94560; }}
        .remediation {{ background: #0f3460; padding: 15px; border-radius: 5px; margin-top: 10px; }}
        .remediation h4 {{ color: #28a745; margin-bottom: 5px; }}
        .footer {{ text-align: center; padding: 30px; color: #a0a0b0; margin-top: 40px; border-top: 1px solid #0f3460; }}
        .filter-bar {{ margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
        .filter-btn {{ padding: 8px 16px; border: 1px solid #0f3460; background: #16213e; color: #e0e0e0; border-radius: 4px; cursor: pointer; }}
        .filter-btn:hover {{ background: #1a2744; }}
        .filter-btn.active {{ background: #e94560; border-color: #e94560; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WOLFSTRIKE</h1>
            <p>Security Assessment Report</p>
            <p>Target: {target}</p>
            <p>Date: {date}</p>
            <p>Author: ATHEX BLACK HAT | Wolf Intelligence PK</p>
        </div>
        
        <div class="summary">
            <div class="summary-card severity-critical">
                <h3>{critical_count}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card severity-high">
                <h3>{high_count}</h3>
                <p>High</p>
            </div>
            <div class="summary-card severity-medium">
                <h3>{medium_count}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card severity-low">
                <h3>{low_count}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card severity-info">
                <h3>{info_count}</h3>
                <p>Info</p>
            </div>
        </div>
        
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterFindings('all')">All</button>
            <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
            <button class="filter-btn" onclick="filterFindings('high')">High</button>
            <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
            <button class="filter-btn" onclick="filterFindings('low')">Low</button>
            <button class="filter-btn" onclick="filterFindings('info')">Info</button>
        </div>
        
        <div id="findings-container">
            {findings_html}
        </div>
        
        <div class="footer">
            <p>WOLFSTRIKE v1.0.0 (Shadowfang) | ATHEX BLACK HAT | Wolf Intelligence PK</p>
            <p>This report is confidential and intended for authorized recipients only.</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(id) {{
            const body = document.getElementById('finding-body-' + id);
            body.classList.toggle('active');
        }}
        
        function filterFindings(severity) {{
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {{
                if (severity === 'all' || finding.dataset.severity === severity) {{
                    finding.style.display = 'block';
                }} else {{
                    finding.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the HTML generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.output_dir = self.config.get('output_dir', 'reports')
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_report(
        self,
        target: str,
        scan_data: Dict[str, Any],
        filename: Optional[str] = None
    ) -> str:
        """
        Generate HTML report.
        
        Args:
            target: Target URL or domain
            scan_data: Complete scan results data
            filename: Output filename
            
        Returns:
            Path to generated HTML file
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wolfstrike_report_{target.replace('://', '_').replace('/', '_')}_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        findings = scan_data.get('findings', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        findings_html = self._generate_findings_html(findings)
        
        html_content = self.HTML_TEMPLATE.format(
            target=target,
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            info_count=severity_counts['info'],
            findings_html=findings_html,
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_findings_html(self, findings: List[Dict[str, Any]]) -> str:
        """
        Generate HTML for findings section.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            HTML string for findings
        """
        if not findings:
            return '<p>No vulnerabilities found. The target appears secure.</p>'
        
        html_parts = []
        
        findings.sort(key=lambda x: {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }.get(x.get('severity', 'info'), 4))
        
        for i, finding in enumerate(findings):
            severity = finding.get('severity', 'info')
            
            finding_html = f"""
            <div class="finding" data-severity="{severity}">
                <div class="finding-header" onclick="toggleFinding({i})">
                    <span class="finding-title">{finding.get('type', 'Unknown Finding')}</span>
                    <span class="finding-severity severity-badge-{severity}">{severity}</span>
                </div>
                <div class="finding-body" id="finding-body-{i}">
                    <div class="finding-detail">
                        <strong>Endpoint:</strong> {finding.get('endpoint', 'N/A')}
                    </div>
                    <div class="finding-detail">
                        <strong>Description:</strong> {finding.get('description', 'No description')}
                    </div>
                    <div class="finding-detail">
                        <strong>Evidence:</strong>
                        <pre style="background:#0d1b2a;padding:10px;border-radius:4px;overflow-x:auto;">{json.dumps(finding.get('evidence', {}), indent=2)}</pre>
                    </div>
                    <div class="remediation">
                        <h4>Remediation</h4>
                        <p>{finding.get('remediation', 'No remediation provided')}</p>
                    </div>
                </div>
            </div>
            """
            
            html_parts.append(finding_html)
        
        return '\n'.join(html_parts)