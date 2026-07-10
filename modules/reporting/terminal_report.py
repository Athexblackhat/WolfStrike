# modules/reporting/terminal_report.py

"""
Terminal Report Generator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Generates formatted terminal output for scan results
with color-coded severity and real-time statistics.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime


class TerminalReporter:
    """
    Terminal report generator.
    
    Creates formatted console output for scan results
    with color coding and structured display.
    """
    
    SEVERITY_COLORS = {
        'critical': '\033[91m',
        'high': '\033[93m',
        'medium': '\033[33m',
        'low': '\033[92m',
        'info': '\033[94m',
        'reset': '\033[0m',
    }
    
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the terminal reporter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.no_color = self.config.get('no_color', False)
    
    def _colorize(self, text: str, severity: str) -> str:
        """
        Apply color based on severity.
        
        Args:
            text: Text to colorize
            severity: Severity level
            
        Returns:
            Colorized text string
        """
        if self.no_color:
            return text
        
        color = self.SEVERITY_COLORS.get(severity, '')
        return f"{color}{text}{self.SEVERITY_COLORS['reset']}"
    
    def print_header(self, target: str) -> None:
        """
        Print report header.
        
        Args:
            target: Target URL
        """
        print()
        print("=" * 70)
        print(f"{self.BOLD}  WOLFSTRIKE Security Assessment Report{self.RESET}")
        print("=" * 70)
        print(f"  Target:     {target}")
        print(f"  Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Tool:       v1.0.0 (Shadowfang)")
        print(f"  Author:     ATHEX BLACK HAT")
        print(f"  Team:       Wolf Intelligence PK")
        print("=" * 70)
        print()
    
    def print_summary(self, scan_data: Dict[str, Any]) -> None:
        """
        Print scan summary.
        
        Args:
            scan_data: Scan results data
        """
        findings = scan_data.get('findings', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        print(f"{self.BOLD}[SUMMARY]{self.RESET}")
        print(f"  Total Vulnerabilities: {len(findings)}")
        
        if severity_counts['critical'] > 0:
            print(f"  Critical: {self._colorize(str(severity_counts['critical']), 'critical')}")
        else:
            print(f"  Critical: 0")
        
        if severity_counts['high'] > 0:
            print(f"  High:     {self._colorize(str(severity_counts['high']), 'high')}")
        else:
            print(f"  High:     0")
        
        print(f"  Medium:   {severity_counts['medium']}")
        print(f"  Low:      {severity_counts['low']}")
        print(f"  Info:     {severity_counts['info']}")
        
        overall = 'CRITICAL' if severity_counts['critical'] > 0 else \
                  'HIGH' if severity_counts['high'] > 3 else \
                  'MEDIUM' if severity_counts['medium'] > 5 else \
                  'LOW' if len(findings) > 0 else 'NONE'
        
        print(f"  Overall Risk: {self._colorize(overall, overall.lower())}")
        print()
    
    def print_findings(self, scan_data: Dict[str, Any], max_display: int = 50) -> None:
        """
        Print detailed findings.
        
        Args:
            scan_data: Scan results data
            max_display: Maximum findings to display
        """
        findings = scan_data.get('findings', [])
        
        if not findings:
            print(f"{self._colorize('[+] No vulnerabilities found!', 'low')}")
            return
        
        findings.sort(key=lambda x: {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }.get(x.get('severity', 'info'), 4))
        
        print(f"{self.BOLD}[FINDINGS]{self.RESET}")
        print()
        
        for i, finding in enumerate(findings[:max_display], 1):
            severity = finding.get('severity', 'info')
            
            print(f"  {self.BOLD}[{i}]{self.RESET} "
                  f"{self._colorize(finding.get('type', 'Unknown'), severity)} "
                  f"({self._colorize(severity.upper(), severity)})")
            
            endpoint = finding.get('endpoint', 'N/A')
            if endpoint:
                print(f"      Endpoint: {endpoint}")
            
            parameter = finding.get('parameter', '')
            if parameter:
                print(f"      Parameter: {parameter}")
            
            description = finding.get('description', 'No description')
            print(f"      Description: {description}")
            
            remediation = finding.get('remediation', '')
            if remediation:
                print(f"      Remediation: {remediation}")
            
            print()
        
        if len(findings) > max_display:
            print(f"  ... and {len(findings) - max_display} more findings")
            print()
    
    def print_module_summary(self, scan_data: Dict[str, Any]) -> None:
        """
        Print module execution summary.
        
        Args:
            scan_data: Scan results data
        """
        modules = scan_data.get('modules_executed', [])
        
        if modules:
            print(f"{self.BOLD}[MODULES EXECUTED]{self.RESET}")
            print(f"  Total: {len(modules)}")
            print()
    
    def generate(self, target: str, scan_data: Dict[str, Any]) -> None:
        """
        Generate complete terminal report.
        
        Args:
            target: Target URL
            scan_data: Scan results data
        """
        self.print_header(target)
        self.print_summary(scan_data)
        self.print_module_summary(scan_data)
        self.print_findings(scan_data)
        
        print("=" * 70)
        print(f"  Report generated by WOLFSTRIKE v1.0.0")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print()