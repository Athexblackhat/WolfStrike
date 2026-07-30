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
import sys
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    FPDF = object


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
    
    # List of available fonts to try (ordered by preference)
    AVAILABLE_FONTS = [
        'Helvetica', 'Arial', 'DejaVu', 'Times', 'Courier',
        'freesans', 'FreeSans', 'LiberationSans',
    ]
    
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
        self.scan_status: str = 'initialized'
        self.errors: List[str] = []
        
        # Check FPDF availability
        self._check_fpdf_availability()
        
        # Initialize PDF
        self.pdf = None
        self._initialize_pdf()
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _check_fpdf_availability(self) -> bool:
        """
        Check if FPDF is available.
        
        Returns:
            True if FPDF is available
        """
        if not FPDF_AVAILABLE:
            self.errors.append("FPDF library is not installed. Install with: pip install fpdf2")
            self.scan_status = 'failed'
            return False
        
        try:
            # Test FPDF creation
            test_pdf = FPDF()
            test_pdf.close()
            return True
        except Exception as e:
            self.errors.append(f"FPDF initialization failed: {str(e)}")
            self.scan_status = 'failed'
            return False
    
    def _initialize_pdf(self) -> None:
        """Initialize PDF object with proper settings."""
        if not FPDF_AVAILABLE:
            return
        
        try:
            self.pdf = FPDF()
            self.pdf.set_auto_page_break(auto=True, margin=20)
            self.scan_status = 'initialized'
        except Exception as e:
            self.errors.append(f"Failed to initialize PDF: {str(e)}")
            self.scan_status = 'failed'
            self.pdf = None
    
    def _get_font_path(self, font_name: str) -> Optional[str]:
        """
        Get font file path if available.
        
        Args:
            font_name: Name of the font
            
        Returns:
            Path to font file or None
        """
        # Common font paths
        font_paths = [
            '/usr/share/fonts/',
            '/usr/local/share/fonts/',
            '~/.fonts/',
            'C:/Windows/Fonts/',
            '/Library/Fonts/',
        ]
        
        font_files = [
            f'{font_name}.ttf',
            f'{font_name}.otf',
            f'{font_name.lower()}.ttf',
            f'{font_name.lower()}.otf',
        ]
        
        import os.path
        for base_path in font_paths:
            expanded_path = os.path.expanduser(base_path)
            if not os.path.exists(expanded_path):
                continue
            
            for font_file in font_files:
                full_path = os.path.join(expanded_path, font_file)
                if os.path.exists(full_path):
                    return full_path
        
        return None
    
    def _validate_font(self, font_name: str) -> bool:
        """
        Validate if font is available.
        
        Args:
            font_name: Name of the font
            
        Returns:
            True if font is available
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.set_font(font_name, '', 10)
            return True
        except Exception:
            return False
    
    def _set_font_fallback(self, font_name: str = '', style: str = '', size: int = 10) -> bool:
        """
        Set font with fallback to Helvetica.
        
        Args:
            font_name: Font name
            style: Font style (B, I, U)
            size: Font size
            
        Returns:
            True if font was set
        """
        if not self.pdf:
            return False
        
        # Try requested font first
        if font_name:
            try:
                self.pdf.set_font(font_name, style, size)
                return True
            except Exception:
                pass
        
        # Try available fonts
        for font in self.AVAILABLE_FONTS:
            try:
                self.pdf.set_font(font, style, size)
                return True
            except Exception:
                continue
        
        # Last resort: try standard fonts
        try:
            self.pdf.set_font('Helvetica', style, size)
            return True
        except Exception:
            try:
                self.pdf.set_font('Arial', style, size)
                return True
            except Exception:
                return False
    
    def _safe_add_page(self) -> bool:
        """
        Safely add a page to PDF.
        
        Returns:
            True if page was added
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.add_page()
            return True
        except Exception as e:
            self.errors.append(f"Failed to add page: {str(e)}")
            return False
    
    def _safe_cell(self, w: float, h: float, txt: str = '', ln: int = 0, align: str = '', fill: bool = False) -> bool:
        """
        Safely add a cell to PDF.
        
        Args:
            w: Cell width
            h: Cell height
            txt: Cell text
            ln: Line break (0=no, 1=after, 2=before)
            align: Alignment (L, C, R)
            fill: Whether to fill cell
            
        Returns:
            True if cell was added
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.cell(w, h, txt, ln=ln, align=align, fill=fill)
            return True
        except Exception as e:
            self.errors.append(f"Failed to add cell: {str(e)}")
            return False
    
    def _safe_multi_cell(self, w: float, h: float, txt: str = '', align: str = '', fill: bool = False) -> bool:
        """
        Safely add a multi-cell to PDF.
        
        Args:
            w: Cell width
            h: Cell height
            txt: Cell text
            align: Alignment (L, C, R)
            fill: Whether to fill cell
            
        Returns:
            True if multi-cell was added
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.multi_cell(w, h, txt, align=align, fill=fill)
            return True
        except Exception as e:
            self.errors.append(f"Failed to add multi-cell: {str(e)}")
            return False
    
    def _safe_line(self, x1: float, y1: float, x2: float, y2: float) -> bool:
        """
        Safely add a line to PDF.
        
        Args:
            x1: Start X
            y1: Start Y
            x2: End X
            y2: End Y
            
        Returns:
            True if line was added
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.line(x1, y1, x2, y2)
            return True
        except Exception as e:
            self.errors.append(f"Failed to add line: {str(e)}")
            return False
    
    def _safe_get_y(self) -> float:
        """
        Safely get Y position.
        
        Returns:
            Y position or 0.0
        """
        if not self.pdf:
            return 0.0
        
        try:
            return self.pdf.get_y()
        except Exception:
            return 0.0
    
    def check_dependencies(self) -> Dict[str, bool]:
        """
        Check if all dependencies are available.
        
        Returns:
            Dictionary with dependency status
        """
        return {
            'fpdf_available': FPDF_AVAILABLE,
            'fpdf_working': self.pdf is not None,
        }
    
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
        # Check dependencies
        deps = self.check_dependencies()
        if not deps.get('fpdf_available', False):
            self.scan_status = 'failed'
            raise RuntimeError(
                "FPDF library is not installed. "
                "Install with: pip install fpdf2"
            )
        
        if not deps.get('fpdf_working', False):
            self.scan_status = 'failed'
            raise RuntimeError("PDF engine failed to initialize")
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wolfstrike_report_{target.replace('://', '_').replace('/', '_')}_{timestamp}.pdf"
        
        filepath = os.path.join(self.output_dir, filename)
        self.scan_status = 'running'
        
        try:
            # Reset PDF
            self._initialize_pdf()
            if not self.pdf:
                raise RuntimeError("Failed to initialize PDF")
            
            # Generate sections
            self._add_cover_page(target, scan_data)
            self._add_executive_summary(scan_data)
            self._add_findings_detail(scan_data)
            self._add_remediation_section(scan_data)
            self._add_appendix(scan_data)
            
            # Output PDF
            try:
                self.pdf.output(filepath)
            except Exception as e:
                raise RuntimeError(f"Failed to save PDF: {str(e)}")
            
            self.scan_status = 'completed'
            return filepath
            
        except Exception as e:
            self.scan_status = 'failed'
            self.errors.append(str(e))
            raise
    
    def _add_cover_page(self, target: str, scan_data: Dict[str, Any]) -> None:
        """
        Add report cover page.
        
        Args:
            target: Target URL
            scan_data: Scan data
        """
        if not self._safe_add_page():
            return
        
        self._safe_cell(0, 40, '', ln=True)
        
        # Title
        self._set_font_fallback('', 'B', 28)
        self._safe_cell(0, 15, 'WOLFSTRIKE', ln=True, align='C')
        
        self._set_font_fallback('', '', 16)
        self._safe_cell(0, 10, 'Security Assessment Report', ln=True, align='C')
        
        self._safe_cell(0, 20, '', ln=True)
        
        # Divider
        self._safe_set_draw_color(100, 100, 100)
        self._safe_line(30, self._safe_get_y(), 180, self._safe_get_y())
        self._safe_cell(0, 10, '', ln=True)
        
        # Details
        self._set_font_fallback('', '', 12)
        self._safe_cell(0, 8, f'Target: {target}', ln=True, align='C')
        
        scan_date = scan_data.get('scan_date', datetime.now().strftime('%Y-%m-%d'))
        self._safe_cell(0, 8, f'Date: {scan_date}', ln=True, align='C')
        
        self._safe_cell(0, 8, 'Tool Version: 1.0.0 (Shadowfang)', ln=True, align='C')
        self._safe_cell(0, 8, 'Author: ATHEX BLACK HAT', ln=True, align='C')
        self._safe_cell(0, 8, 'Team: Wolf Intelligence PK', ln=True, align='C')
    
    def _safe_set_fill_color(self, r: int, g: int, b: int) -> bool:
        """
        Safely set fill color.
        
        Args:
            r: Red (0-255)
            g: Green (0-255)
            b: Blue (0-255)
            
        Returns:
            True if color was set
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.set_fill_color(r, g, b)
            return True
        except Exception:
            return False
    
    def _safe_set_text_color(self, r: int, g: int, b: int) -> bool:
        """
        Safely set text color.
        
        Args:
            r: Red (0-255)
            g: Green (0-255)
            b: Blue (0-255)
            
        Returns:
            True if color was set
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.set_text_color(r, g, b)
            return True
        except Exception:
            return False
    
    def _safe_set_draw_color(self, r: int, g: int, b: int) -> bool:
        """
        Safely set draw color.
        
        Args:
            r: Red (0-255)
            g: Green (0-255)
            b: Blue (0-255)
            
        Returns:
            True if color was set
        """
        if not self.pdf:
            return False
        
        try:
            self.pdf.set_draw_color(r, g, b)
            return True
        except Exception:
            return False
    
    def _add_executive_summary(self, scan_data: Dict[str, Any]) -> None:
        """
        Add executive summary section.
        
        Args:
            scan_data: Scan data
        """
        if not self._safe_add_page():
            return
        
        self._set_font_fallback('', 'B', 18)
        self._safe_cell(0, 12, 'Executive Summary', ln=True)
        self._safe_cell(0, 5, '', ln=True)
        
        findings = scan_data.get('findings', [])
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        self._set_font_fallback('', '', 11)
        
        total_vulns = len(findings)
        
        self._safe_cell(0, 7, f'Total Vulnerabilities Found: {total_vulns}', ln=True)
        self._safe_cell(0, 7, f'Critical: {severity_counts["critical"]}', ln=True)
        self._safe_cell(0, 7, f'High: {severity_counts["high"]}', ln=True)
        self._safe_cell(0, 7, f'Medium: {severity_counts["medium"]}', ln=True)
        self._safe_cell(0, 7, f'Low: {severity_counts["low"]}', ln=True)
        self._safe_cell(0, 7, f'Info: {severity_counts["info"]}', ln=True)
        
        self._safe_cell(0, 10, '', ln=True)
        
        overall_risk = 'Critical' if severity_counts['critical'] > 0 else \
                       'High' if severity_counts['high'] > 3 else \
                       'Medium' if severity_counts['medium'] > 5 else \
                       'Low' if total_vulns > 0 else 'None'
        
        self._set_font_fallback('', 'B', 14)
        self._safe_cell(0, 10, f'Overall Risk Level: {overall_risk}', ln=True)
    
    def _add_findings_detail(self, scan_data: Dict[str, Any]) -> None:
        """
        Add detailed findings section.
        
        Args:
            scan_data: Scan data
        """
        if not self._safe_add_page():
            return
        
        self._set_font_fallback('', 'B', 18)
        self._safe_cell(0, 12, 'Detailed Findings', ln=True)
        self._safe_cell(0, 5, '', ln=True)
        
        findings = scan_data.get('findings', [])
        
        findings.sort(key=lambda x: {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }.get(x.get('severity', 'info'), 4))
        
        for i, finding in enumerate(findings[:50], 1):
            severity = finding.get('severity', 'info')
            
            if self._safe_get_y() > 240:
                if not self._safe_add_page():
                    break
            
            color = self.SEVERITY_COLORS.get(severity, (100, 100, 100))
            self._safe_set_fill_color(*color)
            self._safe_set_text_color(255, 255, 255)
            self._set_font_fallback('', 'B', 10)
            self._safe_cell(0, 7, f'  #{i}  {finding.get("type", "Unknown")}  -  {severity.upper()}', ln=True, fill=True)
            
            self._safe_set_text_color(0, 0, 0)
            self._set_font_fallback('', '', 9)
            
            endpoint = finding.get('endpoint', 'N/A')
            self._safe_cell(0, 6, f'Endpoint: {endpoint}', ln=True)
            
            description = finding.get('description', 'No description')
            self._safe_multi_cell(0, 5, f'Description: {description}')
            
            remediation = finding.get('remediation', 'No remediation provided')
            self._safe_multi_cell(0, 5, f'Remediation: {remediation}')
            
            self._safe_cell(0, 3, '', ln=True)
    
    def _add_remediation_section(self, scan_data: Dict[str, Any]) -> None:
        """
        Add remediation recommendations section.
        
        Args:
            scan_data: Scan data
        """
        if not self._safe_add_page():
            return
        
        self._set_font_fallback('', 'B', 18)
        self._safe_cell(0, 12, 'Remediation Recommendations', ln=True)
        self._safe_cell(0, 5, '', ln=True)
        
        self._set_font_fallback('', '', 10)
        
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
            self._safe_cell(5, 7, '-', ln=False)
            self._safe_cell(0, 7, rec, ln=True)
        
        self._safe_cell(0, 10, '', ln=True)
        
        self._set_font_fallback('', 'B', 14)
        self._safe_cell(0, 10, 'Priority Actions', ln=True)
        
        findings = scan_data.get('findings', [])
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        
        if critical_findings:
            for finding in critical_findings[:5]:
                self._set_font_fallback('', '', 10)
                self._safe_cell(0, 7, f'[CRITICAL] {finding.get("type", "Unknown")} - {finding.get("endpoint", "N/A")}', ln=True)
    
    def _add_appendix(self, scan_data: Dict[str, Any]) -> None:
        """
        Add appendix with scan details.
        
        Args:
            scan_data: Scan data
        """
        if not self._safe_add_page():
            return
        
        self._set_font_fallback('', 'B', 18)
        self._safe_cell(0, 12, 'Appendix - Scan Details', ln=True)
        self._safe_cell(0, 5, '', ln=True)
        
        self._set_font_fallback('', '', 10)
        
        self._safe_cell(0, 7, f'Scan Date: {scan_data.get("scan_date", "N/A")}', ln=True)
        self._safe_cell(0, 7, f'Scan Duration: {scan_data.get("scan_duration", "N/A")}', ln=True)
        self._safe_cell(0, 7, f'Target: {scan_data.get("target", "N/A")}', ln=True)
        self._safe_cell(0, 7, f'Tool Version: 1.0.0 (Shadowfang)', ln=True)
        
        self._safe_cell(0, 5, '', ln=True)
        
        modules = scan_data.get('modules_executed', [])
        if modules:
            self._safe_cell(0, 7, f'Modules Executed: {len(modules)}', ln=True)
            for module in modules[:20]:
                self._safe_cell(0, 6, f'  - {module}', ln=True)
