# modules/reporting/__init__.py

"""
WOLFSTRIKE Reporting Module
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0
"""

from modules.reporting.pdf_generator import PDFGenerator
from modules.reporting.html_generator import HTMLGenerator
from modules.reporting.json_export import JSONExporter
from modules.reporting.terminal_report import TerminalReporter
from modules.reporting.mitre_mapping import MITREMapper
from modules.reporting.risk_calculator import RiskCalculator
from modules.reporting.remediation_guide import RemediationGuide

__all__ = [
    'PDFGenerator',
    'HTMLGenerator',
    'JSONExporter',
    'TerminalReporter',
    'MITREMapper',
    'RiskCalculator',
    'RemediationGuide',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'