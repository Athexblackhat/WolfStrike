# modules/reporting/risk_calculator.py

"""
Risk Score Calculator
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Calculates risk scores for vulnerabilities and overall
application security posture using CVSS-based methodology.
"""

import math
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class RiskCalculator:
    """
    Vulnerability risk score calculator.
    
    Calculates risk scores using CVSS-based methodology
    with exploitability and impact factors.
    """
    
    SEVERITY_WEIGHTS = {
        'critical': 10.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 2.0,
        'info': 0.5,
    }
    
    EXPLOITABILITY_FACTORS = {
        'easy': 1.0,
        'moderate': 0.7,
        'difficult': 0.4,
        'very_difficult': 0.2,
    }
    
    IMPACT_FACTORS = {
        'confidentiality': 0.35,
        'integrity': 0.35,
        'availability': 0.30,
    }
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the risk calculator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
    
    def calculate_vulnerability_score(
        self,
        severity: str,
        exploitability: str = 'moderate',
        data_sensitivity: float = 0.5,
        authentication_required: bool = False,
    ) -> float:
        """
        Calculate risk score for a single vulnerability.
        
        Args:
            severity: Vulnerability severity
            exploitability: Ease of exploitation
            data_sensitivity: Sensitivity of affected data (0.0 - 1.0)
            authentication_required: Whether auth is needed
            
        Returns:
            Risk score (0.0 - 10.0)
        """
        base_weight = self.SEVERITY_WEIGHTS.get(severity, 2.0)
        exploit_factor = self.EXPLOITABILITY_FACTORS.get(exploitability, 0.7)
        
        auth_factor = 0.6 if authentication_required else 0.9
        
        impact_score = (
            self.IMPACT_FACTORS['confidentiality'] * data_sensitivity +
            self.IMPACT_FACTORS['integrity'] * data_sensitivity +
            self.IMPACT_FACTORS['availability'] * 0.5
        )
        
        score = base_weight * exploit_factor * auth_factor * (0.5 + impact_score)
        
        return round(min(10.0, max(0.0, score)), 1)
    
    def calculate_overall_risk(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate overall application risk score.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dictionary with overall risk assessment
        """
        if not findings:
            return {
                'risk_level': RiskLevel.NONE.value,
                'risk_score': 0.0,
                'total_vulnerabilities': 0,
            }
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        weighted_sum = (
            severity_counts['critical'] * 10.0 +
            severity_counts['high'] * 7.0 +
            severity_counts['medium'] * 4.0 +
            severity_counts['low'] * 2.0 +
            severity_counts['info'] * 0.5
        )
        
        total_count = sum(severity_counts.values())
        
        max_possible = total_count * 10.0
        
        if max_possible > 0:
            overall_score = (weighted_sum / max_possible) * 10.0
        else:
            overall_score = 0.0
        
        overall_score = round(min(10.0, overall_score), 1)
        
        if severity_counts['critical'] > 0:
            risk_level = RiskLevel.CRITICAL.value
        elif severity_counts['high'] > 3 or overall_score >= 7.0:
            risk_level = RiskLevel.HIGH.value
        elif severity_counts['medium'] > 5 or overall_score >= 4.0:
            risk_level = RiskLevel.MEDIUM.value
        elif total_count > 0:
            risk_level = RiskLevel.LOW.value
        else:
            risk_level = RiskLevel.NONE.value
        
        return {
            'risk_level': risk_level,
            'risk_score': overall_score,
            'total_vulnerabilities': total_count,
            'severity_counts': severity_counts,
            'weighted_sum': round(weighted_sum, 1),
        }
    
    def get_risk_trend(
        self,
        current_score: float,
        previous_scores: List[float]
    ) -> str:
        """
        Calculate risk trend direction.
        
        Args:
            current_score: Current risk score
            previous_scores: Historical risk scores
            
        Returns:
            Trend direction string
        """
        if not previous_scores:
            return "first_assessment"
        
        last_score = previous_scores[-1]
        
        if current_score > last_score * 1.2:
            return "increasing"
        elif current_score < last_score * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def prioritize_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize findings by calculated risk score.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Sorted list of prioritized findings
        """
        for finding in findings:
            severity = finding.get('severity', 'info')
            score = self.calculate_vulnerability_score(severity)
            finding['risk_score'] = score
        
        findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        return findings