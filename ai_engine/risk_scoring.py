# ai_engine/risk_scoring.py

"""
Risk Scoring Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Machine learning based risk scoring system that calculates
vulnerability severity and overall application risk levels
using multiple weighted factors.
"""

import math
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import statistics


class RiskLevel(Enum):
    """Risk levels for vulnerabilities and applications."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class ImpactArea(Enum):
    """Areas of impact for vulnerabilities."""
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    ACCOUNTABILITY = "accountability"
    COMPLIANCE = "compliance"
    REPUTATION = "reputation"
    FINANCIAL = "financial"


@dataclass
class RiskFactor:
    """Individual risk factor for scoring."""
    name: str
    weight: float
    value: float
    description: str
    category: str


@dataclass
class VulnerabilityRisk:
    """Risk assessment for a single vulnerability."""
    vulnerability_id: str
    vulnerability_type: str
    risk_level: RiskLevel
    score: float
    cvss_base: float
    impact_scores: Dict[ImpactArea, float]
    risk_factors: List[RiskFactor]
    confidence: float
    exploitability_score: float
    remediation_difficulty: str


@dataclass
class ApplicationRisk:
    """Overall application risk assessment."""
    target: str
    overall_risk_level: RiskLevel
    overall_score: float
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_trend: str
    top_risks: List[VulnerabilityRisk]
    recommendations: List[str]


class RiskScorer:
    """
    Advanced risk scoring engine.
    
    Calculates risk scores for vulnerabilities and applications
    using weighted factor analysis and CVSS-based methodology.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the risk scorer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.cvss_version = self.config.get('cvss_version', '3.1')
        self.organization_risk_tolerance = self.config.get('risk_tolerance', 'medium')
        self.enable_business_impact = self.config.get('enable_business_impact', True)
        
        self.vulnerability_risks: List[VulnerabilityRisk] = []
        self.risk_history: List[Dict[str, Any]] = []
        
        self._initialize_default_weights()
    
    def _initialize_default_weights(self) -> None:
        """Initialize default risk factor weights."""
        
        self.impact_weights: Dict[ImpactArea, float] = {
            ImpactArea.CONFIDENTIALITY: 0.30,
            ImpactArea.INTEGRITY: 0.25,
            ImpactArea.AVAILABILITY: 0.20,
            ImpactArea.ACCOUNTABILITY: 0.10,
            ImpactArea.COMPLIANCE: 0.10,
            ImpactArea.REPUTATION: 0.03,
            ImpactArea.FINANCIAL: 0.02,
        }
        
        self.vulnerability_type_weights: Dict[str, Dict[str, float]] = {
            'sqli': {
                'confidentiality': 0.9,
                'integrity': 0.8,
                'availability': 0.4,
                'exploitability': 0.8,
            },
            'xss': {
                'confidentiality': 0.7,
                'integrity': 0.6,
                'availability': 0.2,
                'exploitability': 0.7,
            },
            'rce': {
                'confidentiality': 1.0,
                'integrity': 1.0,
                'availability': 1.0,
                'exploitability': 0.9,
            },
            'lfi': {
                'confidentiality': 0.8,
                'integrity': 0.2,
                'availability': 0.1,
                'exploitability': 0.6,
            },
            'csrf': {
                'confidentiality': 0.5,
                'integrity': 0.6,
                'availability': 0.2,
                'exploitability': 0.5,
            },
            'ssrf': {
                'confidentiality': 0.8,
                'integrity': 0.5,
                'availability': 0.5,
                'exploitability': 0.7,
            },
            'idor': {
                'confidentiality': 0.8,
                'integrity': 0.5,
                'availability': 0.1,
                'exploitability': 0.6,
            },
            'xxe': {
                'confidentiality': 0.7,
                'integrity': 0.4,
                'availability': 0.5,
                'exploitability': 0.6,
            },
            'ssti': {
                'confidentiality': 0.9,
                'integrity': 0.9,
                'availability': 0.8,
                'exploitability': 0.7,
            },
        }
        
        self.exploit_maturity_weights = {
            'proof_of_concept': 0.9,
            'functional': 0.95,
            'automated': 1.0,
            'theoretical': 0.5,
            'not_defined': 0.8,
        }
        
        self.remediation_difficulty_weights = {
            'trivial': 0.9,
            'easy': 0.7,
            'moderate': 0.5,
            'difficult': 0.3,
            'very_difficult': 0.1,
        }
    
    def score_vulnerability(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        findings: Dict[str, Any],
        exploit_maturity: str = 'not_defined',
        remediation_difficulty: str = 'moderate',
    ) -> VulnerabilityRisk:
        """
        Calculate risk score for a single vulnerability.
        
        Args:
            vulnerability_id: Unique identifier
            vulnerability_type: Type of vulnerability
            findings: Dictionary of finding details
            exploit_maturity: Maturity of available exploits
            remediation_difficulty: Difficulty to fix
            
        Returns:
            VulnerabilityRisk object with calculated scores
        """
        risk_factors: List[RiskFactor] = []
        
        type_weights = self.vulnerability_type_weights.get(
            vulnerability_type.lower(),
            {
                'confidentiality': 0.5,
                'integrity': 0.5,
                'availability': 0.3,
                'exploitability': 0.5,
            }
        )
        
        confidentiality_score = type_weights.get('confidentiality', 0.5)
        integrity_score = type_weights.get('integrity', 0.5)
        availability_score = type_weights.get('availability', 0.3)
        
        risk_factors.append(RiskFactor(
            name="Confidentiality Impact",
            weight=self.impact_weights[ImpactArea.CONFIDENTIALITY],
            value=confidentiality_score,
            description="Impact on data confidentiality",
            category="impact"
        ))
        
        risk_factors.append(RiskFactor(
            name="Integrity Impact",
            weight=self.impact_weights[ImpactArea.INTEGRITY],
            value=integrity_score,
            description="Impact on data integrity",
            category="impact"
        ))
        
        risk_factors.append(RiskFactor(
            name="Availability Impact",
            weight=self.impact_weights[ImpactArea.AVAILABILITY],
            value=availability_score,
            description="Impact on service availability",
            category="impact"
        ))
        
        data_sensitivity = findings.get('data_sensitivity', 0.5)
        risk_factors.append(RiskFactor(
            name="Data Sensitivity",
            weight=0.15,
            value=data_sensitivity,
            description="Sensitivity of data at risk",
            category="context"
        ))
        
        authentication_required = findings.get('authentication_required', False)
        auth_factor = 0.6 if authentication_required else 0.9
        risk_factors.append(RiskFactor(
            name="Authentication Required",
            weight=0.10,
            value=auth_factor,
            description="Whether authentication is needed for exploitation",
            category="context"
        ))
        
        exploitability_base = type_weights.get('exploitability', 0.5)
        exploit_maturity_factor = self.exploit_maturity_weights.get(exploit_maturity, 0.8)
        exploitability_score = (exploitability_base + exploit_maturity_factor) / 2
        
        risk_factors.append(RiskFactor(
            name="Exploitability",
            weight=0.20,
            value=exploitability_score,
            description=f"Ease of exploitation (maturity: {exploit_maturity})",
            category="exploitability"
        ))
        
        impact_scores: Dict[ImpactArea, float] = {
            ImpactArea.CONFIDENTIALITY: confidentiality_score,
            ImpactArea.INTEGRITY: integrity_score,
            ImpactArea.AVAILABILITY: availability_score,
            ImpactArea.ACCOUNTABILITY: 0.5,
            ImpactArea.COMPLIANCE: 0.5,
            ImpactArea.REPUTATION: 0.5,
            ImpactArea.FINANCIAL: 0.3,
        }
        
        weighted_score = sum(
            factor.weight * factor.value
            for factor in risk_factors
        )
        
        normalized_score = min(10.0, weighted_score * 10.0)
        
        cvss_base = self._calculate_cvss_base(
            confidentiality_score,
            integrity_score,
            availability_score,
            exploitability_score
        )
        
        confidence = findings.get('confidence', 0.8)
        
        risk_level = self._determine_risk_level(normalized_score)
        
        remediation_weight = self.remediation_difficulty_weights.get(remediation_difficulty, 0.5)
        adjusted_score = normalized_score * (1 + (1 - remediation_weight) * 0.3)
        
        vulnerability_risk = VulnerabilityRisk(
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            risk_level=risk_level,
            score=round(min(10.0, adjusted_score), 2),
            cvss_base=round(cvss_base, 1),
            impact_scores=impact_scores,
            risk_factors=risk_factors,
            confidence=confidence,
            exploitability_score=round(exploitability_score, 2),
            remediation_difficulty=remediation_difficulty
        )
        
        self.vulnerability_risks.append(vulnerability_risk)
        return vulnerability_risk
    
    def _calculate_cvss_base(
        self,
        confidentiality: float,
        integrity: float,
        availability: float,
        exploitability: float
    ) -> float:
        """
        Calculate CVSS base score.
        
        Args:
            confidentiality: Confidentiality impact
            integrity: Integrity impact
            availability: Availability impact
            exploitability: Exploitability score
            
        Returns:
            CVSS base score (0.0 - 10.0)
        """
        impact_score = 1 - (
            (1 - confidentiality) *
            (1 - integrity) *
            (1 - availability)
        )
        
        impact_multiplier = 1.08 if impact_score > 0 else 0.0
        
        if impact_score == 0:
            return 0.0
        
        base_score = impact_multiplier * (impact_score * exploitability)
        base_score = min(10.0, max(0.0, base_score * 10.0))
        
        return base_score
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """
        Determine risk level from numerical score.
        
        Args:
            score: Numerical risk score (0.0 - 10.0)
            
        Returns:
            RiskLevel enum value
        """
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score >= 2.0:
            return RiskLevel.LOW
        elif score > 0:
            return RiskLevel.INFO
        else:
            return RiskLevel.NONE
    
    def score_application(
        self,
        target: str,
        vulnerabilities: Optional[List[VulnerabilityRisk]] = None
    ) -> ApplicationRisk:
        """
        Calculate overall application risk score.
        
        Args:
            target: Application target
            vulnerabilities: List of vulnerability risks (uses stored if None)
            
        Returns:
            ApplicationRisk object
        """
        if vulnerabilities is None:
            vulnerabilities = self.vulnerability_risks
        
        if not vulnerabilities:
            return ApplicationRisk(
                target=target,
                overall_risk_level=RiskLevel.NONE,
                overall_score=0.0,
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                risk_trend="stable",
                top_risks=[],
                recommendations=["No vulnerabilities found. Maintain current security posture."]
            )
        
        critical_count = sum(1 for v in vulnerabilities if v.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for v in vulnerabilities if v.risk_level == RiskLevel.MEDIUM)
        low_count = sum(1 for v in vulnerabilities if v.risk_level == RiskLevel.LOW)
        info_count = sum(1 for v in vulnerabilities if v.risk_level == RiskLevel.INFO)
        
        severity_multipliers = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 4.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.INFO: 0.5,
            RiskLevel.NONE: 0.0,
        }
        
        total_weighted_score = sum(
            v.score * severity_multipliers.get(v.risk_level, 1.0) * v.confidence
            for v in vulnerabilities
        )
        
        max_possible_score = sum(
            10.0 * severity_multipliers.get(v.risk_level, 1.0)
            for v in vulnerabilities
        )
        
        if max_possible_score > 0:
            normalized_score = (total_weighted_score / max_possible_score) * 10.0
        else:
            normalized_score = 0.0
        
        overall_risk_level = self._determine_risk_level(normalized_score)
        
        sorted_vulnerabilities = sorted(
            vulnerabilities,
            key=lambda x: x.score * severity_multipliers.get(x.risk_level, 1.0),
            reverse=True
        )
        
        top_risks = sorted_vulnerabilities[:5]
        
        recommendations = self._generate_application_recommendations(
            critical_count, high_count, medium_count, low_count,
            top_risks, overall_risk_level
        )
        
        if self.risk_history:
            previous_scores = [
                entry['score'] for entry in self.risk_history
                if entry['target'] == target
            ]
            if previous_scores:
                last_score = previous_scores[-1]
                if normalized_score > last_score * 1.2:
                    risk_trend = "increasing"
                elif normalized_score < last_score * 0.8:
                    risk_trend = "decreasing"
                else:
                    risk_trend = "stable"
            else:
                risk_trend = "first_assessment"
        else:
            risk_trend = "first_assessment"
        
        self.risk_history.append({
            'target': target,
            'score': normalized_score,
            'level': overall_risk_level.value,
            'vulnerability_count': len(vulnerabilities),
        })
        
        return ApplicationRisk(
            target=target,
            overall_risk_level=overall_risk_level,
            overall_score=round(normalized_score, 2),
            total_vulnerabilities=len(vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            risk_trend=risk_trend,
            top_risks=top_risks,
            recommendations=recommendations
        )
    
    def _generate_application_recommendations(
        self,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        top_risks: List[VulnerabilityRisk],
        risk_level: RiskLevel
    ) -> List[str]:
        """
        Generate prioritized recommendations.
        
        Args:
            critical_count: Number of critical vulnerabilities
            high_count: Number of high vulnerabilities
            medium_count: Number of medium vulnerabilities
            low_count: Number of low vulnerabilities
            top_risks: Top risk vulnerabilities
            risk_level: Overall risk level
            
        Returns:
            List of recommendation strings
        """
        recommendations: List[str] = []
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append(
                "URGENT: Immediate remediation required. Critical vulnerabilities pose "
                "imminent threat to organization."
            )
        
        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} critical vulnerabilities immediately. "
                "These represent the highest risk to the application."
            )
        
        if high_count > 0:
            recommendations.append(
                f"Remediate {high_count} high severity vulnerabilities within 48 hours."
            )
        
        if medium_count > 0:
            recommendations.append(
                f"Plan remediation for {medium_count} medium severity vulnerabilities "
                "within the next sprint."
            )
        
        for risk in top_risks[:3]:
            recommendations.append(
                f"Prioritize fix for {risk.vulnerability_type.upper()} "
                f"(Score: {risk.score}, Level: {risk.risk_level.value})"
            )
        
        recommendations.append(
            "Implement regular security testing cycle to identify new vulnerabilities early."
        )
        
        recommendations.append(
            "Consider implementing Web Application Firewall (WAF) as compensating control."
        )
        
        return recommendations
    
    def compare_risks(
        self,
        risk_a: VulnerabilityRisk,
        risk_b: VulnerabilityRisk
    ) -> Dict[str, Any]:
        """
        Compare two vulnerability risks.
        
        Args:
            risk_a: First vulnerability risk
            risk_b: Second vulnerability risk
            
        Returns:
            Dictionary with comparison results
        """
        score_diff = risk_a.score - risk_b.score
        
        if score_diff > 0:
            higher_risk = risk_a.vulnerability_type
            lower_risk = risk_b.vulnerability_type
        else:
            higher_risk = risk_b.vulnerability_type
            lower_risk = risk_a.vulnerability_type
        
        return {
            'score_difference': abs(score_diff),
            'higher_risk': higher_risk,
            'lower_risk': lower_risk,
            'cvss_difference': abs(risk_a.cvss_base - risk_b.cvss_base),
            'exploitability_difference': abs(
                risk_a.exploitability_score - risk_b.exploitability_score
            ),
            'recommendation': (
                f"Prioritize remediation of {higher_risk} over {lower_risk}"
            )
        }
    
    def get_risk_distribution(self) -> Dict[str, int]:
        """
        Get distribution of risk levels.
        
        Returns:
            Dictionary with risk level counts
        """
        distribution = defaultdict(int)
        
        for risk in self.vulnerability_risks:
            distribution[risk.risk_level.value] += 1
        
        return dict(distribution)
    
    def get_average_score_by_type(self) -> Dict[str, float]:
        """
        Get average risk score by vulnerability type.
        
        Returns:
            Dictionary mapping type to average score
        """
        type_scores: Dict[str, List[float]] = defaultdict(list)
        
        for risk in self.vulnerability_risks:
            type_scores[risk.vulnerability_type].append(risk.score)
        
        averages: Dict[str, float] = {}
        for vuln_type, scores in type_scores.items():
            averages[vuln_type] = round(statistics.mean(scores), 2)
        
        return averages
    
    def get_high_risk_vulnerabilities(
        self,
        threshold: float = 7.0
    ) -> List[VulnerabilityRisk]:
        """
        Get vulnerabilities above risk threshold.
        
        Args:
            threshold: Minimum risk score
            
        Returns:
            List of high risk vulnerabilities
        """
        return [
            risk for risk in self.vulnerability_risks
            if risk.score >= threshold
        ]
    
    def reset(self) -> None:
        """Reset all risk scoring data."""
        self.vulnerability_risks.clear()
        self.risk_history.clear()