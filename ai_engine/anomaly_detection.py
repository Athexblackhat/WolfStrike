# ai_engine/anomaly_detection.py

"""
Anomaly Detection Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Statistical anomaly detection system for identifying
unusual patterns in web application responses that may
indicate security vulnerabilities.
"""

import math
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import statistics


class AnomalyType(Enum):
    """Types of detectable anomalies."""
    STATISTICAL_OUTLIER = "statistical_outlier"
    PATTERN_DEVIATION = "pattern_deviation"
    FREQUENCY_SPIKE = "frequency_spike"
    SIZE_ANOMALY = "size_anomaly"
    TIME_ANOMALY = "time_anomaly"
    STRUCTURAL_ANOMALY = "structural_anomaly"
    CONTENT_ANOMALY = "content_anomaly"
    HEADER_ANOMALY = "header_anomaly"


class DetectionMethod(Enum):
    """Methods used for anomaly detection."""
    Z_SCORE = "z_score"
    MODIFIED_Z_SCORE = "modified_z_score"
    IQR = "iqr"
    MOVING_AVERAGE = "moving_average"
    EXPONENTIAL_SMOOTHING = "exponential_smoothing"
    CHI_SQUARED = "chi_squared"
    ENTROPY_BASED = "entropy_based"


@dataclass
class DataPoint:
    """Single data point for anomaly analysis."""
    value: float
    timestamp: float
    category: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    anomaly_type: AnomalyType
    detection_method: DetectionMethod
    data_point: DataPoint
    score: float
    threshold: float
    is_anomaly: bool
    severity: str
    description: str
    recommendation: str


class AnomalyDetector:
    """
    Statistical anomaly detection engine.
    
    Implements multiple statistical methods to detect
    anomalies in application behavior and responses.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.sensitivity = self.config.get('sensitivity', 0.95)
        self.min_data_points = self.config.get('min_data_points', 10)
        self.window_size = self.config.get('window_size', 50)
        self.enable_ensemble = self.config.get('enable_ensemble', True)
        
        self.data_points: Dict[str, List[DataPoint]] = defaultdict(list)
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.detected_anomalies: List[AnomalyResult] = []
        
        self.z_score_threshold = 2.5
        self.modified_z_score_threshold = 3.5
        self.iqr_multiplier = 1.5
    
    def add_data_point(self, data_point: DataPoint) -> None:
        """
        Add a data point for analysis.
        
        Args:
            data_point: DataPoint to add
        """
        self.data_points[data_point.category].append(data_point)
        
        if len(self.data_points[data_point.category]) > self.window_size * 2:
            self.data_points[data_point.category] = self.data_points[data_point.category][-self.window_size:]
    
    def detect_anomalies(
        self,
        category: str,
        new_value: float,
        source: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[AnomalyResult]:
        """
        Detect anomalies for a new data point.
        
        Args:
            category: Data category
            new_value: New observed value
            source: Source of the data
            metadata: Additional metadata
            
        Returns:
            List of AnomalyResult objects
        """
        data_point = DataPoint(
            value=new_value,
            timestamp=__import__('time').time(),
            category=category,
            source=source,
            metadata=metadata or {}
        )
        
        self.add_data_point(data_point)
        
        anomalies: List[AnomalyResult] = []
        historical_values = self.get_historical_values(category)
        
        if len(historical_values) < self.min_data_points:
            return anomalies
        
        z_score_result = self._z_score_detection(data_point, historical_values)
        if z_score_result.is_anomaly:
            anomalies.append(z_score_result)
        
        modified_z_result = self._modified_z_score_detection(data_point, historical_values)
        if modified_z_result.is_anomaly:
            anomalies.append(modified_z_result)
        
        iqr_result = self._iqr_detection(data_point, historical_values)
        if iqr_result.is_anomaly:
            anomalies.append(iqr_result)
        
        if len(historical_values) >= self.window_size:
            moving_avg_result = self._moving_average_detection(data_point, historical_values)
            if moving_avg_result.is_anomaly:
                anomalies.append(moving_avg_result)
        
        if self.enable_ensemble:
            ensemble_result = self._ensemble_decision(anomalies, data_point)
            if ensemble_result:
                anomalies.append(ensemble_result)
        
        self.detected_anomalies.extend(anomalies)
        return anomalies
    
    def get_historical_values(self, category: str) -> List[float]:
        """
        Get historical values for a category.
        
        Args:
            category: Data category
            
        Returns:
            List of historical values
        """
        points = self.data_points.get(category, [])
        return [p.value for p in points[:-1]]
    
    def _z_score_detection(
        self,
        data_point: DataPoint,
        historical_values: List[float]
    ) -> AnomalyResult:
        """
        Detect anomalies using Z-Score method.
        
        Args:
            data_point: New data point
            historical_values: Historical values
            
        Returns:
            AnomalyResult
        """
        if len(historical_values) < 2:
            return self._create_no_anomaly_result(data_point, DetectionMethod.Z_SCORE)
        
        mean = statistics.mean(historical_values)
        std_dev = statistics.stdev(historical_values)
        
        if std_dev == 0:
            is_anomaly = data_point.value != mean
            score = float('inf') if is_anomaly else 0.0
        else:
            score = abs(data_point.value - mean) / std_dev
            is_anomaly = score > self.z_score_threshold
        
        severity = self._calculate_severity(score, self.z_score_threshold)
        
        return AnomalyResult(
            anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
            detection_method=DetectionMethod.Z_SCORE,
            data_point=data_point,
            score=score,
            threshold=self.z_score_threshold,
            is_anomaly=is_anomaly,
            severity=severity,
            description=self._generate_description(
                "Z-Score", data_point, mean, std_dev, score, is_anomaly
            ),
            recommendation=self._generate_recommendation(is_anomaly, severity)
        )
    
    def _modified_z_score_detection(
        self,
        data_point: DataPoint,
        historical_values: List[float]
    ) -> AnomalyResult:
        """
        Detect anomalies using Modified Z-Score method.
        
        Args:
            data_point: New data point
            historical_values: Historical values
            
        Returns:
            AnomalyResult
        """
        if len(historical_values) < 3:
            return self._create_no_anomaly_result(data_point, DetectionMethod.MODIFIED_Z_SCORE)
        
        sorted_values = sorted(historical_values)
        median = statistics.median(sorted_values)
        
        deviations = [abs(v - median) for v in sorted_values]
        mad = statistics.median(deviations)
        
        if mad == 0:
            is_anomaly = data_point.value != median
            score = float('inf') if is_anomaly else 0.0
        else:
            score = 0.6745 * abs(data_point.value - median) / mad
            is_anomaly = score > self.modified_z_score_threshold
        
        severity = self._calculate_severity(score, self.modified_z_score_threshold)
        
        return AnomalyResult(
            anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
            detection_method=DetectionMethod.MODIFIED_Z_SCORE,
            data_point=data_point,
            score=score,
            threshold=self.modified_z_score_threshold,
            is_anomaly=is_anomaly,
            severity=severity,
            description=self._generate_description(
                "Modified Z-Score", data_point, median, mad, score, is_anomaly
            ),
            recommendation=self._generate_recommendation(is_anomaly, severity)
        )
    
    def _iqr_detection(
        self,
        data_point: DataPoint,
        historical_values: List[float]
    ) -> AnomalyResult:
        """
        Detect anomalies using IQR method.
        
        Args:
            data_point: New data point
            historical_values: Historical values
            
        Returns:
            AnomalyResult
        """
        if len(historical_values) < 4:
            return self._create_no_anomaly_result(data_point, DetectionMethod.IQR)
        
        sorted_values = sorted(historical_values)
        n = len(sorted_values)
        
        q1_index = int(n * 0.25)
        q3_index = int(n * 0.75)
        
        q1 = sorted_values[q1_index]
        q3 = sorted_values[q3_index]
        
        iqr = q3 - q1
        
        if iqr == 0:
            is_anomaly = data_point.value < q1 or data_point.value > q3
            score = float('inf') if is_anomaly else 0.0
        else:
            lower_bound = q1 - (self.iqr_multiplier * iqr)
            upper_bound = q3 + (self.iqr_multiplier * iqr)
            is_anomaly = data_point.value < lower_bound or data_point.value > upper_bound
            
            if is_anomaly:
                distance = min(
                    abs(data_point.value - lower_bound),
                    abs(data_point.value - upper_bound)
                )
                score = distance / iqr
            else:
                score = 0.0
        
        severity = self._calculate_severity(score, self.iqr_multiplier)
        
        return AnomalyResult(
            anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
            detection_method=DetectionMethod.IQR,
            data_point=data_point,
            score=score,
            threshold=self.iqr_multiplier,
            is_anomaly=is_anomaly,
            severity=severity,
            description=self._generate_description(
                "IQR", data_point, q1, q3, score, is_anomaly
            ),
            recommendation=self._generate_recommendation(is_anomaly, severity)
        )
    
    def _moving_average_detection(
        self,
        data_point: DataPoint,
        historical_values: List[float]
    ) -> AnomalyResult:
        """
        Detect anomalies using Moving Average method.
        
        Args:
            data_point: New data point
            historical_values: Historical values
            
        Returns:
            AnomalyResult
        """
        window = historical_values[-self.window_size:]
        
        if len(window) < 2:
            return self._create_no_anomaly_result(data_point, DetectionMethod.MOVING_AVERAGE)
        
        moving_avg = statistics.mean(window)
        moving_std = statistics.stdev(window) if len(window) >= 2 else 0
        
        if moving_std == 0:
            is_anomaly = data_point.value != moving_avg
            score = float('inf') if is_anomaly else 0.0
        else:
            score = abs(data_point.value - moving_avg) / moving_std
            is_anomaly = score > self.z_score_threshold
        
        severity = self._calculate_severity(score, self.z_score_threshold)
        
        return AnomalyResult(
            anomaly_type=AnomalyType.TIME_ANOMALY,
            detection_method=DetectionMethod.MOVING_AVERAGE,
            data_point=data_point,
            score=score,
            threshold=self.z_score_threshold,
            is_anomaly=is_anomaly,
            severity=severity,
            description=self._generate_description(
                "Moving Average", data_point, moving_avg, moving_std, score, is_anomaly
            ),
            recommendation=self._generate_recommendation(is_anomaly, severity)
        )
    
    def _ensemble_decision(
        self,
        individual_results: List[AnomalyResult],
        data_point: DataPoint
    ) -> Optional[AnomalyResult]:
        """
        Make ensemble decision based on multiple detection methods.
        
        Args:
            individual_results: Results from individual methods
            data_point: Original data point
            
        Returns:
            Combined AnomalyResult or None
        """
        if not individual_results:
            return None
        
        anomaly_count = sum(1 for r in individual_results if r.is_anomaly)
        total_methods = len(individual_results)
        ensemble_score = anomaly_count / total_methods
        
        is_anomaly = ensemble_score >= 0.5
        
        if is_anomaly:
            severity = "high" if ensemble_score >= 0.75 else "medium"
        else:
            severity = "low"
        
        return AnomalyResult(
            anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
            detection_method=DetectionMethod.EXPONENTIAL_SMOOTHING,
            data_point=data_point,
            score=ensemble_score,
            threshold=0.5,
            is_anomaly=is_anomaly,
            severity=severity,
            description=f"Ensemble decision: {anomaly_count}/{total_methods} methods detected anomaly",
            recommendation=self._generate_recommendation(is_anomaly, severity)
        )
    
    def _create_no_anomaly_result(
        self,
        data_point: DataPoint,
        method: DetectionMethod
    ) -> AnomalyResult:
        """
        Create a result indicating no anomaly.
        
        Args:
            data_point: Data point
            method: Detection method used
            
        Returns:
            AnomalyResult with no anomaly
        """
        return AnomalyResult(
            anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
            detection_method=method,
            data_point=data_point,
            score=0.0,
            threshold=0.0,
            is_anomaly=False,
            severity="none",
            description="Insufficient data for analysis",
            recommendation="Collect more data points for reliable analysis"
        )
    
    def _calculate_severity(self, score: float, threshold: float) -> str:
        """
        Calculate severity based on score relative to threshold.
        
        Args:
            score: Anomaly score
            threshold: Detection threshold
            
        Returns:
            Severity string
        """
        if score == float('inf'):
            return "critical"
        
        ratio = score / threshold if threshold > 0 else score
        
        if ratio > 5.0:
            return "critical"
        elif ratio > 3.0:
            return "high"
        elif ratio > 2.0:
            return "medium"
        elif ratio > 1.0:
            return "low"
        else:
            return "info"
    
    def _generate_description(
        self,
        method_name: str,
        data_point: DataPoint,
        reference_value: float,
        spread_value: float,
        score: float,
        is_anomaly: bool
    ) -> str:
        """
        Generate human-readable description.
        
        Args:
            method_name: Name of detection method
            data_point: Data point being analyzed
            reference_value: Reference value (mean/median)
            spread_value: Spread value (std dev/MAD/IQR)
            score: Anomaly score
            is_anomaly: Whether anomaly was detected
            
        Returns:
            Description string
        """
        if is_anomaly:
            return (
                f"{method_name} detected anomaly: value {data_point.value:.4f} "
                f"deviates from reference {reference_value:.4f} "
                f"with spread {spread_value:.4f} (score: {score:.2f})"
            )
        else:
            return (
                f"{method_name}: value {data_point.value:.4f} "
                f"within normal range (score: {score:.2f})"
            )
    
    def _generate_recommendation(self, is_anomaly: bool, severity: str) -> str:
        """
        Generate recommendation based on detection result.
        
        Args:
            is_anomaly: Whether anomaly was detected
            severity: Severity of anomaly
            
        Returns:
            Recommendation string
        """
        if not is_anomaly:
            return "No action required."
        
        if severity in ["critical", "high"]:
            return "Immediate investigation required. This anomaly may indicate active exploitation."
        elif severity == "medium":
            return "Investigate this anomaly. It may indicate a vulnerability or misconfiguration."
        else:
            return "Monitor this anomaly. Consider adjusting detection sensitivity."
    
    def get_anomalies_by_severity(self, severity: str) -> List[AnomalyResult]:
        """
        Get anomalies filtered by severity.
        
        Args:
            severity: Severity level
            
        Returns:
            List of matching anomalies
        """
        return [
            anomaly for anomaly in self.detected_anomalies
            if anomaly.severity == severity
        ]
    
    def get_anomalies_by_category(self, category: str) -> List[AnomalyResult]:
        """
        Get anomalies for a specific data category.
        
        Args:
            category: Data category
            
        Returns:
            List of matching anomalies
        """
        return [
            anomaly for anomaly in self.detected_anomalies
            if anomaly.data_point.category == category
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get anomaly detection statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_analyzed = sum(len(points) for points in self.data_points.values())
        total_anomalies = len(self.detected_anomalies)
        
        severity_counts = Counter(a.severity for a in self.detected_anomalies)
        method_counts = Counter(a.detection_method.value for a in self.detected_anomalies)
        
        return {
            'total_data_points_analyzed': total_analyzed,
            'total_anomalies_detected': total_anomalies,
            'anomaly_rate': (total_anomalies / total_analyzed * 100) if total_analyzed > 0 else 0,
            'by_severity': dict(severity_counts),
            'by_method': dict(method_counts),
            'categories_tracked': len(self.data_points)
        }
    
    def reset(self) -> None:
        """Reset all anomaly detection data."""
        self.data_points.clear()
        self.baselines.clear()
        self.detected_anomalies.clear()