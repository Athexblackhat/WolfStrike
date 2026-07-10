# ai_engine/behavior_analysis.py

"""
Application Behavior Analysis Engine
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Profiles web application behavior to establish baselines
and detect anomalies that may indicate vulnerabilities.
"""

import time
import hashlib
import statistics
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque


class BehaviorCategory(Enum):
    """Categories of application behavior."""
    RESPONSE_TIME = "response_time"
    RESPONSE_SIZE = "response_size"
    ERROR_FREQUENCY = "error_frequency"
    REDIRECT_BEHAVIOR = "redirect_behavior"
    HEADER_CONSISTENCY = "header_consistency"
    COOKIE_BEHAVIOR = "cookie_behavior"
    RATE_LIMITING = "rate_limiting"
    INPUT_HANDLING = "input_handling"
    SESSION_MANAGEMENT = "session_management"
    ERROR_MESSAGE_CONSISTENCY = "error_message_consistency"


class BaselineStatus(Enum):
    """Status of behavior baseline."""
    NOT_ESTABLISHED = "not_established"
    IN_PROGRESS = "in_progress"
    ESTABLISHED = "established"
    OUTDATED = "outdated"


@dataclass
class BehaviorSample:
    """Single behavior sample data point."""
    category: BehaviorCategory
    value: float
    timestamp: float
    endpoint: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorBaseline:
    """Baseline for a behavior category."""
    category: BehaviorCategory
    mean: float
    median: float
    std_dev: float
    min_value: float
    max_value: float
    sample_count: int
    established_at: float
    confidence: float


@dataclass
class BehaviorAnomaly:
    """Detected behavioral anomaly."""
    category: BehaviorCategory
    observed_value: float
    expected_range: Tuple[float, float]
    deviation_factor: float
    timestamp: float
    endpoint: str
    severity: str
    description: str


class BehaviorAnalyzer:
    """
    Application behavior analysis engine.
    
    Establishes behavioral baselines and detects anomalies
    that may indicate security vulnerabilities or attacks.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the behavior analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.baseline_samples_required = self.config.get('baseline_samples', 20)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 2.5)
        self.max_history_per_category = self.config.get('max_history', 1000)
        self.analysis_window = self.config.get('analysis_window', 100)
        
        self.samples: Dict[BehaviorCategory, deque] = {
            category: deque(maxlen=self.max_history_per_category)
            for category in BehaviorCategory
        }
        
        self.baselines: Dict[BehaviorCategory, BehaviorBaseline] = {}
        self.anomalies: List[BehaviorAnomaly] = []
        self.endpoint_profiles: Dict[str, Dict[str, Any]] = {}
    
    def record_sample(
        self,
        category: BehaviorCategory,
        value: float,
        endpoint: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record a behavior sample for analysis.
        
        Args:
            category: Behavior category
            value: Observed value
            endpoint: Target endpoint
            metadata: Additional metadata
        """
        sample = BehaviorSample(
            category=category,
            value=value,
            timestamp=time.time(),
            endpoint=endpoint,
            metadata=metadata or {}
        )
        
        self.samples[category].append(sample)
        
        if endpoint not in self.endpoint_profiles:
            self.endpoint_profiles[endpoint] = {
                'first_seen': time.time(),
                'total_requests': 0,
                'error_count': 0,
                'categories': defaultdict(list)
            }
        
        self.endpoint_profiles[endpoint]['total_requests'] += 1
        if metadata and metadata.get('is_error', False):
            self.endpoint_profiles[endpoint]['error_count'] += 1
        
        self.endpoint_profiles[endpoint]['categories'][category.value].append(value)
    
    def establish_baseline(
        self,
        category: BehaviorCategory,
        force: bool = False
    ) -> Optional[BehaviorBaseline]:
        """
        Establish baseline for a behavior category.
        
        Args:
            category: Behavior category to baseline
            force: Force re-establish baseline even if already exists
            
        Returns:
            BehaviorBaseline if enough samples, None otherwise
        """
        samples = list(self.samples[category])
        
        if len(samples) < self.baseline_samples_required:
            return None
        
        if category in self.baselines and not force:
            return self.baselines[category]
        
        values = [s.value for s in samples]
        
        if not values:
            return None
        
        mean_value = statistics.mean(values)
        median_value = statistics.median(values)
        
        if len(values) >= 2:
            std_dev = statistics.stdev(values)
        else:
            std_dev = 0.0
        
        baseline = BehaviorBaseline(
            category=category,
            mean=mean_value,
            median=median_value,
            std_dev=std_dev,
            min_value=min(values),
            max_value=max(values),
            sample_count=len(values),
            established_at=time.time(),
            confidence=min(1.0, len(values) / (self.baseline_samples_required * 2))
        )
        
        self.baselines[category] = baseline
        return baseline
    
    def establish_all_baselines(self) -> Dict[BehaviorCategory, Optional[BehaviorBaseline]]:
        """
        Establish baselines for all behavior categories.
        
        Returns:
            Dictionary of category to baseline
        """
        results: Dict[BehaviorCategory, Optional[BehaviorBaseline]] = {}
        
        for category in BehaviorCategory:
            baseline = self.establish_baseline(category)
            results[category] = baseline
        
        return results
    
    def detect_anomaly(
        self,
        category: BehaviorCategory,
        value: float,
        endpoint: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[BehaviorAnomaly]:
        """
        Detect if a behavior sample is anomalous.
        
        Args:
            category: Behavior category
            value: Observed value
            endpoint: Target endpoint
            metadata: Additional metadata
            
        Returns:
            BehaviorAnomaly if anomaly detected, None otherwise
        """
        if category not in self.baselines:
            return None
        
        baseline = self.baselines[category]
        
        if baseline.std_dev == 0:
            if value != baseline.mean:
                deviation = float('inf')
            else:
                return None
        else:
            deviation = abs(value - baseline.mean) / baseline.std_dev
        
        if deviation < self.anomaly_threshold:
            return None
        
        expected_min = baseline.mean - (self.anomaly_threshold * baseline.std_dev)
        expected_max = baseline.mean + (self.anomaly_threshold * baseline.std_dev)
        
        if deviation > 5.0:
            severity = "critical"
        elif deviation > 4.0:
            severity = "high"
        elif deviation > 3.0:
            severity = "medium"
        else:
            severity = "low"
        
        description = self._describe_anomaly(category, value, baseline, deviation)
        
        anomaly = BehaviorAnomaly(
            category=category,
            observed_value=value,
            expected_range=(expected_min, expected_max),
            deviation_factor=deviation,
            timestamp=time.time(),
            endpoint=endpoint,
            severity=severity,
            description=description
        )
        
        self.anomalies.append(anomaly)
        return anomaly
    
    def _describe_anomaly(
        self,
        category: BehaviorCategory,
        value: float,
        baseline: BehaviorBaseline,
        deviation: float
    ) -> str:
        """
        Generate human-readable anomaly description.
        
        Args:
            category: Behavior category
            value: Observed value
            baseline: Established baseline
            deviation: Deviation factor
            
        Returns:
            Description string
        """
        descriptions = {
            BehaviorCategory.RESPONSE_TIME: (
                f"Response time of {value:.3f}s deviates {deviation:.1f} standard deviations "
                f"from baseline mean of {baseline.mean:.3f}s. Possible injection or DoS condition."
            ),
            BehaviorCategory.RESPONSE_SIZE: (
                f"Response size of {value:.0f} bytes deviates {deviation:.1f} standard deviations "
                f"from baseline. Possible data exfiltration or error leakage."
            ),
            BehaviorCategory.ERROR_FREQUENCY: (
                f"Error frequency spike detected. Deviation factor of {deviation:.1f} "
                f"indicates potential vulnerability triggering."
            ),
            BehaviorCategory.REDIRECT_BEHAVIOR: (
                f"Unusual redirect behavior detected. Deviation of {deviation:.1f} "
                f"from normal pattern. Possible open redirect or SSRF."
            ),
            BehaviorCategory.HEADER_CONSISTENCY: (
                f"Header inconsistency detected with deviation factor of {deviation:.1f}. "
                f"Possible header injection or cache poisoning."
            ),
            BehaviorCategory.INPUT_HANDLING: (
                f"Abnormal input handling detected. Deviation of {deviation:.1f} "
                f"suggests potential injection vulnerability."
            ),
        }
        
        return descriptions.get(
            category,
            f"Anomalous behavior detected with deviation factor of {deviation:.1f}."
        )
    
    def get_endpoint_profile(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Get behavioral profile for an endpoint.
        
        Args:
            endpoint: Target endpoint
            
        Returns:
            Profile dictionary or None
        """
        return self.endpoint_profiles.get(endpoint)
    
    def get_anomalies_by_severity(self, severity: str) -> List[BehaviorAnomaly]:
        """
        Get anomalies filtered by severity.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of matching anomalies
        """
        return [
            anomaly for anomaly in self.anomalies
            if anomaly.severity == severity
        ]
    
    def get_anomalies_by_category(
        self,
        category: BehaviorCategory
    ) -> List[BehaviorAnomaly]:
        """
        Get anomalies filtered by category.
        
        Args:
            category: Behavior category to filter by
            
        Returns:
            List of matching anomalies
        """
        return [
            anomaly for anomaly in self.anomalies
            if anomaly.category == category
        ]
    
    def get_baseline_status(self) -> Dict[str, Any]:
        """
        Get status of all baselines.
        
        Returns:
            Dictionary with baseline status information
        """
        status = {
            'total_categories': len(BehaviorCategory),
            'established_baselines': len(self.baselines),
            'total_samples_collected': sum(len(samples) for samples in self.samples.values()),
            'categories': {}
        }
        
        for category in BehaviorCategory:
            sample_count = len(self.samples[category])
            
            if category in self.baselines:
                baseline_status = BaselineStatus.ESTABLISHED
            elif sample_count > 0:
                baseline_status = BaselineStatus.IN_PROGRESS
            else:
                baseline_status = BaselineStatus.NOT_ESTABLISHED
            
            status['categories'][category.value] = {
                'status': baseline_status.value,
                'sample_count': sample_count,
                'required_samples': self.baseline_samples_required,
                'progress_percent': min(100, (sample_count / self.baseline_samples_required) * 100)
            }
        
        return status
    
    def get_recent_anomalies(self, count: int = 10) -> List[BehaviorAnomaly]:
        """
        Get most recent anomalies.
        
        Args:
            count: Number of recent anomalies to return
            
        Returns:
            List of recent anomalies
        """
        sorted_anomalies = sorted(
            self.anomalies,
            key=lambda x: x.timestamp,
            reverse=True
        )
        return sorted_anomalies[:count]
    
    def reset(self) -> None:
        """Reset all behavior data."""
        for category in BehaviorCategory:
            self.samples[category].clear()
        
        self.baselines.clear()
        self.anomalies.clear()
        self.endpoint_profiles.clear()