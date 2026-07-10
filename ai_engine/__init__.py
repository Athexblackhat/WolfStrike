# ai_engine/__init__.py

"""
WOLFSTRIKE AI Engine Package
Author: ATHEX BLACK HAT
Team: Wolf Intelligence PK
Version: 1.0.0

Provides machine learning and artificial intelligence capabilities
for intelligent vulnerability detection, payload generation,
false positive reduction, and risk assessment.
"""

from ai_engine.pattern_recognition import PatternRecognition
from ai_engine.payload_generator import PayloadGenerator
from ai_engine.false_positive import FalsePositiveFilter
from ai_engine.behavior_analysis import BehaviorAnalyzer
from ai_engine.anomaly_detection import AnomalyDetector
from ai_engine.risk_scoring import RiskScorer

__all__ = [
    'PatternRecognition',
    'PayloadGenerator',
    'FalsePositiveFilter',
    'BehaviorAnalyzer',
    'AnomalyDetector',
    'RiskScorer',
]

__version__ = '1.0.0'
__author__ = 'ATHEX BLACK HAT'
__team__ = 'Wolf Intelligence PK'