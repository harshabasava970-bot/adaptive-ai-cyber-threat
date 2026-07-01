"""
core — Application Core Infrastructure Package
================================================
Adaptive AI for Cyber Threat Detection

Exports the primary objects that every other module depends on.
Import from here rather than from individual modules to maintain
a clean public API for the core package.

Usage:
    from src.core import ConfigManager, setup_logging, get_logger
    from src.core import ThreatType, RiskLevel, ModelAlgorithm
    from src.core import CyberThreatBaseError, ModelNotTrainedError
    from src.core import BaseDetectionModel, PredictionResult, ModelMetrics
"""

from src.core.base_model import BaseDetectionModel, ModelMetrics, PredictionResult
from src.core.config import ConfigManager
from src.core.constants import (
    APP_NAME,
    APP_VERSION,
    MODELS_DIR,
    PROJECT_ROOT,
    RANDOM_SEED,
    DetectionStatus,
    ModelAlgorithm,
    RiskLevel,
    ThreatType,
)
from src.core.exceptions import (
    ConfigurationError,
    CyberThreatBaseError,
    DataError,
    DataLoadError,
    DataValidationError,
    DetectionError,
    ExplainabilityError,
    InvalidInputError,
    MissingEnvironmentVariableError,
    ModelInferenceError,
    ModelNotFoundError,
    ModelNotTrainedError,
    ModelTrainingError,
    ReportGenerationError,
)
from src.core.logger import get_logger, get_model_logger, get_security_logger, setup_logging

__all__ = [
    # Config
    "ConfigManager",
    # Logging
    "setup_logging",
    "get_logger",
    "get_security_logger",
    "get_model_logger",
    # Constants
    "APP_NAME",
    "APP_VERSION",
    "PROJECT_ROOT",
    "MODELS_DIR",
    "RANDOM_SEED",
    "ThreatType",
    "RiskLevel",
    "ModelAlgorithm",
    "DetectionStatus",
    # Exceptions
    "CyberThreatBaseError",
    "ConfigurationError",
    "MissingEnvironmentVariableError",
    "DataError",
    "DataLoadError",
    "DataValidationError",
    "DetectionError",
    "InvalidInputError",
    "ModelInferenceError",
    "ModelNotFoundError",
    "ModelNotTrainedError",
    "ModelTrainingError",
    "ExplainabilityError",
    "ReportGenerationError",
    # Base classes
    "BaseDetectionModel",
    "PredictionResult",
    "ModelMetrics",
]
