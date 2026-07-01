"""
exceptions.py — Custom Exception Hierarchy
============================================
Adaptive AI for Cyber Threat Detection

Defines a structured exception hierarchy for the entire application.
Every module raises a specific exception type — never bare Exception objects.

Design Principles:
- Single Responsibility: each exception handles one failure domain
- Liskov Substitution: all exceptions inherit from CyberThreatBaseError
- Structured error codes for API response mapping (RFC 7807 Problem Details)

IEEE 29148: Exception handling is a non-functional requirement (NFR-ERR-001).

Author: B.Tech Capstone Project
"""

from typing import Any, Optional


# =============================================================================
# Base Exception
# =============================================================================

class CyberThreatBaseError(Exception):
    """Base exception for all application-specific errors.

    All custom exceptions in this application inherit from this class.
    This allows callers to catch the entire exception hierarchy with a
    single except clause when needed.

    Attributes:
        message: Human-readable error description.
        error_code: Machine-readable code for API error responses.
        details: Optional dictionary with additional context.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "CYBER_THREAT_ERROR",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialise the base exception.

        Args:
            message: Human-readable error message.
            error_code: Unique error code for API/logging correlation.
            details: Optional dictionary with structured error details.
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise the exception to a dictionary for API responses.

        Returns:
            Dictionary conforming to RFC 7807 Problem Details structure.
        """
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# Configuration Exceptions
# =============================================================================

class ConfigurationError(CyberThreatBaseError):
    """Raised when application configuration is invalid or missing.

    Examples:
        - Required environment variable not set
        - YAML configuration file malformed
        - Invalid threshold values
    """

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialise configuration exception.

        Args:
            message: Description of the configuration error.
            config_key: The specific config key that caused the error.
            details: Additional context.
        """
        _details = details or {}
        if config_key:
            _details["config_key"] = config_key
        super().__init__(
            message=message,
            error_code="CONFIG_ERROR",
            details=_details,
        )


class MissingEnvironmentVariableError(ConfigurationError):
    """Raised when a required environment variable is not set."""

    def __init__(self, variable_name: str) -> None:
        """Initialise with the missing variable name.

        Args:
            variable_name: Name of the missing environment variable.
        """
        super().__init__(
            message=f"Required environment variable '{variable_name}' is not set. "
                    f"Check your .env file against .env.example.",
            config_key=variable_name,
        )
        self.error_code = "MISSING_ENV_VAR"


# =============================================================================
# Data Exceptions
# =============================================================================

class DataError(CyberThreatBaseError):
    """Base class for all data pipeline errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "DATA_ERROR",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message=message, error_code=error_code, details=details)


class DataLoadError(DataError):
    """Raised when a dataset cannot be loaded from disk or remote source."""

    def __init__(
        self,
        source: str,
        reason: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialise data load error.

        Args:
            source: Path or URL where data load was attempted.
            reason: Specific reason the load failed.
            details: Additional context.
        """
        super().__init__(
            message=f"Failed to load data from '{source}': {reason}",
            error_code="DATA_LOAD_ERROR",
            details={"source": source, "reason": reason, **(details or {})},
        )


class DataValidationError(DataError):
    """Raised when data fails schema or quality validation checks."""

    def __init__(
        self,
        field: str,
        issue: str,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Initialise data validation error.

        Args:
            field: Name of the field that failed validation.
            issue: Description of the validation failure.
            details: Additional context.
        """
        super().__init__(
            message=f"Data validation failed for field '{field}': {issue}",
            error_code="DATA_VALIDATION_ERROR",
            details={"field": field, "issue": issue, **(details or {})},
        )


class DataPreprocessingError(DataError):
    """Raised when data preprocessing (cleaning, encoding) fails."""

    def __init__(self, step: str, reason: str) -> None:
        super().__init__(
            message=f"Preprocessing step '{step}' failed: {reason}",
            error_code="DATA_PREPROCESSING_ERROR",
            details={"step": step, "reason": reason},
        )


# =============================================================================
# Model Exceptions
# =============================================================================

class ModelError(CyberThreatBaseError):
    """Base class for all ML/DL model errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "MODEL_ERROR",
        model_name: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        _details = details or {}
        if model_name:
            _details["model_name"] = model_name
        super().__init__(message=message, error_code=error_code, details=_details)


class ModelNotTrainedError(ModelError):
    """Raised when inference is attempted on an untrained model."""

    def __init__(self, model_name: str) -> None:
        super().__init__(
            message=f"Model '{model_name}' has not been trained. "
                    f"Call .train() or .load() before .predict().",
            error_code="MODEL_NOT_TRAINED",
            model_name=model_name,
        )


class ModelNotFoundError(ModelError):
    """Raised when a saved model artifact cannot be found on disk."""

    def __init__(self, model_path: str) -> None:
        super().__init__(
            message=f"Model artifact not found at path: '{model_path}'.",
            error_code="MODEL_NOT_FOUND",
            details={"model_path": model_path},
        )


class ModelTrainingError(ModelError):
    """Raised when model training fails due to data or algorithm issues."""

    def __init__(self, model_name: str, reason: str) -> None:
        super().__init__(
            message=f"Training failed for model '{model_name}': {reason}",
            error_code="MODEL_TRAINING_ERROR",
            model_name=model_name,
            details={"reason": reason},
        )


class ModelInferenceError(ModelError):
    """Raised when model prediction/inference fails."""

    def __init__(self, model_name: str, reason: str) -> None:
        super().__init__(
            message=f"Inference failed for model '{model_name}': {reason}",
            error_code="MODEL_INFERENCE_ERROR",
            model_name=model_name,
            details={"reason": reason},
        )


# =============================================================================
# Detection Exceptions
# =============================================================================

class DetectionError(CyberThreatBaseError):
    """Base class for threat detection pipeline errors."""

    def __init__(
        self,
        message: str,
        threat_type: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        _details = details or {}
        if threat_type:
            _details["threat_type"] = threat_type
        super().__init__(
            message=message,
            error_code="DETECTION_ERROR",
            details=_details,
        )


class InvalidInputError(DetectionError):
    """Raised when user input fails validation before detection."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(
            message=f"Invalid input for field '{field}': {reason}",
            details={"field": field, "reason": reason},
        )
        self.error_code = "INVALID_INPUT"


# =============================================================================
# Explainability Exceptions
# =============================================================================

class ExplainabilityError(CyberThreatBaseError):
    """Raised when SHAP or LIME explanation generation fails."""

    def __init__(self, explainer_type: str, reason: str) -> None:
        super().__init__(
            message=f"{explainer_type} explanation failed: {reason}",
            error_code="EXPLAINABILITY_ERROR",
            details={"explainer_type": explainer_type, "reason": reason},
        )


# =============================================================================
# Database Exceptions
# =============================================================================

class DatabaseError(CyberThreatBaseError):
    """Base class for database operation errors."""

    def __init__(self, operation: str, reason: str) -> None:
        super().__init__(
            message=f"Database operation '{operation}' failed: {reason}",
            error_code="DATABASE_ERROR",
            details={"operation": operation, "reason": reason},
        )


class RecordNotFoundError(DatabaseError):
    """Raised when a requested database record does not exist."""

    def __init__(self, table: str, record_id: Any) -> None:
        super().__init__(
            operation="SELECT",
            reason=f"Record with id='{record_id}' not found in table '{table}'",
        )
        self.error_code = "RECORD_NOT_FOUND"


# =============================================================================
# Report Exceptions
# =============================================================================

class ReportGenerationError(CyberThreatBaseError):
    """Raised when PDF/CSV report generation fails."""

    def __init__(self, report_type: str, reason: str) -> None:
        super().__init__(
            message=f"Report generation failed for type '{report_type}': {reason}",
            error_code="REPORT_GENERATION_ERROR",
            details={"report_type": report_type, "reason": reason},
        )
