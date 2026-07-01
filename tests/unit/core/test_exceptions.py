"""
test_exceptions.py — Unit Tests for Custom Exception Hierarchy
===============================================================
Adaptive AI for Cyber Threat Detection

IEEE 29119 Test Coverage:
  - TC-EXC-001: All exceptions inherit from CyberThreatBaseError
  - TC-EXC-002: to_dict() returns RFC 7807 compliant structure
  - TC-EXC-003: error_code is set correctly per exception type
  - TC-EXC-004: Details dict is populated correctly
  - TC-EXC-005: Exception messages are human-readable

Author: B.Tech Capstone Project
"""

import pytest

from src.core.exceptions import (
    ConfigurationError,
    CyberThreatBaseError,
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


class TestExceptionHierarchy:
    """TC-EXC-001: All exceptions must inherit from CyberThreatBaseError."""

    @pytest.mark.parametrize("exc_class,args", [
        (ConfigurationError, ("Config missing",)),
        (MissingEnvironmentVariableError, ("SECRET_KEY",)),
        (DataLoadError, ("data/raw/file.csv", "file not found")),
        (DataValidationError, ("email_body", "empty string")),
        (ModelNotTrainedError, ("phishing_model",)),
        (ModelNotFoundError, ("data/models/phishing.pkl",)),
        (ModelTrainingError, ("xgboost_url", "NaN in features")),
        (ModelInferenceError, ("distilbert_phishing", "CUDA OOM")),
        (InvalidInputError, ("url", "empty string not allowed")),
        (ExplainabilityError, ("SHAP", "background dataset missing")),
        (ReportGenerationError, ("pdf", "reportlab not installed")),
    ])
    def test_inherits_from_base(self, exc_class, args):
        """Every custom exception should be a CyberThreatBaseError."""
        exc = exc_class(*args)
        assert isinstance(exc, CyberThreatBaseError), (
            f"{exc_class.__name__} does not inherit from CyberThreatBaseError"
        )
        assert isinstance(exc, Exception)


class TestExceptionToDictMethod:
    """TC-EXC-002: to_dict() output must follow RFC 7807 structure."""

    def test_to_dict_has_required_keys(self):
        """to_dict() must contain error_code, message, and details."""
        exc = ModelNotTrainedError("phishing_bert")
        result = exc.to_dict()
        assert "error_code" in result
        assert "message" in result
        assert "details" in result

    def test_to_dict_error_code_is_string(self):
        """error_code in to_dict() must be a non-empty string."""
        exc = DataLoadError("data/raw/urls.csv", "permission denied")
        result = exc.to_dict()
        assert isinstance(result["error_code"], str)
        assert len(result["error_code"]) > 0

    def test_to_dict_message_is_human_readable(self):
        """Message in to_dict() should mention the problematic entity."""
        exc = ModelNotFoundError("data/models/missing_model.pkl")
        result = exc.to_dict()
        assert "data/models/missing_model.pkl" in result["message"]


class TestSpecificExceptions:
    """TC-EXC-003 / TC-EXC-004: Specific exceptions set correct fields."""

    def test_missing_env_var_error_code(self):
        """MissingEnvironmentVariableError should use MISSING_ENV_VAR code."""
        exc = MissingEnvironmentVariableError("DATABASE_URL")
        assert exc.error_code == "MISSING_ENV_VAR"
        assert "DATABASE_URL" in exc.message

    def test_data_load_error_details(self):
        """DataLoadError should include source and reason in details."""
        exc = DataLoadError("s3://bucket/file.csv", "access denied")
        assert exc.details["source"] == "s3://bucket/file.csv"
        assert exc.details["reason"] == "access denied"

    def test_data_validation_error_details(self):
        """DataValidationError should include field and issue in details."""
        exc = DataValidationError("url_length", "exceeds 2048 characters")
        assert exc.details["field"] == "url_length"
        assert exc.details["issue"] == "exceeds 2048 characters"

    def test_model_not_trained_error_message(self):
        """ModelNotTrainedError message should mention model name."""
        exc = ModelNotTrainedError("xgboost_url_detector")
        assert "xgboost_url_detector" in exc.message
        assert "train" in exc.message.lower() or "load" in exc.message.lower()

    def test_model_training_error_includes_reason(self):
        """ModelTrainingError details should contain the failure reason."""
        exc = ModelTrainingError("random_forest", "insufficient data")
        assert exc.details["reason"] == "insufficient data"

    def test_model_inference_error_error_code(self):
        """ModelInferenceError should use MODEL_INFERENCE_ERROR code."""
        exc = ModelInferenceError("distilbert", "tensor shape mismatch")
        assert exc.error_code == "MODEL_INFERENCE_ERROR"

    def test_invalid_input_error_code(self):
        """InvalidInputError should use INVALID_INPUT error code."""
        exc = InvalidInputError("email_body", "must not be empty")
        assert exc.error_code == "INVALID_INPUT"
        assert exc.details["field"] == "email_body"

    def test_explainability_error_details(self):
        """ExplainabilityError should record explainer_type and reason."""
        exc = ExplainabilityError("LIME", "model output shape unexpected")
        assert exc.details["explainer_type"] == "LIME"
        assert exc.details["reason"] == "model output shape unexpected"


class TestExceptionRepr:
    """TC-EXC-005: repr() output should be informative for debugging."""

    def test_repr_contains_class_name(self):
        """repr() should include the exception class name."""
        exc = ConfigurationError("bad config")
        assert "ConfigurationError" in repr(exc)

    def test_repr_contains_error_code(self):
        """repr() should include the error_code for quick identification."""
        exc = ModelNotFoundError("/path/to/model.pkl")
        assert "MODEL_NOT_FOUND" in repr(exc)
