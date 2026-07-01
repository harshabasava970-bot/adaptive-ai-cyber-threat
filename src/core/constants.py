"""
constants.py — Application-Wide Constants
==========================================
Adaptive AI for Cyber Threat Detection

All hard-coded values are centralised here. This prevents magic numbers/strings
scattered across the codebase and makes configuration changes trivial.

Design Pattern: Constant Module (no instantiation required)
IEEE 29148: Traceability — constants map directly to requirements.

Author: B.Tech Capstone Project
"""

from enum import Enum, unique
from pathlib import Path

# ---------------------------------------------------------------------------
# Project Root
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR: Path = PROJECT_ROOT / "config"
DATA_DIR: Path = PROJECT_ROOT / "data"
LOGS_DIR: Path = PROJECT_ROOT / "logs"
MODELS_DIR: Path = DATA_DIR / "models"
RAW_DATA_DIR: Path = DATA_DIR / "raw"
PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
REPORTS_DIR: Path = DATA_DIR / "reports"


# ---------------------------------------------------------------------------
# Application Metadata
# ---------------------------------------------------------------------------
APP_NAME: str = "AdaptiveAICyberThreat"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = (
    "Intelligent AI-based cybersecurity platform for multi-threat detection "
    "using Machine Learning, Deep Learning, and Explainable AI."
)


# ---------------------------------------------------------------------------
# Threat Categories (IEEE 7000 — AI transparency requirement)
# ---------------------------------------------------------------------------
@unique
class ThreatType(str, Enum):
    """Enumeration of all supported threat detection categories.

    Using str-based Enum ensures JSON serialisability without custom encoders.
    """

    PHISHING_EMAIL = "phishing_email"
    MALICIOUS_URL = "malicious_url"
    SUSPICIOUS_LOGIN = "suspicious_login"
    NETWORK_ANOMALY = "network_anomaly"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Risk Level Classification
# ---------------------------------------------------------------------------
@unique
class RiskLevel(str, Enum):
    """Standardised risk levels used across all detection modules.

    Maps to CVSS-inspired scoring ranges defined in settings.yaml.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Model Algorithm Names
# ---------------------------------------------------------------------------
@unique
class ModelAlgorithm(str, Enum):
    """Supported ML/DL algorithm identifiers.

    Used for model registry lookups and report generation.
    """

    DISTILBERT = "distilbert"
    BERT = "bert"
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    ISOLATION_FOREST = "isolation_forest"
    LOGISTIC_REGRESSION = "logistic_regression"


# ---------------------------------------------------------------------------
# Detection Status
# ---------------------------------------------------------------------------
@unique
class DetectionStatus(str, Enum):
    """Status of a detection inference request."""

    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# API Constants
# ---------------------------------------------------------------------------
API_V1_PREFIX: str = "/api/v1"
API_HEALTH_ENDPOINT: str = "/health"
API_DOCS_TITLE: str = "Adaptive AI Cyber Threat Detection API"

# HTTP Status Code aliases (for readability in test files)
HTTP_200_OK: int = 200
HTTP_201_CREATED: int = 201
HTTP_400_BAD_REQUEST: int = 400
HTTP_401_UNAUTHORIZED: int = 401
HTTP_403_FORBIDDEN: int = 403
HTTP_404_NOT_FOUND: int = 404
HTTP_422_UNPROCESSABLE: int = 422
HTTP_500_INTERNAL_ERROR: int = 500


# ---------------------------------------------------------------------------
# Feature Engineering Constants
# ---------------------------------------------------------------------------
# URL Feature extraction
URL_MAX_LENGTH: int = 2048
URL_SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "paypal", "ebay", "amazon", "microsoft", "apple",
    "google", "facebook", "confirm", "password", "credential",
    "wallet", "bitcoin", "free", "lucky", "winner", "prize",
]

# Email Feature extraction
EMAIL_MAX_SUBJECT_LENGTH: int = 998
EMAIL_MIN_BODY_LENGTH: int = 10

# Network Feature extraction
NETWORK_FEATURE_COLUMNS: list[str] = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "is_host_login",
    "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
]

# Login behaviour feature columns
LOGIN_FEATURE_COLUMNS: list[str] = [
    "hour_of_day", "day_of_week", "login_duration",
    "failed_attempts", "ip_country_mismatch", "new_device",
    "new_location", "typing_speed_anomaly", "session_duration",
    "concurrent_sessions",
]


# ---------------------------------------------------------------------------
# Explainability Constants
# ---------------------------------------------------------------------------
SHAP_MAX_DISPLAY_FEATURES: int = 20
LIME_NUM_FEATURES: int = 15
LIME_NUM_SAMPLES: int = 5000


# ---------------------------------------------------------------------------
# Logging Constants
# ---------------------------------------------------------------------------
SECURITY_LOGGER_NAME: str = "src.security"
MODEL_LOGGER_NAME: str = "src.models"
API_LOGGER_NAME: str = "src.api"
DATA_LOGGER_NAME: str = "src.data"


# ---------------------------------------------------------------------------
# Database Constants
# ---------------------------------------------------------------------------
DB_DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"
DB_MAX_STRING_LENGTH: int = 2048
DB_MAX_URL_LENGTH: int = 2048
DB_MAX_EMAIL_LENGTH: int = 320


# ---------------------------------------------------------------------------
# Report Constants
# ---------------------------------------------------------------------------
REPORT_DATE_FORMAT: str = "%Y-%m-%d"
REPORT_DATETIME_FORMAT: str = "%Y-%m-%d_%H-%M-%S"
REPORT_MAX_ROWS: int = 10_000


# ---------------------------------------------------------------------------
# Seed for Reproducibility (IEEE requirement for research reproducibility)
# ---------------------------------------------------------------------------
RANDOM_SEED: int = 42
