"""
schemas.py — Pydantic Request/Response Schemas
================================================
Adaptive AI for Cyber Threat Detection

All API input validation and response serialisation models.
Pydantic v2 syntax — automatic validation + OpenAPI docs generation.

Author: B.Tech Capstone Project
"""

from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ── Request Models ─────────────────────────────────────────────────

class PhishingRequest(BaseModel):
    """Request body for phishing email detection endpoint."""
    email_text: str = Field(
        ...,
        min_length=10,
        max_length=50000,
        description="Full email body text to analyse.",
        examples=["Urgent: Your account has been compromised. Click here to verify."],
    )
    model: str = Field(
        default="distilbert",
        description="Model to use: 'distilbert', 'bert', or 'random_forest'.",
    )

    @field_validator("email_text")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class URLRequest(BaseModel):
    """Request body for malicious URL detection endpoint."""
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="URL string to analyse for malicious indicators.",
        examples=["http://suspicious-login-verify.xyz/paypal/account"],
    )

    @field_validator("url")
    @classmethod
    def strip_url(cls, v: str) -> str:
        return v.strip()


class LoginRequest(BaseModel):
    """Request body for suspicious login behaviour detection."""
    hour_of_day:          int   = Field(..., ge=0,  le=23)
    day_of_week:          int   = Field(..., ge=0,  le=6)
    login_duration:       float = Field(..., ge=0)
    failed_attempts:      int   = Field(..., ge=0)
    ip_country_mismatch:  int   = Field(..., ge=0,  le=1)
    new_device:           int   = Field(..., ge=0,  le=1)
    new_location:         int   = Field(..., ge=0,  le=1)
    typing_speed_anomaly: float = Field(..., ge=0.0, le=1.0)
    session_duration:     float = Field(..., ge=0)
    concurrent_sessions:  int   = Field(..., ge=1)
    bytes_transferred:    float = Field(default=5000.0, ge=0)
    login_frequency_24h:  int   = Field(default=2,  ge=0)


class NetworkRequest(BaseModel):
    """Request body for network anomaly detection.

    Accepts a dictionary of NSL-KDD feature name → value mappings.
    Unknown keys are ignored; missing keys default to 0.
    """
    features: dict[str, float] = Field(
        ...,
        description="NSL-KDD feature dictionary. Missing features default to 0.",
        examples=[{"duration": 0, "protocol_type": 0, "src_bytes": 491, "dst_bytes": 0}],
    )


class FusedRequest(BaseModel):
    """Request body for the Threat Fusion Engine endpoint.

    At least one sub-request must be provided.
    """
    phishing: Optional[PhishingRequest] = None
    url:      Optional[URLRequest]      = None
    login:    Optional[LoginRequest]    = None
    network:  Optional[NetworkRequest]  = None


# ── Response Models ────────────────────────────────────────────────

class PredictionResponse(BaseModel):
    """Standard prediction response returned by all detection endpoints."""
    threat_type:       str
    is_threat:         bool
    probability:       float
    risk_score:        float
    risk_level:        str
    model_name:        str
    algorithm:         str
    inference_time_ms: float
    explanation:       Optional[dict] = None
    metadata:          Optional[dict] = None


class FusedResponse(BaseModel):
    """Response from the Threat Fusion Engine endpoint."""
    report_id:           str
    timestamp:           str
    composite_risk_score: float
    risk_level:          str
    is_threat:           bool
    active_threats:      list[str]
    predictions:         dict[str, Any]
    summary:             str
    recommendations:     list[str]


class HealthResponse(BaseModel):
    """Health check response."""
    status:  str
    version: str
    env:     str


class RecentDetectionsResponse(BaseModel):
    """Response for recent detections list."""
    total: int
    detections: list[dict]


class ModelMetricsResponse(BaseModel):
    """Response for model performance metrics."""
    models: list[dict]
