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
    """Human-readable login behaviour request.

    Users provide realistic cybersecurity context — not raw ML features.
    Internal conversion to anomaly indicators happens in the detector.
    """
    username:          str   = Field(default="unknown_user", description="Username or user ID")
    country:           str   = Field(default="IN", description="Login origin country code")
    hour_of_day:       int   = Field(..., ge=0,  le=23, description="Hour of login (0-23)")
    day_of_week:       int   = Field(..., ge=0,  le=6,  description="Day of week (0=Monday)")
    failed_attempts:   int   = Field(default=0, ge=0,   description="Failed attempts before success")
    known_device:      int   = Field(default=1, ge=0, le=1, description="1=Known device, 0=Unknown")
    vpn_enabled:       int   = Field(default=0, ge=0, le=1, description="1=VPN detected, 0=No VPN")
    new_location:      int   = Field(default=0, ge=0, le=1, description="1=New location, 0=Known location")
    is_business_hours: int   = Field(default=1, ge=0, le=1, description="1=Business hours, 0=Outside")
    # Derived internally — kept for API compatibility
    login_duration:       float = Field(default=120.0, ge=0)
    ip_country_mismatch:  int   = Field(default=0, ge=0, le=1)
    new_device:           int   = Field(default=0, ge=0, le=1)
    typing_speed_anomaly: float = Field(default=0.1, ge=0.0, le=1.0)
    session_duration:     float = Field(default=1800.0, ge=0)
    concurrent_sessions:  int   = Field(default=1, ge=1)

    @field_validator("country")
    @classmethod
    def uppercase_country(cls, v: str) -> str:
        return v.upper().strip()

    def model_post_init(self, __context) -> None:
        """Derive internal fields from human-readable inputs."""
        # Derive ip_country_mismatch from country if not explicitly set
        if self.known_device == 0:
            object.__setattr__(self, "new_device", 1)
        if self.country not in ("IN", "US", "GB", "CA", "AU"):
            object.__setattr__(self, "ip_country_mismatch", 1)
    bytes_transferred:    float = Field(default=5000.0, ge=0)
    login_frequency_24h:  int   = Field(default=2,  ge=0)


class NetworkRequest(BaseModel):
    """Human-readable network connection request.

    Accepts protocol-level inputs. Internal conversion to NSL-KDD
    compatible features happens in the detector.
    """
    features: dict[str, float] = Field(
        default_factory=dict,
        description=(
            "Network connection features. Supported keys: "
            "protocol_type (0=tcp,1=udp,2=icmp), src_bytes, dst_bytes, "
            "duration, serror_rate, rerror_rate, root_shell, "
            "num_failed_logins, same_srv_rate, dst_host_count, "
            "packets_per_sec, bytes_per_sec."
        ),
        examples=[{
            "protocol_type": 0,
            "src_bytes": 1000,
            "dst_bytes": 500,
            "duration": 2,
            "serror_rate": 0.0,
            "root_shell": 0,
        }],
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
    """Response from the Adaptive Threat Fusion Engine endpoint."""
    report_id:            str
    timestamp:            str
    composite_risk_score: float
    risk_level:           str
    is_threat:            bool
    active_threats:       list[str]
    predictions:          dict[str, Any]
    summary:              str
    recommendations:      list[str]
    confidence:           float = 0.0
    contributing_modules: list[str] = []
    fusion_method:        str = "adaptive_confidence_weighted"


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
