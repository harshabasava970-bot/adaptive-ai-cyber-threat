"""
risk_utils.py — Shared Risk Classification Utilities
======================================================
Adaptive Explainable Multi-Source Cyber Threat Detection Framework
using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME

Single source of truth for risk classification across the entire application:
  • Dashboard KPI cards and timeline
  • Threat Fusion page
  • Analytics page
  • PDF and CSV reports
  • API response post-processing

Design
──────
Two distinct concepts are separated here:

  is_confirmed_threat (bool)
      Whether the detection represents a confirmed actionable threat.
      Derived exclusively from risk_level.
      CRITICAL and HIGH  → True   (escalate / THREAT status)
      MEDIUM             → False  (investigate / REVIEW status)
      LOW and INFO       → False  (monitor / SAFE status)

      The raw ``is_threat`` boolean stored in the database was set by the
      fusion engine using a probability threshold (≥ 0.25 for the "low"
      tier).  A LOW-risk event can therefore have is_threat=True in the DB
      but is_confirmed_threat=False.  User-facing displays must use
      is_confirmed_threat so that LOW risk is never shown as a confirmed threat.

  status (str: SAFE | REVIEW | THREAT)
      The operational classification shown in the UI, timeline, and reports.
      Derived from risk_level using the same mapping as is_confirmed_threat.

  confidence (float | None)
      Model confidence for a detection result.
      A value of exactly 0.0 can mean "not available" (e.g. fusion scans
      where the individual module did not return confidence metadata) rather
      than genuine zero confidence.  Callers should pass None when confidence
      is not available, and use ``safe_confidence()`` to format the display
      value.  The ``avg_confidence()`` helper excludes None values so that
      fusion-only scans do not drag down the session average.

Author: B.Tech Capstone Project 2026-2027
"""

from __future__ import annotations

from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Risk levels that represent a confirmed actionable threat.
CONFIRMED_RISK_LEVELS: frozenset[str] = frozenset({"critical", "high"})

# Ordered tier thresholds (composite score → risk label).
# Mirrors AdaptiveThreatFusionEngine._THRESHOLDS.
RISK_THRESHOLDS: dict[str, float] = {
    "critical": 0.85,
    "high":     0.65,
    "medium":   0.45,
    "low":      0.25,
    # anything below 0.25 → "info"
}

# Status labels used in UI, timeline, and reports.
STATUS_THREAT = "THREAT"
STATUS_REVIEW = "REVIEW"
STATUS_SAFE   = "SAFE"

# ---------------------------------------------------------------------------
# Core classification helpers
# ---------------------------------------------------------------------------


def risk_to_status(risk_level: str) -> str:
    """Map a risk level string to its operational status label.

    This is the single source of truth used by Dashboard, Timeline, Analytics,
    Threat Fusion, PDF reports, and CSV exports.

    Args:
        risk_level: One of "critical", "high", "medium", "low", "info"
                    (case-insensitive).

    Returns:
        "THREAT"  for critical or high risk.
        "REVIEW"  for medium risk.
        "SAFE"    for low, info, or any unrecognised value.

    Examples:
        >>> risk_to_status("critical")
        'THREAT'
        >>> risk_to_status("LOW")
        'SAFE'
        >>> risk_to_status("medium")
        'REVIEW'
    """
    level = (risk_level or "").lower().strip()
    if level in CONFIRMED_RISK_LEVELS:
        return STATUS_THREAT
    if level == "medium":
        return STATUS_REVIEW
    return STATUS_SAFE


def is_confirmed_threat(risk_level: str) -> bool:
    """Return True only when the risk level represents a confirmed threat.

    Args:
        risk_level: Risk level string (case-insensitive).

    Returns:
        True for "critical" or "high"; False for everything else.
    """
    return (risk_level or "").lower().strip() in CONFIRMED_RISK_LEVELS


def score_to_risk_level(score: float) -> str:
    """Convert a composite risk score (0.0–1.0) to a risk level string.

    Mirrors AdaptiveThreatFusionEngine._classify_risk().

    Args:
        score: Composite risk score in [0.0, 1.0].

    Returns:
        One of "critical", "high", "medium", "low", "info".
    """
    if score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    if score >= RISK_THRESHOLDS["high"]:
        return "high"
    if score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    if score >= RISK_THRESHOLDS["low"]:
        return "low"
    return "info"


def score_to_status(score: float) -> str:
    """Convenience: convert a risk score directly to a status label.

    Args:
        score: Composite risk score in [0.0, 1.0].

    Returns:
        "THREAT", "REVIEW", or "SAFE".
    """
    return risk_to_status(score_to_risk_level(score))


# ---------------------------------------------------------------------------
# Confidence helpers
# ---------------------------------------------------------------------------

# Sentinel: confidence values at or below this threshold are treated as
# "not available" when computing averages.  The fusion engine falls back to
# 0.75 when metadata is absent, but the dashboard defaults to 0.0 on missing
# explanation keys, so we treat 0.0 as unavailable.
_CONFIDENCE_UNAVAILABLE_THRESHOLD: float = 0.0


def safe_confidence(value: Optional[float]) -> Optional[float]:
    """Normalise a raw confidence value; return None if unavailable.

    A raw value of exactly 0.0 (the dashboard default when no confidence
    was returned by the API) is treated as "not available".

    Args:
        value: Raw confidence float, or None.

    Returns:
        The original float if it is a meaningful value (> 0.0),
        otherwise None.
    """
    if value is None:
        return None
    try:
        v = float(value)
        return v if v > _CONFIDENCE_UNAVAILABLE_THRESHOLD else None
    except (TypeError, ValueError):
        return None


def format_confidence(value: Optional[float], decimals: int = 1) -> str:
    """Format a confidence value for display.

    Args:
        value: Confidence float (0.0–1.0) or None.
        decimals: Number of decimal places for the percentage.

    Returns:
        Formatted percentage string (e.g. "87.3%") or "N/A" if unavailable.
    """
    cleaned = safe_confidence(value)
    if cleaned is None:
        return "N/A"
    return f"{cleaned:.{decimals}%}"


def avg_confidence(confidences: list[Optional[float]]) -> Optional[float]:
    """Compute mean confidence, excluding unavailable (None / 0.0) values.

    Args:
        confidences: List of raw confidence values from scan records.

    Returns:
        Mean of valid confidence values, or None if none are available.
    """
    valid = [safe_confidence(v) for v in confidences]
    valid = [v for v in valid if v is not None]
    return sum(valid) / len(valid) if valid else None


# ---------------------------------------------------------------------------
# Processing-time helpers
# ---------------------------------------------------------------------------

# Threshold above which a processing time is flagged as a potential outlier
# (e.g. caused by API cold-start, network retry, or model load).
LATENCY_OUTLIER_THRESHOLD_MS: float = 5000.0


def flag_latency(processing_ms: float) -> str:
    """Return a display annotation for unusually high processing times.

    The high latency is preserved and not hidden — cold-start delays on
    free-tier hosting (Render.com) are a documented characteristic of
    the deployment environment.

    Args:
        processing_ms: Measured round-trip time in milliseconds.

    Returns:
        Empty string for normal latency; "⚠ Cold-start / network delay"
        for values exceeding the outlier threshold.
    """
    if processing_ms >= LATENCY_OUTLIER_THRESHOLD_MS:
        return "⚠ Cold-start / network delay"
    return ""


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta

IST_OFFSET = timedelta(hours=5, minutes=30)


def utc_now_ist() -> datetime:
    """Return the current time as a UTC-naive datetime adjusted to IST.

    The result is a naive datetime in IST (+05:30) suitable for display.
    It is NOT timezone-aware; callers must label it explicitly as IST.
    """
    return datetime.utcnow() + IST_OFFSET


def utc_to_ist(utc_dt: datetime) -> datetime:
    """Convert a UTC-naive datetime to its IST equivalent (UTC + 05:30).

    Args:
        utc_dt: UTC-naive datetime (as stored in the database).

    Returns:
        IST-naive datetime (UTC + 05:30). Apply only once per value.
    """
    return utc_dt + IST_OFFSET


def format_ist(utc_dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a UTC datetime as an IST string with label.

    Args:
        utc_dt: UTC-naive datetime.
        fmt: strftime format string.

    Returns:
        Formatted string with " IST" suffix, e.g. "2026-09-19 18:04:08 IST".
    """
    return utc_to_ist(utc_dt).strftime(fmt) + " IST"


def format_dual_timestamp(utc_iso: str) -> str:
    """Convert a UTC ISO string to a dual IST/UTC display string.

    Used in PDF reports and CSV exports so every timestamp shows both
    timezone values.  Applies the IST offset exactly once.

    Args:
        utc_iso: UTC ISO string from ThreatDetection.to_dict(), e.g.
                 "2026-09-19T12:34:08" or "2026-09-19T12:34:08.123456".
                 The string must NOT already include a timezone suffix.

    Returns:
        Two-line string: "2026-09-19 18:04:08 IST\\n2026-09-19 12:34:08 UTC"
        or "—" if the input is empty/None.
    """
    if not utc_iso:
        return "—"
    try:
        bare = str(utc_iso)[:19].replace("T", " ")
        utc_dt = datetime.strptime(bare, "%Y-%m-%d %H:%M:%S")
        ist_dt = utc_dt + IST_OFFSET
        return (
            f"{ist_dt.strftime('%Y-%m-%d %H:%M:%S')} IST\n"
            f"{utc_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
    except (ValueError, TypeError):
        return str(utc_iso)[:19] if utc_iso and len(str(utc_iso)) >= 19 else str(utc_iso)
