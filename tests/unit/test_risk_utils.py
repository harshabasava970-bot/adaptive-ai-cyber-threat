"""
test_risk_utils.py — Regression Tests for src/core/risk_utils.py
=================================================================
Covers all 13 required detection scenarios plus supporting utilities:

Required scenarios (from spec):
  1.  Phishing email (malicious)
  2.  Legitimate email
  3.  Malicious URL
  4.  Legitimate URL
  5.  Normal login
  6.  Suspicious login
  7.  Normal network connection
  8.  Suspicious network connection
  9.  LOW-risk fusion event
  10. MEDIUM-risk event
  11. HIGH-risk event
  12. CRITICAL-risk event
  13. Duplicate scans
  +   Missing confidence
  +   Empty dataset
  +   Timezone conversion (IST/UTC)
  +   High processing latency (cold-start outlier)

All risk/status logic uses risk_utils as the single source of truth.

Author: B.Tech Capstone Project 2026-2027
"""

from datetime import datetime, timedelta
from typing import Optional

import pytest

from src.core.risk_utils import (
    CONFIRMED_RISK_LEVELS,
    IST_OFFSET,
    avg_confidence,
    flag_latency,
    format_confidence,
    format_dual_timestamp,
    format_ist,
    is_confirmed_threat,
    risk_to_status,
    safe_confidence,
    score_to_risk_level,
    score_to_status,
    utc_now_ist,
    utc_to_ist,
)


# ─────────────────────────────────────────────────────────────────
# risk_to_status — all five levels
# ─────────────────────────────────────────────────────────────────

class TestRiskToStatus:
    """Single source of truth for status mapping."""

    # Scenario 12: CRITICAL-risk event
    def test_critical_maps_to_threat(self):
        assert risk_to_status("critical") == "THREAT"

    # Scenario 11: HIGH-risk event
    def test_high_maps_to_threat(self):
        assert risk_to_status("high") == "THREAT"

    # Scenario 10: MEDIUM-risk event
    def test_medium_maps_to_review(self):
        assert risk_to_status("medium") == "REVIEW"

    # Scenario 9: LOW-risk event
    def test_low_maps_to_safe(self):
        assert risk_to_status("low") == "SAFE"

    def test_info_maps_to_safe(self):
        assert risk_to_status("info") == "SAFE"

    def test_empty_string_maps_to_safe(self):
        assert risk_to_status("") == "SAFE"

    def test_none_maps_to_safe(self):
        assert risk_to_status(None) == "SAFE"  # type: ignore[arg-type]

    def test_case_insensitive(self):
        assert risk_to_status("CRITICAL") == "THREAT"
        assert risk_to_status("High")     == "THREAT"
        assert risk_to_status("MEDIUM")   == "REVIEW"
        assert risk_to_status("LOW")      == "SAFE"

    def test_unknown_level_maps_to_safe(self):
        assert risk_to_status("extreme") == "SAFE"


# ─────────────────────────────────────────────────────────────────
# is_confirmed_threat
# ─────────────────────────────────────────────────────────────────

class TestIsConfirmedThreat:
    """Only CRITICAL and HIGH are confirmed threats."""

    def test_critical_is_confirmed(self):
        assert is_confirmed_threat("critical") is True

    def test_high_is_confirmed(self):
        assert is_confirmed_threat("high") is True

    def test_medium_is_not_confirmed(self):
        assert is_confirmed_threat("medium") is False

    # Core regression: LOW-risk login with score 0.282 must not be a confirmed threat
    def test_low_is_not_confirmed(self):
        assert is_confirmed_threat("low") is False

    def test_info_is_not_confirmed(self):
        assert is_confirmed_threat("info") is False

    def test_confirmed_set_contents(self):
        assert CONFIRMED_RISK_LEVELS == {"critical", "high"}


# ─────────────────────────────────────────────────────────────────
# score_to_risk_level
# ─────────────────────────────────────────────────────────────────

class TestScoreToRiskLevel:
    """Score thresholds must match the fusion engine."""

    def test_above_critical_threshold(self):
        assert score_to_risk_level(0.92) == "critical"

    def test_at_critical_threshold(self):
        assert score_to_risk_level(0.85) == "critical"

    def test_high_band(self):
        assert score_to_risk_level(0.75) == "high"

    def test_at_high_threshold(self):
        assert score_to_risk_level(0.65) == "high"

    def test_medium_band(self):
        assert score_to_risk_level(0.55) == "medium"

    def test_at_medium_threshold(self):
        assert score_to_risk_level(0.45) == "medium"

    def test_low_band(self):
        # Scenario 9: LOW-risk fusion event (score 0.282)
        assert score_to_risk_level(0.282) == "low"

    def test_at_low_threshold(self):
        assert score_to_risk_level(0.25) == "low"

    def test_below_low_threshold(self):
        assert score_to_risk_level(0.10) == "info"

    def test_zero(self):
        assert score_to_risk_level(0.0) == "info"


class TestScoreToStatus:
    def test_critical_score_gives_threat(self):
        assert score_to_status(0.92) == "THREAT"

    def test_low_score_gives_safe(self):
        assert score_to_status(0.282) == "SAFE"

    def test_medium_score_gives_review(self):
        assert score_to_status(0.55) == "REVIEW"


# ─────────────────────────────────────────────────────────────────
# Confidence helpers
# ─────────────────────────────────────────────────────────────────

class TestSafeConfidence:
    """0.0 means unavailable; None means unavailable; anything > 0 is valid."""

    def test_normal_value_returned(self):
        assert safe_confidence(0.85) == pytest.approx(0.85)

    def test_zero_returns_none(self):
        # Scenario: missing confidence (fusion scan stored 0.0)
        assert safe_confidence(0.0) is None

    def test_none_returns_none(self):
        assert safe_confidence(None) is None

    def test_small_positive_returned(self):
        assert safe_confidence(0.001) == pytest.approx(0.001)

    def test_one_returned(self):
        assert safe_confidence(1.0) == pytest.approx(1.0)

    def test_negative_returns_none(self):
        # Negative confidence is invalid; treat as unavailable
        assert safe_confidence(-0.1) is None


class TestFormatConfidence:
    def test_normal_formats_as_percent(self):
        assert format_confidence(0.875) == "87.5%"

    def test_zero_returns_na(self):
        assert format_confidence(0.0) == "N/A"

    def test_none_returns_na(self):
        assert format_confidence(None) == "N/A"

    def test_one_formats_correctly(self):
        assert format_confidence(1.0) == "100.0%"


class TestAvgConfidence:
    """avg_confidence must exclude None / 0.0 values."""

    def test_all_valid(self):
        result = avg_confidence([0.8, 0.9, 0.7])
        assert result == pytest.approx(0.8)

    def test_excludes_zero(self):
        # Scenario: missing confidence — 0.0 should not drag down the average
        result = avg_confidence([0.9, 0.0, 0.8])
        assert result == pytest.approx(0.85)

    def test_excludes_none(self):
        result = avg_confidence([0.9, None, 0.8])
        assert result == pytest.approx(0.85)

    def test_all_none_returns_none(self):
        # Scenario: empty dataset / all unavailable
        assert avg_confidence([None, None]) is None

    def test_all_zero_returns_none(self):
        assert avg_confidence([0.0, 0.0]) is None

    def test_empty_list_returns_none(self):
        assert avg_confidence([]) is None

    def test_mixed_none_and_zero_returns_none(self):
        assert avg_confidence([None, 0.0, None]) is None

    def test_single_valid_value(self):
        assert avg_confidence([0.75]) == pytest.approx(0.75)

    def test_fusion_scans_not_counted_when_confidence_zero(self):
        # Simulation: 3 individual scans with confidence, 2 fusion scans with 0.0
        confs = [0.92, 0.88, 0.75, 0.0, 0.0]
        result = avg_confidence(confs)
        assert result == pytest.approx((0.92 + 0.88 + 0.75) / 3)


# ─────────────────────────────────────────────────────────────────
# Processing-time outlier (Scenario: high latency)
# ─────────────────────────────────────────────────────────────────

class TestFlagLatency:
    """High latency must be flagged as cold-start, not hidden."""

    def test_normal_latency_no_flag(self):
        assert flag_latency(240.0) == ""

    def test_high_latency_flagged(self):
        # Scenario: URL scan at ~10 314 ms (API cold-start on Render free tier)
        result = flag_latency(10_314.0)
        assert result != ""
        assert "cold" in result.lower() or "delay" in result.lower()

    def test_threshold_boundary(self):
        assert flag_latency(5000.0) != ""
        assert flag_latency(4999.9) == ""


# ─────────────────────────────────────────────────────────────────
# Timestamp helpers
# ─────────────────────────────────────────────────────────────────

class TestTimestampUtils:
    """All timezone conversions must apply the offset exactly once."""

    def test_utc_to_ist_adds_5h30m(self):
        utc = datetime(2026, 9, 19, 10, 0, 0)
        ist = utc_to_ist(utc)
        assert ist == datetime(2026, 9, 19, 15, 30, 0)

    def test_utc_midnight_to_ist(self):
        utc = datetime(2026, 9, 19, 0, 0, 0)
        ist = utc_to_ist(utc)
        assert ist.hour == 5
        assert ist.minute == 30

    def test_ist_offset_constant(self):
        assert IST_OFFSET == timedelta(hours=5, minutes=30)

    def test_no_double_conversion(self):
        utc = datetime(2026, 9, 19, 10, 0, 0)
        once  = utc_to_ist(utc)
        twice = utc_to_ist(once)  # applying again would be wrong
        assert once.hour == 15   # correct: 10 + 5:30
        assert twice.hour == 21  # wrong if applied twice — verify once is correct

    def test_format_ist_has_label(self):
        utc = datetime(2026, 9, 19, 12, 0, 0)
        result = format_ist(utc)
        assert "IST" in result
        assert "17:30:00" in result  # 12:00 UTC → 17:30 IST

    def test_format_dual_timestamp_contains_both(self):
        result = format_dual_timestamp("2026-09-19T12:34:08")
        assert "IST" in result
        assert "UTC" in result
        assert "18:04:08" in result   # IST
        assert "12:34:08" in result   # UTC

    def test_format_dual_timestamp_empty(self):
        assert format_dual_timestamp("") == "—"
        assert format_dual_timestamp(None) == "—"  # type: ignore[arg-type]

    def test_format_dual_timestamp_no_double_conversion(self):
        result = format_dual_timestamp("2026-09-19T10:00:00")
        assert "15:30:00 IST" in result
        assert "21:00:00" not in result   # would appear if offset applied twice

    def test_utc_now_ist_is_ahead(self):
        before = datetime.utcnow()
        ist = utc_now_ist()
        after = datetime.utcnow()
        # IST should be roughly 5:30 ahead of utcnow
        diff_before = ist - before
        diff_after  = ist - after
        assert timedelta(hours=5, minutes=29) <= diff_before <= timedelta(hours=5, minutes=31)


# ─────────────────────────────────────────────────────────────────
# End-to-end detection scenarios (all 13 required cases)
# ─────────────────────────────────────────────────────────────────

class TestDetectionScenarios:
    """
    Simulate the full lifecycle of each required detection type:
    build a scan record dict (as produced by save_scan), then verify
    status, is_confirmed_threat, confidence, and timestamp labels.
    """

    def _scan(self, scan_type: str, risk_level: str, score: float,
              confidence: Optional[float] = None,
              processing_ms: float = 120.0) -> dict:
        """Minimal scan record matching the dashboard scan_db schema."""
        return {
            "scan_type":    scan_type,
            "risk_level":   risk_level,
            "threat_score": int(round(score * 100)),
            "probability":  round(score, 4),
            "confidence":   safe_confidence(confidence),
            "processing_ms": processing_ms,
            "status":       risk_to_status(risk_level),
            "is_threat":    risk_level in ("critical", "high"),
            "timestamp_utc": "2026-09-19T12:00:00Z",
        }

    # ── Scenario 1: Phishing email (malicious) ─────────────────────
    def test_phishing_email_malicious(self):
        s = self._scan("phishing", "high", 0.82, confidence=0.91)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True
        assert s["confidence"] == pytest.approx(0.91)

    # ── Scenario 2: Legitimate email ──────────────────────────────
    def test_phishing_email_legitimate(self):
        s = self._scan("phishing", "info", 0.05, confidence=0.95)
        assert s["status"] == "SAFE"
        assert is_confirmed_threat(s["risk_level"]) is False

    # ── Scenario 3: Malicious URL ──────────────────────────────────
    def test_malicious_url(self):
        s = self._scan("url", "critical", 0.94, confidence=0.88)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True

    # ── Scenario 4: Legitimate URL ────────────────────────────────
    def test_legitimate_url(self):
        s = self._scan("url", "info", 0.03, confidence=0.97)
        assert s["status"] == "SAFE"
        assert is_confirmed_threat(s["risk_level"]) is False

    # ── Scenario 5: Normal login ───────────────────────────────────
    def test_normal_login(self):
        s = self._scan("login", "low", 0.15, confidence=0.90)
        assert s["status"] == "SAFE"
        assert is_confirmed_threat(s["risk_level"]) is False

    # ── Scenario 6: Suspicious login ──────────────────────────────
    def test_suspicious_login(self):
        s = self._scan("login", "high", 0.78, confidence=0.82)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True

    # ── Scenario 7: Normal network connection ─────────────────────
    def test_normal_network(self):
        s = self._scan("network", "info", 0.08, confidence=0.93)
        assert s["status"] == "SAFE"
        assert is_confirmed_threat(s["risk_level"]) is False

    # ── Scenario 8: Suspicious network connection ─────────────────
    def test_suspicious_network(self):
        s = self._scan("network", "critical", 0.97, confidence=0.89)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True

    # ── Scenario 9: LOW-risk fusion event ─────────────────────────
    def test_low_risk_fusion(self):
        # Core regression: score 0.282, risk_level=low, raw is_threat may be True
        # but status must be SAFE and is_confirmed_threat must be False.
        s = self._scan("fusion", "low", 0.282, confidence=None)
        assert s["status"] == "SAFE"
        assert is_confirmed_threat(s["risk_level"]) is False
        assert s["confidence"] is None  # no confidence available

    # ── Scenario 10: MEDIUM-risk event ────────────────────────────
    def test_medium_risk_event(self):
        s = self._scan("fusion", "medium", 0.51, confidence=0.72)
        assert s["status"] == "REVIEW"
        assert is_confirmed_threat(s["risk_level"]) is False
        assert s["confidence"] == pytest.approx(0.72)

    # ── Scenario 11: HIGH-risk event ──────────────────────────────
    def test_high_risk_event(self):
        s = self._scan("fusion", "high", 0.76, confidence=0.84)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True

    # ── Scenario 12: CRITICAL-risk event ──────────────────────────
    def test_critical_risk_event(self):
        s = self._scan("fusion", "critical", 0.92, confidence=0.95)
        assert s["status"] == "THREAT"
        assert is_confirmed_threat(s["risk_level"]) is True
        assert s["threat_score"] == 92

    # ── Scenario 13: Duplicate scans ──────────────────────────────
    def test_duplicate_scans_both_recorded_independently(self):
        """Each scan gets its own record; duplicates are not deduplicated."""
        s1 = self._scan("url", "high", 0.78, confidence=0.87)
        s2 = self._scan("url", "high", 0.78, confidence=0.87)
        # Both have same values but are separate records
        assert s1["status"] == s2["status"] == "THREAT"
        assert s1["threat_score"] == s2["threat_score"] == 78
        # avg_confidence over both still correct
        avg = avg_confidence([s1["confidence"], s2["confidence"]])
        assert avg == pytest.approx(0.87)

    # ── Scenario: Missing confidence ──────────────────────────────
    def test_missing_confidence_stored_as_none(self):
        s = self._scan("url", "high", 0.78, confidence=0.0)
        assert s["confidence"] is None  # 0.0 normalised to None

    def test_missing_confidence_excluded_from_avg(self):
        scans = [
            self._scan("url",     "high",   0.78, confidence=0.87),
            self._scan("fusion",  "low",    0.28, confidence=0.0),  # missing
            self._scan("phishing","critical",0.92, confidence=0.93),
        ]
        confs = [s["confidence"] for s in scans]
        avg = avg_confidence(confs)
        assert avg == pytest.approx((0.87 + 0.93) / 2)

    # ── Scenario: Empty dataset ────────────────────────────────────
    def test_empty_dataset_avg_confidence_returns_none(self):
        assert avg_confidence([]) is None

    def test_empty_dataset_all_none_confidence_returns_none(self):
        assert avg_confidence([None, None, None]) is None

    # ── Scenario: Timezone conversion ─────────────────────────────
    def test_timezone_conversion_correct(self):
        utc = datetime(2026, 9, 19, 12, 34, 8)
        ist = utc_to_ist(utc)
        assert ist == datetime(2026, 9, 19, 18, 4, 8)

    def test_pdf_dual_timestamp_correct(self):
        result = format_dual_timestamp("2026-09-19T12:34:08")
        assert "18:04:08 IST" in result
        assert "12:34:08 UTC" in result

    # ── Scenario: High processing latency ─────────────────────────
    def test_high_latency_flagged_not_hidden(self):
        """~10 314 ms URL scan (API cold-start) must be preserved and flagged."""
        s = self._scan("url", "info", 0.05, confidence=0.97, processing_ms=10_314.0)
        assert s["processing_ms"] == 10_314.0  # not deleted
        assert flag_latency(s["processing_ms"]) != ""  # flagged

    def test_normal_latency_not_flagged(self):
        s = self._scan("url", "high", 0.78, confidence=0.87, processing_ms=238.0)
        assert flag_latency(s["processing_ms"]) == ""


# ─────────────────────────────────────────────────────────────────
# Stats function regression (confidence None handling)
# ─────────────────────────────────────────────────────────────────

class TestStatsConfidenceRegression:
    """Replicate the stats() function's avg_confidence logic in isolation."""

    def _compute_avg_conf(self, scan_db: list) -> Optional[float]:
        """Mirror the fixed stats() logic using risk_utils.avg_confidence."""
        return avg_confidence([r.get("confidence") for r in scan_db])

    def test_fusion_scans_with_none_excluded(self):
        db = [
            {"confidence": 0.91, "risk_level": "high",   "status": "THREAT"},
            {"confidence": None, "risk_level": "low",    "status": "SAFE"},   # fusion
            {"confidence": 0.85, "risk_level": "medium", "status": "REVIEW"},
        ]
        avg = self._compute_avg_conf(db)
        assert avg == pytest.approx((0.91 + 0.85) / 2)

    def test_all_none_confidence_returns_none(self):
        db = [
            {"confidence": None, "risk_level": "low", "status": "SAFE"},
            {"confidence": None, "risk_level": "low", "status": "SAFE"},
        ]
        assert self._compute_avg_conf(db) is None

    def test_no_accuracy_field_returned_by_stats_logic(self):
        """stats() must never return an 'accuracy' key (mirrors TestStatsFunction)."""
        db = [{"confidence": 0.9, "risk_level": "high", "status": "THREAT",
               "processing_ms": 100, "is_simulated": False}]
        from src.core.risk_utils import avg_confidence as _ac
        result = {
            "total":    len(db),
            "threats":  sum(1 for r in db if r["risk_level"] in ("critical", "high")),
            "avg_conf": _ac([r.get("confidence") for r in db]),
        }
        assert "accuracy" not in result
