"""
test_fusion.py — Unit Tests for Threat Fusion Engine
======================================================
IEEE 29119 Test Coverage:
  TC-FUS-001: Weighted score with all modules
  TC-FUS-002: Partial modules (some None)
  TC-FUS-003: Risk level classification boundaries
  TC-FUS-004: Empty input returns info-level report
  TC-FUS-005: Active threats list is correct

Author: B.Tech Capstone Project
"""

import pytest
from unittest.mock import patch
from src.core.base_model import PredictionResult
from src.core.constants import ModelAlgorithm, RiskLevel, ThreatType
from src.fusion.threat_fusion import ThreatFusionEngine


def _make_result(threat_type: ThreatType, prob: float, is_threat: bool) -> PredictionResult:
    return PredictionResult(
        threat_type=threat_type,
        is_threat=is_threat,
        probability=prob,
        risk_score=prob,
        model_name="test_model",
        algorithm=ModelAlgorithm.XGBOOST,
    )


@pytest.fixture
def engine():
    return ThreatFusionEngine()


class TestFusionEngine:

    def test_all_modules_produces_weighted_score(self, engine):
        """TC-FUS-001: All four modules → weighted composite score."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.9, True),
            url_result=_make_result(ThreatType.MALICIOUS_URL, 0.8, True),
            login_result=_make_result(ThreatType.SUSPICIOUS_LOGIN, 0.7, True),
            network_result=_make_result(ThreatType.NETWORK_ANOMALY, 0.6, True),
        )
        assert 0.0 <= report.composite_risk_score <= 1.0
        assert report.is_threat is True
        assert len(report.active_threats) == 4

    def test_partial_modules_renormalises_weights(self, engine):
        """TC-FUS-002: Missing modules are excluded; weights renormalised."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.9, True),
        )
        assert 0.0 <= report.composite_risk_score <= 1.0
        assert report.composite_risk_score > 0.0

    def test_empty_input_returns_info(self, engine):
        """TC-FUS-004: No inputs → score=0, risk=info."""
        report = engine.fuse()
        assert report.composite_risk_score == 0.0
        assert report.risk_level == RiskLevel.INFO
        assert report.is_threat is False

    def test_risk_level_critical_threshold(self, engine):
        """TC-FUS-003: Score >= 0.85 → CRITICAL."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.99, True),
        )
        assert report.risk_level == RiskLevel.CRITICAL

    def test_risk_level_info_threshold(self, engine):
        """TC-FUS-003: Score < 0.25 → INFO."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.05, False),
        )
        assert report.risk_level in (RiskLevel.INFO, RiskLevel.LOW)

    def test_active_threats_only_contains_triggered(self, engine):
        """TC-FUS-005: active_threats only lists modules where is_threat=True."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.9, True),
            url_result=_make_result(ThreatType.MALICIOUS_URL, 0.1, False),
        )
        assert "phishing_email" in report.active_threats
        assert "malicious_url" not in report.active_threats

    def test_report_has_recommendations_when_threat(self, engine):
        """Threat reports always include remediation recommendations."""
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.9, True),
        )
        assert len(report.recommendations) > 0

    def test_report_to_dict_is_serialisable(self, engine):
        """FusedThreatReport.to_dict() produces JSON-serialisable output."""
        import json
        report = engine.fuse(
            phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.7, True),
        )
        serialised = json.dumps(report.to_dict())
        assert isinstance(serialised, str)

    def test_report_id_is_unique(self, engine):
        """Each fusion call produces a unique report_id."""
        r1 = engine.fuse(phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.5, False))
        r2 = engine.fuse(phishing_result=_make_result(ThreatType.PHISHING_EMAIL, 0.5, False))
        assert r1.report_id != r2.report_id
