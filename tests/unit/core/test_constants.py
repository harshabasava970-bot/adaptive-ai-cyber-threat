"""
test_constants.py — Unit Tests for Application Constants
==========================================================
Adaptive AI for Cyber Threat Detection

IEEE 29119 Test Coverage:
  - TC-CST-001: All enum members are valid strings
  - TC-CST-002: Path constants resolve to existing or creatable directories
  - TC-CST-003: Enum members are unique (no duplicate values)
  - TC-CST-004: ThreatType, RiskLevel, ModelAlgorithm cover required items

Author: B.Tech Capstone Project
"""

import pytest
from pathlib import Path

from src.core.constants import (
    APP_NAME,
    APP_VERSION,
    PROJECT_ROOT,
    RANDOM_SEED,
    DetectionStatus,
    ModelAlgorithm,
    RiskLevel,
    ThreatType,
)


class TestApplicationMetadata:
    """Tests for application metadata constants."""

    def test_app_name_is_non_empty_string(self):
        """APP_NAME must be a non-empty string."""
        assert isinstance(APP_NAME, str)
        assert len(APP_NAME) > 0

    def test_app_version_follows_semver(self):
        """APP_VERSION should follow major.minor.patch format."""
        parts = APP_VERSION.split(".")
        assert len(parts) == 3, "Version must be in major.minor.patch format"
        for part in parts:
            assert part.isdigit(), f"Version part '{part}' is not a digit"

    def test_project_root_exists(self):
        """PROJECT_ROOT must point to an existing directory."""
        assert PROJECT_ROOT.exists(), f"PROJECT_ROOT does not exist: {PROJECT_ROOT}"
        assert PROJECT_ROOT.is_dir()

    def test_random_seed_is_integer(self):
        """RANDOM_SEED must be a non-negative integer for reproducibility."""
        assert isinstance(RANDOM_SEED, int)
        assert RANDOM_SEED >= 0


class TestThreatTypeEnum:
    """TC-CST-004: ThreatType must cover all 4 detection categories."""

    def test_all_four_threat_types_present(self):
        """All four threat types required by the project spec must exist."""
        required = {
            "phishing_email",
            "malicious_url",
            "suspicious_login",
            "network_anomaly",
        }
        actual = {t.value for t in ThreatType}
        for req in required:
            assert req in actual, f"Missing required ThreatType: {req}"

    def test_threat_type_values_are_strings(self):
        """TC-CST-001: All ThreatType values must be strings."""
        for threat in ThreatType:
            assert isinstance(threat.value, str)
            assert len(threat.value) > 0

    def test_threat_type_is_json_serialisable(self):
        """ThreatType values must be directly serialisable to JSON strings."""
        import json
        for threat in ThreatType:
            # Should not raise TypeError
            serialised = json.dumps(threat.value)
            assert isinstance(serialised, str)

    def test_threat_type_unique_values(self):
        """TC-CST-003: No duplicate enum values in ThreatType."""
        values = [t.value for t in ThreatType]
        assert len(values) == len(set(values)), "ThreatType has duplicate values"


class TestRiskLevelEnum:
    """Tests for the RiskLevel enumeration."""

    def test_all_risk_levels_present(self):
        """RiskLevel must include critical, high, medium, low, and info."""
        required = {"critical", "high", "medium", "low", "info"}
        actual = {r.value for r in RiskLevel}
        assert required == actual, f"Missing risk levels: {required - actual}"

    def test_risk_level_values_are_strings(self):
        """All RiskLevel values must be strings."""
        for level in RiskLevel:
            assert isinstance(level.value, str)

    def test_risk_level_unique_values(self):
        """No duplicate values in RiskLevel enum."""
        values = [r.value for r in RiskLevel]
        assert len(values) == len(set(values))


class TestModelAlgorithmEnum:
    """Tests for the ModelAlgorithm enumeration."""

    def test_all_required_algorithms_present(self):
        """All algorithms specified in the project requirements must be present."""
        required = {
            "distilbert",
            "bert",
            "random_forest",
            "xgboost",
            "isolation_forest",
            "logistic_regression",
        }
        actual = {a.value for a in ModelAlgorithm}
        for req in required:
            assert req in actual, f"Missing required ModelAlgorithm: {req}"

    def test_model_algorithm_unique_values(self):
        """No duplicate values in ModelAlgorithm enum."""
        values = [a.value for a in ModelAlgorithm]
        assert len(values) == len(set(values))


class TestDetectionStatusEnum:
    """Tests for the DetectionStatus enumeration."""

    def test_all_statuses_present(self):
        """Required pipeline statuses must be present."""
        required = {"success", "failed", "pending", "skipped"}
        actual = {s.value for s in DetectionStatus}
        assert required == actual
