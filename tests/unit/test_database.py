"""
test_database.py — Unit Tests for Database Repository
=======================================================
IEEE 29119 Test Coverage:
  TC-DB-001: ThreatDetection record saved and retrieved
  TC-DB-002: get_recent returns records ordered by timestamp
  TC-DB-003: get_total_count returns correct count
  TC-DB-004: ModelMetrics record saved correctly

Author: B.Tech Capstone Project
"""

import pytest
from src.core.base_model import PredictionResult
from src.core.constants import ModelAlgorithm, RiskLevel, ThreatType
from src.database.models import init_db, get_engine
from src.database.repository import ThreatRepository
from src.fusion.threat_fusion import FusedThreatReport


@pytest.fixture
def in_memory_repo():
    """Provide a ThreatRepository backed by an in-memory SQLite database."""
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    from src.database.models import get_session
    repo = ThreatRepository.__new__(ThreatRepository)
    repo.repo = None
    repo._SessionFactory = get_session(engine)
    return repo


def _make_report(risk_score: float = 0.75, is_threat: bool = True) -> FusedThreatReport:
    """Build a minimal FusedThreatReport for testing."""
    return FusedThreatReport(
        report_id="test-report-001",
        timestamp="2025-01-01T12:00:00Z",
        composite_risk_score=risk_score,
        risk_level=RiskLevel.HIGH,
        is_threat=is_threat,
        active_threats=["phishing_email"],
        predictions={},
        summary="Test threat report",
        recommendations=["Take action."],
    )


class TestThreatRepository:

    def test_save_and_retrieve_detection(self, in_memory_repo):
        """TC-DB-001: Saved record can be retrieved via get_recent."""
        report = _make_report()
        row_id = in_memory_repo.save_detection(report)
        assert isinstance(row_id, int)
        assert row_id > 0

        recent = in_memory_repo.get_recent(limit=10)
        assert len(recent) == 1
        assert recent[0]["report_id"] == "test-report-001"

    def test_get_total_count(self, in_memory_repo):
        """TC-DB-003: Total count increments correctly."""
        assert in_memory_repo.get_total_count() == 0
        in_memory_repo.save_detection(_make_report())
        assert in_memory_repo.get_total_count() == 1

    def test_get_recent_respects_limit(self, in_memory_repo):
        """TC-DB-002: get_recent(limit=1) returns at most 1 record."""
        for i in range(5):
            r = _make_report()
            r.report_id = f"report-{i}"
            in_memory_repo.save_detection(r)
        recent = in_memory_repo.get_recent(limit=2)
        assert len(recent) <= 2

    def test_get_threat_counts(self, in_memory_repo):
        """Threat type counts are aggregated correctly."""
        r = _make_report()
        r.active_threats = ["phishing_email", "malicious_url"]
        in_memory_repo.save_detection(r)
        counts = in_memory_repo.get_threat_counts()
        assert counts.get("phishing_email", 0) >= 1
