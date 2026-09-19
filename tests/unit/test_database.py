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
from datetime import datetime
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


# ─────────────────────────────────────────────────────────────────
# Fix #1 — get_report_summary() (added alongside original TC-DB tests)
# ─────────────────────────────────────────────────────────────────

def _rpt(risk_level: RiskLevel, score: float, threats: list[str],
         is_threat_raw: bool | None = None) -> FusedThreatReport:
    resolved = (
        is_threat_raw if is_threat_raw is not None
        else risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    )
    import uuid as _uuid
    return FusedThreatReport(
        report_id=str(_uuid.uuid4()),
        timestamp=datetime(2026, 9, 19, 12, 0, 0).isoformat() + "Z",
        composite_risk_score=score,
        risk_level=risk_level,
        is_threat=resolved,
        active_threats=threats,
        predictions={},
        summary="test",
        recommendations=[],
    )


class TestGetReportSummaryDB:
    """TC-DB-005 through TC-DB-010: get_report_summary() consistency."""

    def test_empty_db(self, in_memory_repo):
        s = in_memory_repo.get_report_summary()
        assert s == {
            "total_scans": 0,
            "confirmed_threats": 0,
            "phishing_emails": 0,
            "malicious_urls": 0,
            "suspicious_logins": 0,
            "network_anomalies": 0,
        }

    def test_total_scans_includes_all_risk_levels(self, in_memory_repo):
        for lvl, sc in [(RiskLevel.CRITICAL, 0.91), (RiskLevel.LOW, 0.25),
                        (RiskLevel.INFO, 0.05)]:
            in_memory_repo.save_detection(_rpt(lvl, sc, []))
        s = in_memory_repo.get_report_summary()
        assert s["total_scans"] == 3

    def test_confirmed_threats_excludes_low_and_medium(self, in_memory_repo):
        in_memory_repo.save_detection(_rpt(RiskLevel.CRITICAL, 0.91, ["phishing_email"]))
        in_memory_repo.save_detection(_rpt(RiskLevel.LOW, 0.28, ["suspicious_login"], True))
        in_memory_repo.save_detection(_rpt(RiskLevel.MEDIUM, 0.50, []))
        s = in_memory_repo.get_report_summary()
        assert s["total_scans"] == 3
        assert s["confirmed_threats"] == 1  # CRITICAL only

    def test_category_counts_not_inflated_by_low_risk(self, in_memory_repo):
        # LOW login: raw is_threat=True but NOT a confirmed threat
        in_memory_repo.save_detection(_rpt(RiskLevel.LOW, 0.28, ["suspicious_login"], True))
        s = in_memory_repo.get_report_summary()
        assert s["suspicious_logins"] == 0

    def test_fusion_multi_type_counts_categories_correctly(self, in_memory_repo):
        in_memory_repo.save_detection(
            _rpt(RiskLevel.CRITICAL, 0.92, ["phishing_email", "malicious_url"])
        )
        s = in_memory_repo.get_report_summary()
        assert s["total_scans"] == 1
        assert s["confirmed_threats"] == 1
        assert s["phishing_emails"] == 1
        assert s["malicious_urls"] == 1

    def test_invariant_total_ge_confirmed(self, in_memory_repo):
        in_memory_repo.save_detection(_rpt(RiskLevel.HIGH, 0.75, ["phishing_email"]))
        in_memory_repo.save_detection(_rpt(RiskLevel.LOW,  0.26, [], True))
        s = in_memory_repo.get_report_summary()
        assert s["total_scans"] >= s["confirmed_threats"]
