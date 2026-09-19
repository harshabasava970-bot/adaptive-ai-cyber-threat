"""
test_report_generator.py — Unit Tests for Report Generator Fixes
=================================================================
Covers all 5 fixes applied to the report generation pipeline:

  Fix #1 — Count consistency: get_report_summary() returns mathematically
            consistent totals. total_scans >= confirmed_threats, and category
            sums can exceed confirmed_threats (one scan may carry multiple
            threat types) but never exceed total_scans × max_types_per_scan.

  Fix #2 — Is Threat display: _is_confirmed_threat_display() and
            ThreatDetection.is_confirmed_threat use risk_level as the
            single source of truth (critical/high = YES, others = NO).
            LOW risk with any probability value must never show YES.

  Fix #3 — Timestamps: _utc_iso_to_display() produces both IST and UTC,
            clearly labelled. No double-conversion. Empty input handled.

  Fix #4 — Threat type text: _format_threat_types() returns full, human-
            readable strings from active_threats JSON list. No [:25] cut-off.

  Fix #5 — CSV enrichment: _enrich_records_for_export() adds derived columns
            (scan_time_ist, scan_time_utc, is_confirmed_threat,
            detection_status, threat_types_clean) without removing originals.

Scenario matrix (Fix #5 validation):
  - One phishing detection (HIGH risk)
  - Two URL detections (one MEDIUM, one HIGH)
  - Three login detections (one LOW, one MEDIUM, one CRITICAL)
  - One network detection (CRITICAL)
  - Multiple fusion scans (mixed types)
  - One LOW-risk event  → is_confirmed_threat = False
  - One CRITICAL-risk event → is_confirmed_threat = True

Author: B.Tech Capstone Project 2026-2027
"""

import uuid
from datetime import datetime, timedelta

import pytest

from src.core.constants import RiskLevel
from src.database.models import ThreatDetection, get_engine, init_db
from src.database.repository import ThreatRepository
from src.fusion.threat_fusion import FusedThreatReport
from src.reports.report_generator import (
    _enrich_records_for_export,
    _format_threat_types,
    _is_confirmed_threat_display,
    _utc_iso_to_display,
)


# ─────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def repo():
    """In-memory SQLite repository for testing."""
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    from src.database.models import get_session
    r = ThreatRepository.__new__(ThreatRepository)
    r._SessionFactory = get_session(engine)
    return r


def _report(
    risk_level: RiskLevel,
    composite: float,
    active_threats: list[str],
    is_threat: bool | None = None,
) -> FusedThreatReport:
    """Build a minimal FusedThreatReport with a unique report_id."""
    # is_threat stored in DB comes from the fusion engine; we set it
    # explicitly here to test that is_confirmed_threat overrides it properly.
    resolved_is_threat = (
        is_threat
        if is_threat is not None
        else risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    )
    return FusedThreatReport(
        report_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        composite_risk_score=composite,
        risk_level=risk_level,
        is_threat=resolved_is_threat,
        active_threats=active_threats,
        predictions={},
        summary="Test",
        recommendations=[],
    )


# ─────────────────────────────────────────────────────────────────
# Fix #3 — _utc_iso_to_display()
# ─────────────────────────────────────────────────────────────────

class TestUtcIsoToDisplay:
    """Timestamps must show both IST and UTC, labelled, with no double-conversion."""

    def test_normal_conversion(self):
        # 12:00 UTC → 17:30 IST
        result = _utc_iso_to_display("2026-09-19T12:00:00")
        assert "17:30:00 IST" in result
        assert "12:00:00 UTC" in result

    def test_midnight_utc(self):
        # 00:00 UTC → 05:30 IST
        result = _utc_iso_to_display("2026-09-19T00:00:00")
        assert "05:30:00 IST" in result
        assert "00:00:00 UTC" in result

    def test_with_microseconds(self):
        # Microseconds should be stripped gracefully
        result = _utc_iso_to_display("2026-09-19T12:34:08.123456")
        assert "18:04:08 IST" in result
        assert "12:34:08 UTC" in result

    def test_empty_string_returns_placeholder(self):
        result = _utc_iso_to_display("")
        assert result == "—"

    def test_none_treated_as_empty(self):
        result = _utc_iso_to_display(None)  # type: ignore[arg-type]
        assert result == "—"

    def test_no_double_conversion(self):
        # Applying IST offset twice would give +11:00 — must not happen
        result = _utc_iso_to_display("2026-09-19T10:00:00")
        # Single conversion: 10:00 + 5:30 = 15:30 IST
        assert "15:30:00 IST" in result
        # Double conversion would give 21:00 — must not appear
        assert "21:00:00" not in result

    def test_ist_always_ahead_of_utc(self):
        result = _utc_iso_to_display("2026-09-19T08:00:00")
        lines = result.split("\n")
        assert len(lines) == 2
        ist_time = lines[0].split(" ")[1]  # "HH:MM:SS"
        utc_time = lines[1].split(" ")[1]
        # IST (13:30) must be greater than UTC (08:00)
        assert ist_time > utc_time

    def test_both_labels_present(self):
        result = _utc_iso_to_display("2026-09-19T06:00:00")
        assert "IST" in result
        assert "UTC" in result


# ─────────────────────────────────────────────────────────────────
# Fix #4 — _format_threat_types()
# ─────────────────────────────────────────────────────────────────

class TestFormatThreatTypes:
    """Threat type text must be complete — no 25-char truncation."""

    def test_single_type_from_active_threats(self):
        r = {"active_threats": ["phishing_email"], "threat_type": "phishing_email"}
        assert _format_threat_types(r) == "Phishing Email"

    def test_multiple_types_from_active_threats(self):
        r = {"active_threats": ["malicious_url", "suspicious_login"],
             "threat_type": "malicious_url,suspicious_login"}
        result = _format_threat_types(r)
        assert "Malicious Url" in result or "Malicious URL" in result.replace("_", " ").title()
        assert "Suspicious Login" in result

    def test_long_combo_not_truncated(self):
        # "malicious_url,suspicious_login" previously truncated to 25 chars
        r = {
            "active_threats": ["malicious_url", "suspicious_login", "phishing_email"],
            "threat_type": "malicious_url,suspicious_login,phishing_email",
        }
        result = _format_threat_types(r)
        # All three must be fully present
        assert "Phishing Email" in result
        # Result should not end with a partial word
        assert not result.endswith("_")
        assert len(result) > 25  # definitely longer than the old limit

    def test_fallback_to_threat_type_string(self):
        r = {"active_threats": None, "threat_type": "network_anomaly"}
        result = _format_threat_types(r)
        assert "Network Anomaly" in result

    def test_empty_active_threats_list(self):
        r = {"active_threats": [], "threat_type": "none"}
        result = _format_threat_types(r)
        assert result == "None"

    def test_none_values_handled(self):
        r = {"active_threats": None, "threat_type": None}
        result = _format_threat_types(r)
        assert result == "None"

    def test_underscores_replaced(self):
        r = {"active_threats": ["network_anomaly"]}
        result = _format_threat_types(r)
        assert "_" not in result


# ─────────────────────────────────────────────────────────────────
# Fix #2 — _is_confirmed_threat_display()
# ─────────────────────────────────────────────────────────────────

class TestIsConfirmedThreatDisplay:
    """Is Threat display must use risk_level — never the raw boolean."""

    def test_critical_is_yes(self):
        r = {"risk_level": "critical", "is_threat": True}
        assert _is_confirmed_threat_display(r).startswith("YES")

    def test_high_is_yes(self):
        r = {"risk_level": "high", "is_threat": True}
        assert _is_confirmed_threat_display(r).startswith("YES")

    def test_medium_is_no(self):
        r = {"risk_level": "medium", "is_threat": True}
        assert _is_confirmed_threat_display(r).startswith("NO")

    def test_low_is_no_even_if_raw_is_threat_true(self):
        """Core regression: LOW risk must show NO regardless of raw is_threat."""
        r = {"risk_level": "low", "is_threat": True, "risk_score": 0.282}
        result = _is_confirmed_threat_display(r)
        assert result.startswith("NO"), (
            f"LOW risk must display NO, got: {result!r}. "
            "This was the reported bug: score 0.282 with risk_level=low "
            "was incorrectly showing 'Is Threat: YES'."
        )

    def test_info_is_no(self):
        r = {"risk_level": "info", "is_threat": False}
        assert _is_confirmed_threat_display(r).startswith("NO")

    def test_low_with_score_above_fusion_threshold(self):
        """Fusion sets is_threat=True at score >= 0.25 (low threshold).
        But risk_level=low means the display should still be NO."""
        r = {"risk_level": "low", "is_threat": True, "risk_score": 0.30}
        assert _is_confirmed_threat_display(r).startswith("NO")

    def test_status_annotation_present(self):
        """Each level should include an annotation after YES/NO."""
        for level, expected_prefix in [
            ("critical", "YES"),
            ("high",     "YES"),
            ("medium",   "NO"),
            ("low",      "NO"),
            ("info",     "NO"),
        ]:
            result = _is_confirmed_threat_display({"risk_level": level})
            assert result.startswith(expected_prefix), (
                f"risk_level={level!r} → expected prefix {expected_prefix!r}, got {result!r}"
            )
            # Must have annotation after the YES/NO
            assert len(result) > 3, f"No annotation for level={level!r}: {result!r}"


# ─────────────────────────────────────────────────────────────────
# Fix #2 — ThreatDetection.is_confirmed_threat property
# ─────────────────────────────────────────────────────────────────

class TestThreatDetectionIsConfirmedThreat:
    """The ORM model property must match the display function logic.

    Uses a proper SQLAlchemy in-memory instance to avoid missing
    _sa_instance_state errors that occur with __new__ + attribute assignment.
    """

    @pytest.fixture(autouse=True)
    def _setup_engine(self):
        """Create a throw-away in-memory DB so ORM instances initialise cleanly."""
        from src.database.models import get_engine, init_db, get_session
        engine = get_engine("sqlite:///:memory:")
        init_db(engine)
        Session = get_session(engine)
        self._session = Session()

    def _make_orm(self, risk_level: str, is_threat_db: bool) -> ThreatDetection:
        """Create a persisted ThreatDetection row so the ORM state is valid."""
        import uuid as _u
        obj = ThreatDetection(
            report_id=str(_u.uuid4()),
            threat_type="test",
            is_threat=is_threat_db,
            probability=0.5,
            risk_score=0.5,
            risk_level=risk_level,
            model_name="test",
            algorithm="test",
        )
        self._session.add(obj)
        self._session.flush()   # assigns id; keeps session open
        return obj

    def test_critical_confirmed(self):
        assert self._make_orm("critical", True).is_confirmed_threat is True

    def test_high_confirmed(self):
        assert self._make_orm("high", True).is_confirmed_threat is True

    def test_medium_not_confirmed(self):
        assert self._make_orm("medium", True).is_confirmed_threat is False

    def test_low_not_confirmed_even_with_raw_true(self):
        """Key regression: LOW risk, raw is_threat=True → is_confirmed_threat=False."""
        obj = self._make_orm("low", True)
        assert obj.is_confirmed_threat is False, (
            "LOW risk must not be a confirmed threat even if the DB "
            "boolean is_threat=True (set by probability threshold)."
        )

    def test_info_not_confirmed(self):
        assert self._make_orm("info", False).is_confirmed_threat is False

    def test_to_dict_includes_both_fields(self):
        """to_dict() must expose both is_threat (raw) and is_confirmed_threat (derived)."""
        import uuid as _u
        obj = ThreatDetection(
            report_id=str(_u.uuid4()),
            threat_type="suspicious_login",
            is_threat=True,      # raw: set by fusion probability threshold
            risk_level="low",    # → is_confirmed_threat should be False
            probability=0.282,
            risk_score=0.282,
            composite_score=0.282,
            model_name="test",
            algorithm="test",
            input_preview=None,
            active_threats=["suspicious_login"],
        )
        self._session.add(obj)
        self._session.flush()
        d = obj.to_dict()
        assert "is_threat" in d
        assert "is_confirmed_threat" in d
        assert d["is_threat"] is True            # raw preserved
        assert d["is_confirmed_threat"] is False  # derived correct


# ─────────────────────────────────────────────────────────────────
# Fix #1 — get_report_summary() consistency
# ─────────────────────────────────────────────────────────────────

class TestGetReportSummary:
    """Summary counts must be mathematically consistent."""

    def test_empty_db_returns_zeros(self, repo):
        s = repo.get_report_summary()
        assert s["total_scans"] == 0
        assert s["confirmed_threats"] == 0
        assert s["phishing_emails"] == 0
        assert s["malicious_urls"] == 0
        assert s["suspicious_logins"] == 0
        assert s["network_anomalies"] == 0

    def test_total_scans_counts_all_risk_levels(self, repo):
        """ALL risk levels contribute to total_scans."""
        for level, score in [
            (RiskLevel.CRITICAL, 0.92),
            (RiskLevel.HIGH,     0.72),
            (RiskLevel.MEDIUM,   0.52),
            (RiskLevel.LOW,      0.28),
            (RiskLevel.INFO,     0.10),
        ]:
            repo.save_detection(_report(level, score, []))
        s = repo.get_report_summary()
        assert s["total_scans"] == 5

    def test_confirmed_threats_only_critical_and_high(self, repo):
        """Only CRITICAL and HIGH count as confirmed threats."""
        repo.save_detection(_report(RiskLevel.CRITICAL, 0.92, ["phishing_email"]))
        repo.save_detection(_report(RiskLevel.HIGH,     0.72, ["malicious_url"]))
        repo.save_detection(_report(RiskLevel.MEDIUM,   0.52, ["suspicious_login"]))
        repo.save_detection(_report(RiskLevel.LOW,      0.28, ["suspicious_login"], is_threat=True))
        repo.save_detection(_report(RiskLevel.INFO,     0.10, []))
        s = repo.get_report_summary()
        assert s["total_scans"] == 5
        assert s["confirmed_threats"] == 2  # only CRITICAL + HIGH

    def test_category_counts_from_confirmed_threats_only(self, repo):
        """Category counts come from confirmed-threat rows only."""
        # LOW login — not a confirmed threat
        repo.save_detection(_report(RiskLevel.LOW, 0.28, ["suspicious_login"], is_threat=True))
        # HIGH phishing — confirmed threat
        repo.save_detection(_report(RiskLevel.HIGH, 0.75, ["phishing_email"]))
        s = repo.get_report_summary()
        assert s["suspicious_logins"] == 0, (
            "LOW-risk suspicious login must NOT appear in category counts."
        )
        assert s["phishing_emails"] == 1

    def test_fusion_scan_with_multiple_types(self, repo):
        """One fusion scan with two active threats counts as 1 scan but 2 categories."""
        repo.save_detection(_report(
            RiskLevel.CRITICAL, 0.91,
            ["phishing_email", "malicious_url"]
        ))
        s = repo.get_report_summary()
        assert s["total_scans"] == 1
        assert s["confirmed_threats"] == 1
        assert s["phishing_emails"] == 1
        assert s["malicious_urls"] == 1

    def test_total_scans_ge_confirmed_threats(self, repo):
        """Invariant: total_scans >= confirmed_threats always."""
        repo.save_detection(_report(RiskLevel.CRITICAL, 0.92, ["phishing_email"]))
        repo.save_detection(_report(RiskLevel.LOW,      0.28, ["suspicious_login"], is_threat=True))
        repo.save_detection(_report(RiskLevel.MEDIUM,   0.55, []))
        s = repo.get_report_summary()
        assert s["total_scans"] >= s["confirmed_threats"]

    def test_full_scenario_matrix(self, repo):
        """Full scenario: 1 phishing(HIGH) + 2 URL(MEDIUM+HIGH) + 3 login(LOW+MEDIUM+CRITICAL)
        + 1 network(CRITICAL) + 2 fusion(mixed) — validates the report's
        count labels are truthful."""
        # phishing
        repo.save_detection(_report(RiskLevel.HIGH,     0.78, ["phishing_email"]))
        # URL
        repo.save_detection(_report(RiskLevel.MEDIUM,   0.55, ["malicious_url"]))
        repo.save_detection(_report(RiskLevel.HIGH,     0.71, ["malicious_url"]))
        # login
        repo.save_detection(_report(RiskLevel.LOW,      0.28, ["suspicious_login"], is_threat=True))
        repo.save_detection(_report(RiskLevel.MEDIUM,   0.48, ["suspicious_login"]))
        repo.save_detection(_report(RiskLevel.CRITICAL, 0.93, ["suspicious_login"]))
        # network
        repo.save_detection(_report(RiskLevel.CRITICAL, 0.96, ["network_anomaly"]))
        # fusion (multi-type)
        repo.save_detection(_report(RiskLevel.HIGH, 0.81, ["phishing_email", "malicious_url"]))
        repo.save_detection(_report(RiskLevel.LOW,  0.27, ["suspicious_login", "network_anomaly"], is_threat=True))

        s = repo.get_report_summary()

        # 9 total scans
        assert s["total_scans"] == 9

        # Confirmed (CRITICAL/HIGH): phishing-H, url-H, login-C, network-C, fusion-H = 5
        assert s["confirmed_threats"] == 5

        # Category sums (confirmed rows only):
        # phishing_email: HIGH-phishing(1) + fusion-H(1) = 2
        assert s["phishing_emails"] == 2, f"Expected 2 phishing, got {s['phishing_emails']}"
        # malicious_url: url-H(1) + fusion-H(1) = 2
        assert s["malicious_urls"] == 2, f"Expected 2 URLs, got {s['malicious_urls']}"
        # suspicious_login: login-C(1) only (LOW and MEDIUM not counted)
        assert s["suspicious_logins"] == 1, f"Expected 1 login, got {s['suspicious_logins']}"
        # network_anomaly: network-C(1) only (LOW fusion not counted)
        assert s["network_anomalies"] == 1, f"Expected 1 network, got {s['network_anomalies']}"

        # Invariant: total_scans >= confirmed_threats
        assert s["total_scans"] >= s["confirmed_threats"]


# ─────────────────────────────────────────────────────────────────
# Fix #5 — _enrich_records_for_export()
# ─────────────────────────────────────────────────────────────────

class TestEnrichRecordsForExport:
    """CSV export must have correct derived columns without dropping originals."""

    def _record(self, risk_level: str, is_threat_raw: bool,
                score: float, active_threats: list, ts: str) -> dict:
        return {
            "id": 1,
            "report_id": str(uuid.uuid4()),
            "timestamp": ts,
            "threat_type": ",".join(active_threats) or "none",
            "is_threat": is_threat_raw,
            "is_confirmed_threat": risk_level.lower() in ("critical", "high"),
            "risk_level": risk_level,
            "risk_score": score,
            "probability": score,
            "composite_score": score,
            "model_name": "test",
            "algorithm": "test",
            "input_preview": None,
            "active_threats": active_threats,
        }

    def test_original_columns_preserved(self):
        records = [self._record("high", True, 0.75, ["phishing_email"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert "is_threat" in df.columns
        assert "timestamp" in df.columns
        assert "risk_level" in df.columns

    def test_derived_columns_added(self):
        records = [self._record("low", True, 0.28, ["suspicious_login"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        for col in ["scan_time_ist", "scan_time_utc",
                    "is_confirmed_threat", "detection_status", "threat_types_clean"]:
            assert col in df.columns, f"Missing column: {col}"

    def test_low_risk_is_confirmed_threat_false(self):
        records = [self._record("low", True, 0.28, ["suspicious_login"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert df["is_confirmed_threat"].iloc[0] == False  # noqa: E712

    def test_critical_risk_is_confirmed_threat_true(self):
        records = [self._record("critical", True, 0.95, ["network_anomaly"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert df["is_confirmed_threat"].iloc[0] == True  # noqa: E712

    def test_low_risk_detection_status_is_safe(self):
        records = [self._record("low", True, 0.28, [], "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert df["detection_status"].iloc[0] == "SAFE"

    def test_medium_risk_detection_status_is_review(self):
        records = [self._record("medium", True, 0.55, [], "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert df["detection_status"].iloc[0] == "REVIEW"

    def test_high_risk_detection_status_is_threat(self):
        records = [self._record("high", True, 0.75, [], "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert df["detection_status"].iloc[0] == "THREAT"

    def test_scan_time_ist_has_ist_label(self):
        records = [self._record("high", True, 0.75, ["phishing_email"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert "IST" in df["scan_time_ist"].iloc[0]

    def test_scan_time_utc_has_utc_label(self):
        records = [self._record("high", True, 0.75, ["phishing_email"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        assert "UTC" in df["scan_time_utc"].iloc[0]

    def test_ist_and_utc_differ_by_5h30m(self):
        records = [self._record("high", True, 0.75, [],
                                "2026-09-19T10:00:00")]
        df = _enrich_records_for_export(records)
        ist_str = df["scan_time_ist"].iloc[0].replace(" IST", "")
        utc_str = df["scan_time_utc"].iloc[0].replace(" UTC", "")
        ist_dt = datetime.strptime(ist_str, "%Y-%m-%d %H:%M:%S")
        utc_dt = datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")
        assert ist_dt - utc_dt == timedelta(hours=5, minutes=30)

    def test_threat_types_clean_no_underscores(self):
        records = [self._record("high", True, 0.75,
                                ["malicious_url", "suspicious_login"],
                                "2026-09-19T12:00:00")]
        df = _enrich_records_for_export(records)
        clean = df["threat_types_clean"].iloc[0]
        assert "_" not in clean

    def test_empty_records_returns_empty_dataframe(self):
        import pandas as pd
        df = _enrich_records_for_export([])
        assert isinstance(df, pd.DataFrame)
        assert df.empty

    def test_mixed_risk_levels_all_correct(self):
        """End-to-end: all five risk levels in one export."""
        records = [
            self._record("critical", True,  0.95, ["network_anomaly"],    "2026-09-19T06:00:00"),
            self._record("high",     True,  0.75, ["phishing_email"],     "2026-09-19T07:00:00"),
            self._record("medium",   True,  0.55, ["malicious_url"],      "2026-09-19T08:00:00"),
            self._record("low",      True,  0.28, ["suspicious_login"],   "2026-09-19T09:00:00"),
            self._record("info",     False, 0.10, [],                     "2026-09-19T10:00:00"),
        ]
        df = _enrich_records_for_export(records)
        statuses = df["detection_status"].tolist()
        confirmed = df["is_confirmed_threat"].tolist()
        assert statuses == ["THREAT", "THREAT", "REVIEW", "SAFE", "SAFE"]
        assert confirmed == [True, True, False, False, False]
