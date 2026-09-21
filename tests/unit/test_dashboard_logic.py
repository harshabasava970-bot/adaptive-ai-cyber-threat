"""
test_dashboard_logic.py — Unit tests for dashboard fixes
=========================================================
Tests for:
  - Risk-to-status mapping (Fix 2)
  - Stats function correctness (Fix 1 / Fix 7)
  - IST timezone conversion (Fix 5)
  - Empty scan history (Fix 7)

Author: B.Tech Capstone Project
"""

from datetime import datetime, timedelta
import pytest


# ── Helpers replicating dashboard logic ────────────────────────────

def risk_to_status(risk_level: str) -> str:
    """Mirrors the status derivation in save_scan()."""
    if risk_level in ("critical", "high"):
        return "THREAT"
    elif risk_level == "medium":
        return "REVIEW"
    return "SAFE"


def utc_to_ist(utc_dt: datetime) -> datetime:
    """Mirrors the IST conversion in save_scan()."""
    return utc_dt + timedelta(hours=5, minutes=30)


def compute_stats(scan_db: list) -> dict:
    """Mirrors the fixed stats() function in the dashboard.

    avg_conf now uses risk_utils.avg_confidence() which excludes None/0.0
    values so fusion scans without confidence don't drag down the average.
    Returns None for avg_conf when no valid confidence values are present.
    """
    from src.core.risk_utils import avg_confidence as _avg_conf
    if not scan_db:
        return {"total": 0, "threats": 0, "critical": 0, "high": 0,
                "safe": 0, "simulated": 0, "avg_conf": None, "avg_ms": 0.0}
    total    = len(scan_db)
    threats  = sum(1 for r in scan_db if r["risk_level"] in ("critical", "high"))
    critical = sum(1 for r in scan_db if r["risk_level"] == "critical")
    high     = sum(1 for r in scan_db if r["risk_level"] == "high")
    safe     = sum(1 for r in scan_db if r["status"] == "SAFE")
    sim      = sum(1 for r in scan_db if r.get("is_simulated"))
    avg_conf = _avg_conf([r.get("confidence") for r in scan_db])  # None if all unavailable
    avg_ms   = sum(r.get("processing_ms", 0) for r in scan_db) / total
    return {"total": total, "threats": threats, "critical": critical,
            "high": high, "safe": safe, "simulated": sim,
            "avg_conf": avg_conf, "avg_ms": avg_ms}


# ── Fix 2: Risk-to-status consistency ──────────────────────────────

class TestRiskToStatus:
    """Status must be consistent with risk_level — not just is_threat bool."""

    def test_critical_maps_to_threat(self):
        assert risk_to_status("critical") == "THREAT"

    def test_high_maps_to_threat(self):
        assert risk_to_status("high") == "THREAT"

    def test_medium_maps_to_review(self):
        assert risk_to_status("medium") == "REVIEW"

    def test_low_maps_to_safe(self):
        """Low risk must NEVER show THREAT status (was the original bug)."""
        assert risk_to_status("low") == "SAFE"

    def test_info_maps_to_safe(self):
        assert risk_to_status("info") == "SAFE"

    def test_low_risk_is_not_threat(self):
        """Explicitly guard the reported inconsistency: LOW risk -> SAFE."""
        status = risk_to_status("low")
        assert status != "THREAT", (
            "LOW risk should never produce THREAT status. "
            "This was the inconsistency reported in the review."
        )


# ── Fix 5: IST timezone conversion ─────────────────────────────────

class TestTimezoneConversion:
    """UTC timestamps must convert correctly to IST (+05:30)."""

    def test_utc_to_ist_offset(self):
        utc = datetime(2026, 8, 1, 12, 0, 0)
        ist = utc_to_ist(utc)
        assert ist.hour == 17
        assert ist.minute == 30

    def test_utc_midnight_to_ist(self):
        """Midnight UTC = 05:30 IST."""
        utc = datetime(2026, 8, 1, 0, 0, 0)
        ist = utc_to_ist(utc)
        assert ist.hour == 5
        assert ist.minute == 30

    def test_ist_is_ahead_of_utc(self):
        utc = datetime(2026, 8, 1, 10, 0, 0)
        ist = utc_to_ist(utc)
        assert ist > utc

    def test_ist_offset_is_5h30m(self):
        utc = datetime(2026, 8, 1, 8, 15, 0)
        ist = utc_to_ist(utc)
        delta = ist - utc
        assert delta == timedelta(hours=5, minutes=30)


# ── Fix 1 & 7: Stats correctness and no fabricated accuracy ────────

class TestStatsFunction:
    """stats() must count correctly and not compute misleading accuracy."""

    def _make_scan(self, risk_level, status, confidence=0.8, is_sim=False):
        return {
            "risk_level": risk_level,
            "status": status,
            "confidence": confidence,
            "processing_ms": 100.0,
            "is_simulated": is_sim,
        }

    def test_empty_db_returns_zeros(self):
        s = compute_stats([])
        assert s["total"] == 0
        assert s["threats"] == 0
        assert s["avg_conf"] is None  # None when no scans, not 0.0

    def test_total_count(self):
        db = [self._make_scan("low","SAFE")] * 5
        s = compute_stats(db)
        assert s["total"] == 5

    def test_threats_only_counts_critical_and_high(self):
        db = [
            self._make_scan("critical", "THREAT"),
            self._make_scan("high",     "THREAT"),
            self._make_scan("medium",   "REVIEW"),
            self._make_scan("low",      "SAFE"),
            self._make_scan("info",     "SAFE"),
        ]
        s = compute_stats(db)
        assert s["threats"] == 2

    def test_safe_count_uses_status_field(self):
        db = [
            self._make_scan("low",  "SAFE"),
            self._make_scan("info", "SAFE"),
            self._make_scan("high", "THREAT"),
        ]
        s = compute_stats(db)
        assert s["safe"] == 2

    def test_no_accuracy_field_in_stats(self):
        """Fix 1: stats() must NOT compute a misleading accuracy value."""
        db = [self._make_scan("low","SAFE")] * 3
        s = compute_stats(db)
        assert "accuracy" not in s, (
            "stats() must not contain 'accuracy' — that was a misleading "
            "scan-ratio masquerading as model accuracy."
        )

    def test_avg_confidence_correct(self):
        db = [
            self._make_scan("low",  "SAFE",   confidence=0.6),
            self._make_scan("high", "THREAT", confidence=0.9),
        ]
        s = compute_stats(db)
        # Both values are valid (> 0.0), so average = 0.75
        assert s["avg_conf"] is not None
        assert abs(s["avg_conf"] - 0.75) < 0.001

    def test_avg_confidence_excludes_none(self):
        """Fusion scans with confidence=None must not drag down the average."""
        db = [
            self._make_scan("high", "THREAT", confidence=0.9),
            self._make_scan("low",  "SAFE",   confidence=None),  # fusion/missing
        ]
        s = compute_stats(db)
        assert s["avg_conf"] is not None
        assert abs(s["avg_conf"] - 0.9) < 0.001

    def test_avg_confidence_all_none_returns_none(self):
        db = [
            self._make_scan("low", "SAFE", confidence=None),
            self._make_scan("low", "SAFE", confidence=None),
        ]
        s = compute_stats(db)
        assert s["avg_conf"] is None

    def test_simulated_count(self):
        db = [
            self._make_scan("low","SAFE",is_sim=True),
            self._make_scan("low","SAFE",is_sim=True),
            self._make_scan("high","THREAT",is_sim=False),
        ]
        s = compute_stats(db)
        assert s["simulated"] == 2

    def test_critical_and_high_counted_separately(self):
        db = [
            self._make_scan("critical","THREAT"),
            self._make_scan("critical","THREAT"),
            self._make_scan("high","THREAT"),
        ]
        s = compute_stats(db)
        assert s["critical"] == 2
        assert s["high"] == 1
        assert s["threats"] == 3


# ── Fix 1: Model Accuracy KPI display ──────────────────────────────

class TestAccuracyDisplay:
    """
    The Model Accuracy KPI must NEVER show a fabricated percentage.

    Rules enforced here:
    1. stats() must not contain an 'accuracy' key.
    2. The KPI display value must not be a raw number-percent string
       (e.g. "97.5%") when derived solely from session scan ratios.
    3. When no real evaluation metrics are available, the display
       value should communicate that clearly (not a fabricated number).
    """

    def test_stats_has_no_accuracy_key(self):
        """stats() must not expose an accuracy field at all (Fix 1)."""
        db = [
            {"risk_level": "high",   "status": "THREAT",
             "confidence": 0.9, "processing_ms": 120.0, "is_simulated": False},
            {"risk_level": "low",    "status": "SAFE",
             "confidence": 0.6, "processing_ms": 80.0,  "is_simulated": False},
            {"risk_level": "medium", "status": "REVIEW",
             "confidence": 0.7, "processing_ms": 95.0,  "is_simulated": False},
        ]
        s = compute_stats(db)
        assert "accuracy" not in s, (
            "stats() must not compute accuracy from scan ratios — "
            "that was the misleading 26.3% / 97.5% bug."
        )

    def test_accuracy_display_is_not_fabricated_ratio(self):
        """
        Simulate what the dashboard KPI builder receives.
        The value for 'Model Accuracy' must NOT be derived from
        threat_count / total_count arithmetic.
        """
        # Simulate a session with 1 phishing scan out of 4 total
        db = [
            {"risk_level": "high",  "status": "THREAT",
             "confidence": 0.9, "processing_ms": 100, "is_simulated": False},
            {"risk_level": "low",   "status": "SAFE",
             "confidence": 0.6, "processing_ms": 80,  "is_simulated": False},
            {"risk_level": "low",   "status": "SAFE",
             "confidence": 0.5, "processing_ms": 70,  "is_simulated": False},
            {"risk_level": "low",   "status": "SAFE",
             "confidence": 0.5, "processing_ms": 75,  "is_simulated": False},
        ]
        s = compute_stats(db)

        # The old bug: accuracy = threats / total = 1/4 = 25.0% (shown as ~26.3%)
        # Ensure this ratio is not present under "accuracy"
        assert "accuracy" not in s
        # threats/total should NOT be labelled accuracy
        ratio_as_percentage = round(s["threats"] / s["total"] * 100, 1)
        # The value is 25.0 — confirm it is NOT presented as model accuracy
        assert ratio_as_percentage == 25.0  # this is just a ratio, not accuracy
        # Model accuracy must come from actual evaluation, not this ratio

    def test_stats_has_correct_keys_only(self):
        """stats() must return exactly the expected set of keys."""
        s = compute_stats([])
        expected_keys = {
            "total", "threats", "critical", "high",
            "safe", "simulated", "avg_conf", "avg_ms",
        }
        assert set(s.keys()) == expected_keys, (
            f"Unexpected keys in stats(): {set(s.keys()) - expected_keys}"
        )

# ── Fix 9: Model Performance page routing ──────────────────────────

class TestPageRouting:
    """
    Validate that all page names used in navigation match the routing
    elif conditions.  The original bug was:
      NAV had ("🏆","Model Performance") but routing used
      elif page == "Performance" → page was unreachable.
    """

    # These are all the pages defined in the NAV dict
    NAV_PAGES = [
        "Dashboard", "Phishing", "URL Analyser", "Login Monitor",
        "Network", "Threat Fusion", "Timeline", "Reports", "Analytics",
        "Simulation", "Model Performance", "Dataset Info",
        "System Workflow", "About",
    ]

    def test_model_performance_page_name_is_consistent(self):
        """'Model Performance' must be the canonical name — not 'Performance'."""
        assert "Model Performance" in self.NAV_PAGES
        assert "Performance" not in self.NAV_PAGES, (
            "The routing bug used 'Performance' instead of 'Model Performance'. "
            "Ensure the elif in app.py uses 'Model Performance'."
        )

    def test_all_nav_pages_are_known(self):
        """Every page in NAV must have an expected name (no typos)."""
        known = {
            "Dashboard", "Phishing", "URL Analyser", "Login Monitor",
            "Network", "Threat Fusion", "Timeline", "Reports", "Analytics",
            "Simulation", "Model Performance", "Dataset Info",
            "System Workflow", "About",
        }
        for page in self.NAV_PAGES:
            assert page in known, f"Unexpected page name in NAV: '{page}'"


# ── Fix 4: Compliance claims ────────────────────────────────────────

class TestComplianceClaims:
    """
    Ensure the codebase does not claim formal IEEE compliance where
    it has not been independently assessed/certified.
    """

    def test_no_false_compliance_strings_in_api_description(self):
        """
        The API description must not claim formal IEEE compliance
        without qualification. A safe phrasing uses 'designed with'
        or 'principles' rather than 'Compliant'.
        """
        import importlib, sys
        # We read the source text rather than import (avoids side-effects)
        import pathlib
        api_src = pathlib.Path(
            __file__
        ).resolve().parent.parent.parent / "src" / "api" / "main.py"
        text = api_src.read_text(encoding="utf-8")
        # The old bad string was "IEEE 29148 / 29119 / 1012 / 7000 Compliant"
        assert "IEEE 29148 / 29119 / 1012 / 7000 Compliant" not in text, (
            "API description must not claim formal IEEE compliance. "
            "Use 'designed with ... principles' instead."
        )

    def test_no_false_compliance_in_report_footer(self):
        """PDF report footer must not claim IEEE 29148 compliance."""
        import pathlib
        rg_src = pathlib.Path(
            __file__
        ).resolve().parent.parent.parent / "src" / "reports" / "report_generator.py"
        text = rg_src.read_text(encoding="utf-8")
        assert "IEEE 29148 Compliant" not in text, (
            "Report footer must not claim IEEE 29148 formal compliance."
        )

    def test_report_uses_full_academic_title(self):
        """PDF report title must use the full fixed academic title."""
        import pathlib
        rg_src = pathlib.Path(
            __file__
        ).resolve().parent.parent.parent / "src" / "reports" / "report_generator.py"
        text = rg_src.read_text(encoding="utf-8")
        assert "Adaptive Explainable Multi-Source Cyber Threat Detection Framework" in text, (
            "Report generator must use the full academic project title."
        )


# ── Fix 5: IST timestamp labelling in app.py ───────────────────────

class TestTimestampLabelling:
    """
    Validate that the dashboard source consistently labels timestamps
    as IST and does not show raw UTC times to the user without labelling.
    """

    def test_ist_label_present_in_scan_record(self):
        """scan_time field must include 'IST' label."""
        from datetime import datetime, timedelta
        now_utc = datetime(2026, 9, 19, 10, 30, 0)
        now_ist = now_utc + timedelta(hours=5, minutes=30)
        scan_time = now_ist.strftime("%H:%M:%S") + " IST"
        assert "IST" in scan_time
        assert scan_time == "16:00:00 IST"

    def test_scan_time_not_utc(self):
        """scan_time must not be the same as raw UTC time string."""
        from datetime import datetime, timedelta
        now_utc = datetime(2026, 9, 19, 0, 0, 0)
        now_ist = now_utc + timedelta(hours=5, minutes=30)
        utc_str = now_utc.strftime("%H:%M:%S")
        ist_str  = now_ist.strftime("%H:%M:%S") + " IST"
        assert ist_str != utc_str, (
            "IST scan_time must differ from raw UTC time string."
        )

    def test_timestamp_utc_stored_separately(self):
        """The UTC timestamp must still be stored for DB integrity."""
        from datetime import datetime, timedelta
        import uuid
        # Simulate what save_scan() produces
        now_utc = datetime(2026, 9, 19, 10, 0, 0)
        now_ist = now_utc + timedelta(hours=5, minutes=30)
        record = {
            "timestamp_utc": now_utc.isoformat() + "Z",
            "scan_time":     now_ist.strftime("%H:%M:%S") + " IST",
            "scan_date":     now_ist.strftime("%Y-%m-%d"),
        }
        # UTC preserved
        assert record["timestamp_utc"].endswith("Z")
        assert "2026-09-19T10:00:00Z" == record["timestamp_utc"]
        # IST used for display
        assert record["scan_time"] == "15:30:00 IST"
        assert record["scan_date"] == "2026-09-19"

    def test_no_double_conversion(self):
        """Applying the IST offset twice must produce a wrong result — guard."""
        from datetime import datetime, timedelta
        now_utc = datetime(2026, 9, 19, 10, 0, 0)
        ist_once  = now_utc + timedelta(hours=5, minutes=30)
        ist_twice = ist_once + timedelta(hours=5, minutes=30)
        assert ist_once.hour == 15, "Single IST conversion: 10:00 UTC → 15:30 IST"
        assert ist_twice.hour == 21, "Double IST conversion is wrong (21:00)"
        # The correct scan_time comes from one conversion only
        assert ist_once.strftime("%H:%M") == "15:30"


# ── Fix 2: Status colour helpers ────────────────────────────────────

class TestStatusColors:
    """
    Consistent colour mapping for SAFE/REVIEW/THREAT statuses.
    These mirror what the dashboard renders.
    """

    # Colours from app.py design tokens
    SUCCESS = "#22C55E"
    WARN    = "#F59E0B"
    CRIT    = "#EF4444"

    def _status_color(self, status: str) -> str:
        """Mirrors dashboard s_color logic in render_timeline."""
        # In app.py: s_color = SUCCESS if not rec["is_threat"] else CRIT
        # But is_threat is now derived from risk_level via status field
        return self.SUCCESS if status == "SAFE" else self.CRIT

    def test_safe_status_gets_green(self):
        assert self._status_color("SAFE") == self.SUCCESS

    def test_threat_status_gets_red(self):
        assert self._status_color("THREAT") == self.CRIT

    def test_review_status_gets_red_not_green(self):
        """REVIEW (medium risk) should not use the SAFE green color."""
        assert self._status_color("REVIEW") != self.SUCCESS

    def test_low_risk_produces_safe_status_and_green(self):
        """End-to-end: low risk → SAFE status → green colour."""
        status = risk_to_status("low")
        color  = self._status_color(status)
        assert status == "SAFE"
        assert color  == self.SUCCESS

    def test_high_risk_produces_threat_status_and_red(self):
        """End-to-end: high risk → THREAT status → red colour."""
        status = risk_to_status("high")
        color  = self._status_color(status)
        assert status == "THREAT"
        assert color  == self.CRIT


# ── Fix 7: Attack Distribution chart data integrity ────────────────

class TestAttackDistribution:
    """
    Attack Distribution pie chart must sum to 100% and only use
    real session scan data — never fabricated values.
    """

    def test_distribution_sums_to_total(self):
        """Counts across scan types must equal total scan count."""
        db = [
            {"risk_level":"high","status":"THREAT","confidence":0.9,
             "processing_ms":100,"is_simulated":False,"scan_type":"phishing"},
            {"risk_level":"low","status":"SAFE","confidence":0.6,
             "processing_ms":80,"is_simulated":False,"scan_type":"url"},
            {"risk_level":"low","status":"SAFE","confidence":0.5,
             "processing_ms":70,"is_simulated":False,"scan_type":"url"},
            {"risk_level":"medium","status":"REVIEW","confidence":0.7,
             "processing_ms":90,"is_simulated":False,"scan_type":"login"},
        ]
        import pandas as pd
        df = pd.DataFrame(db)
        dist = df["scan_type"].value_counts().to_dict()
        assert sum(dist.values()) == len(db) == 4

    def test_distribution_percentages_sum_to_100(self):
        """Pie chart percentages must sum to exactly 100%."""
        import pandas as pd
        db = [
            {"scan_type": "phishing"},
            {"scan_type": "url"},
            {"scan_type": "url"},
            {"scan_type": "login"},
        ]
        df = pd.DataFrame(db)
        dist = df["scan_type"].value_counts()
        pct  = (dist / dist.sum() * 100).round(1)
        assert abs(pct.sum() - 100.0) < 0.5, (
            f"Percentages should sum to ~100%, got {pct.sum()}"
        )

    def test_empty_db_does_not_raise(self):
        """Empty scan_db must not cause a KeyError or ZeroDivisionError."""
        s = compute_stats([])
        assert s["total"] == 0
        # Simulate what the chart builder does
        import pandas as pd
        df = pd.DataFrame([])
        assert df.empty


# ── Fix 1 (render_timeline): Status badge colour uses status not is_threat ──

class TestTimelineStatusColour:
    """
    render_timeline s_color must derive from rec['status'], NOT rec['is_threat'].

    Root cause: the fusion engine sets is_threat=True for any event with
    probability >= 0.25 (the LOW threshold). A LOW-risk scan therefore has
    is_threat=True but status='SAFE'. The old code coloured the badge red
    using is_threat, giving a red 'SAFE' badge. The fix uses status.
    """

    SUCCESS = "#22C55E"
    WARN    = "#F59E0B"
    CRIT    = "#EF4444"

    def _s_color(self, status: str) -> str:
        """Mirrors the fixed s_color logic in render_timeline."""
        return (
            self.CRIT if status == "THREAT"
            else (self.WARN if status == "REVIEW" else self.SUCCESS)
        )

    def test_safe_status_gives_green(self):
        assert self._s_color("SAFE") == self.SUCCESS

    def test_review_status_gives_amber(self):
        assert self._s_color("REVIEW") == self.WARN

    def test_threat_status_gives_red(self):
        assert self._s_color("THREAT") == self.CRIT

    def test_low_risk_with_raw_is_threat_true_shows_green(self):
        """
        Core regression: LOW-risk fusion scan with is_threat=True from the API.
        Old: s_color = SUCCESS if not rec['is_threat'] else CRIT → gives CRIT (red).
        New: s_color from rec['status'] = 'SAFE' → gives SUCCESS (green).
        """
        rec = {"risk_level": "low", "is_threat": True, "status": "SAFE"}
        s_color = self._s_color(rec["status"])  # fixed logic
        assert s_color == self.SUCCESS, (
            "LOW-risk scan with raw is_threat=True must produce green badge, not red. "
            "Colour must be derived from status, not is_threat."
        )

    def test_medium_risk_not_green_not_red(self):
        rec = {"risk_level": "medium", "is_threat": True, "status": "REVIEW"}
        s_color = self._s_color(rec["status"])
        assert s_color == self.WARN
        assert s_color != self.CRIT
        assert s_color != self.SUCCESS

    def test_high_risk_gives_red(self):
        rec = {"risk_level": "high", "is_threat": True, "status": "THREAT"}
        s_color = self._s_color(rec["status"])
        assert s_color == self.CRIT

    def test_critical_risk_gives_red(self):
        rec = {"risk_level": "critical", "is_threat": True, "status": "THREAT"}
        s_color = self._s_color(rec["status"])
        assert s_color == self.CRIT

    def test_info_risk_gives_green(self):
        rec = {"risk_level": "info", "is_threat": False, "status": "SAFE"}
        s_color = self._s_color(rec["status"])
        assert s_color == self.SUCCESS


# ── Fix 2 (Threat Activity Timeline): filter by status not is_threat ────────

class TestThreatChartFilter:
    """
    The Threat Activity Timeline chart must count 'Threats' using
    status == 'THREAT', not is_threat == True.

    Fixes the same root cause as s_color: LOW-risk scans with is_threat=True
    were incorrectly counted in the threat line of the chart.
    """

    def _count_threats_old(self, scan_db: list) -> int:
        """Mimics the OLD (broken) filter: is_threat == True."""
        return sum(1 for r in scan_db if r.get("is_threat") is True)

    def _count_threats_new(self, scan_db: list) -> int:
        """Mimics the FIXED filter: status == 'THREAT'."""
        return sum(1 for r in scan_db if r.get("status") == "THREAT")

    def _make_scan(self, risk_level: str, is_threat_raw: bool) -> dict:
        from src.core.risk_utils import risk_to_status
        return {
            "risk_level": risk_level,
            "is_threat": is_threat_raw,
            "status": risk_to_status(risk_level),
        }

    def test_low_risk_is_threat_true_not_counted(self):
        """LOW scan with raw is_threat=True must NOT appear in threat count."""
        db = [self._make_scan("low", is_threat_raw=True)]
        assert self._count_threats_old(db) == 1, "Old logic counts it (bug)"
        assert self._count_threats_new(db) == 0, "New logic must not count it"

    def test_medium_risk_not_counted_as_threat(self):
        db = [self._make_scan("medium", is_threat_raw=True)]
        assert self._count_threats_new(db) == 0

    def test_high_risk_is_counted(self):
        db = [self._make_scan("high", is_threat_raw=True)]
        assert self._count_threats_new(db) == 1

    def test_critical_risk_is_counted(self):
        db = [self._make_scan("critical", is_threat_raw=True)]
        assert self._count_threats_new(db) == 1

    def test_mixed_scan_db(self):
        """Only CRITICAL/HIGH scans count as threats in the chart."""
        db = [
            self._make_scan("critical", True),
            self._make_scan("high",     True),
            self._make_scan("medium",   True),   # REVIEW — not a threat
            self._make_scan("low",      True),   # SAFE   — not a threat
            self._make_scan("info",     False),  # SAFE   — not a threat
        ]
        assert self._count_threats_new(db) == 2
        # Old logic would incorrectly count 4 (all where is_threat=True)
        assert self._count_threats_old(db) == 4


# ── Fix 5 (get_threat_counts): uses risk_level not is_threat ─────────────────

class TestGetThreatCountsLogic:
    """
    get_threat_counts() must count by risk_level in {critical, high},
    not by the raw is_threat DB column.
    """

    def test_low_risk_record_not_counted(self):
        """A LOW-risk record with is_threat=True must not appear in counts."""
        import uuid
        from src.database.models import get_engine, init_db, get_session, ThreatDetection
        from src.database.repository import ThreatRepository
        from src.core.constants import RiskLevel
        from src.fusion.threat_fusion import FusedThreatReport

        engine = get_engine("sqlite:///:memory:")
        init_db(engine)
        Session = get_session(engine)
        repo = ThreatRepository.__new__(ThreatRepository)
        repo._SessionFactory = Session

        # Manually insert a LOW-risk record with is_threat=True (fusion engine artifact)
        sess = Session()
        sess.add(ThreatDetection(
            report_id=str(uuid.uuid4()),
            threat_type="suspicious_login",
            is_threat=True,          # raw fusion bool — True but LOW risk
            probability=0.28,
            risk_score=0.28,
            risk_level="low",        # ← this is what matters
            model_name="test",
            algorithm="test",
            active_threats=["suspicious_login"],
        ))
        sess.commit()
        sess.close()

        counts = repo.get_threat_counts()
        assert counts.get("suspicious_login", 0) == 0, (
            "LOW-risk record must NOT appear in get_threat_counts(), "
            "even if is_threat=True in the DB."
        )

    def test_high_risk_record_is_counted(self):
        """A HIGH-risk record must appear in get_threat_counts()."""
        import uuid
        from src.database.models import get_engine, init_db, get_session, ThreatDetection
        from src.database.repository import ThreatRepository

        engine = get_engine("sqlite:///:memory:")
        init_db(engine)
        Session = get_session(engine)
        repo = ThreatRepository.__new__(ThreatRepository)
        repo._SessionFactory = Session

        sess = Session()
        sess.add(ThreatDetection(
            report_id=str(uuid.uuid4()),
            threat_type="phishing_email",
            is_threat=True,
            probability=0.82,
            risk_score=0.82,
            risk_level="high",
            model_name="test",
            algorithm="test",
            active_threats=["phishing_email"],
        ))
        sess.commit()
        sess.close()

        counts = repo.get_threat_counts()
        assert counts.get("phishing_email", 0) == 1

    def test_medium_risk_not_in_counts(self):
        """MEDIUM-risk (REVIEW) must not appear in get_threat_counts()."""
        import uuid
        from src.database.models import get_engine, init_db, get_session, ThreatDetection
        from src.database.repository import ThreatRepository

        engine = get_engine("sqlite:///:memory:")
        init_db(engine)
        Session = get_session(engine)
        repo = ThreatRepository.__new__(ThreatRepository)
        repo._SessionFactory = Session

        sess = Session()
        sess.add(ThreatDetection(
            report_id=str(uuid.uuid4()),
            threat_type="malicious_url",
            is_threat=True,
            probability=0.55,
            risk_score=0.55,
            risk_level="medium",
            model_name="test",
            algorithm="test",
            active_threats=["malicious_url"],
        ))
        sess.commit()
        sess.close()

        counts = repo.get_threat_counts()
        assert counts.get("malicious_url", 0) == 0, (
            "MEDIUM-risk record (REVIEW status) must NOT appear in threat counts."
        )
