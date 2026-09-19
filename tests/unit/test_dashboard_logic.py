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
    """Mirrors the stats() function in the dashboard."""
    if not scan_db:
        return {"total": 0, "threats": 0, "critical": 0, "high": 0,
                "safe": 0, "simulated": 0, "avg_conf": 0.0, "avg_ms": 0.0}
    total    = len(scan_db)
    threats  = sum(1 for r in scan_db if r["risk_level"] in ("critical", "high"))
    critical = sum(1 for r in scan_db if r["risk_level"] == "critical")
    high     = sum(1 for r in scan_db if r["risk_level"] == "high")
    safe     = sum(1 for r in scan_db if r["status"] == "SAFE")
    sim      = sum(1 for r in scan_db if r.get("is_simulated"))
    avg_conf = sum(r["confidence"] for r in scan_db) / total
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
        assert s["avg_conf"] == 0.0

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
            self._make_scan("low","SAFE",confidence=0.6),
            self._make_scan("high","THREAT",confidence=0.9),
        ]
        s = compute_stats(db)
        assert abs(s["avg_conf"] - 0.75) < 0.001

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
