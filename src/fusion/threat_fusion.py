"""
threat_fusion.py — Threat Fusion Engine (Module 10)
=====================================================
Adaptive AI for Cyber Threat Detection

Aggregates prediction results from all four detection modules into a
single composite risk score and unified threat assessment.

Design Pattern:
  - Composite: aggregates multiple PredictionResult objects
  - Strategy: different aggregation strategies (weighted, max, mean)

The composite risk score formula:
    risk = w_phishing*p_phi + w_url*p_url + w_login*p_login + w_net*p_net

Weights are configurable in config/settings.yaml under fusion.weights.

IEEE 29148 FR: FR-FUS-001, FR-FUS-002, FR-FUS-003

Author: B.Tech Capstone Project
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid

from src.core.base_model import PredictionResult
from src.core.config import ConfigManager
from src.core.constants import RiskLevel, ThreatType
from src.core.logger import get_logger, get_security_logger

logger = get_logger(__name__)
sec_logger = get_security_logger()


@dataclass
class FusedThreatReport:
    """Unified threat report produced by the Fusion Engine.

    Attributes:
        report_id: Unique UUID for this report (audit trail).
        timestamp: ISO 8601 timestamp of report creation.
        composite_risk_score: Weighted aggregate risk [0.0, 1.0].
        risk_level: Categorical risk (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        is_threat: True if composite_risk_score exceeds high threshold.
        active_threats: List of threat types that triggered detection.
        predictions: Individual module results keyed by ThreatType.
        summary: Human-readable threat summary string.
        recommendations: List of recommended remediation actions.
    """

    report_id: str
    timestamp: str
    composite_risk_score: float
    risk_level: RiskLevel
    is_threat: bool
    active_threats: list[str]
    predictions: dict[str, dict]
    summary: str
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to JSON-compatible dictionary."""
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "composite_risk_score": round(self.composite_risk_score, 4),
            "risk_level": self.risk_level.value,
            "is_threat": self.is_threat,
            "active_threats": self.active_threats,
            "predictions": self.predictions,
            "summary": self.summary,
            "recommendations": self.recommendations,
        }


class ThreatFusionEngine:
    """Aggregates multi-module threat predictions into a unified report.

    Usage:
        engine = ThreatFusionEngine()
        report = engine.fuse(
            phishing_result=phishing_pred,
            url_result=url_pred,
            login_result=login_pred,
            network_result=network_pred,
        )

    Attributes:
        config: ConfigManager instance.
        weights: Per-module risk weighting dictionary.
        thresholds: Risk level boundary thresholds.
    """

    def __init__(self) -> None:
        """Initialise the Fusion Engine with config-driven weights."""
        self.config = ConfigManager.get_instance()
        self.weights = {
            ThreatType.PHISHING_EMAIL:  self.config.get_float("fusion.weights.phishing", 0.30),
            ThreatType.MALICIOUS_URL:   self.config.get_float("fusion.weights.malicious_url", 0.25),
            ThreatType.SUSPICIOUS_LOGIN: self.config.get_float("fusion.weights.login_behaviour", 0.25),
            ThreatType.NETWORK_ANOMALY:  self.config.get_float("fusion.weights.network_anomaly", 0.20),
        }
        self.thresholds = {
            "critical": self.config.get_float("fusion.risk_levels.critical", 0.85),
            "high":     self.config.get_float("fusion.risk_levels.high",     0.65),
            "medium":   self.config.get_float("fusion.risk_levels.medium",   0.45),
            "low":      self.config.get_float("fusion.risk_levels.low",      0.25),
        }
        logger.info("ThreatFusionEngine initialised. Weights: %s", self.weights)

    def fuse(
        self,
        phishing_result: Optional[PredictionResult] = None,
        url_result:      Optional[PredictionResult] = None,
        login_result:    Optional[PredictionResult] = None,
        network_result:  Optional[PredictionResult] = None,
    ) -> FusedThreatReport:
        """Compute composite risk score from available module results.

        Modules that are not provided (None) are excluded from scoring.
        Weights are re-normalised to sum to 1.0 in that case.

        Args:
            phishing_result: Result from phishing email detector.
            url_result:      Result from malicious URL detector.
            login_result:    Result from login behaviour detector.
            network_result:  Result from network anomaly detector.

        Returns:
            FusedThreatReport with composite risk and recommendations.
        """
        results_map: dict[ThreatType, Optional[PredictionResult]] = {
            ThreatType.PHISHING_EMAIL:   phishing_result,
            ThreatType.MALICIOUS_URL:    url_result,
            ThreatType.SUSPICIOUS_LOGIN: login_result,
            ThreatType.NETWORK_ANOMALY:  network_result,
        }

        # Filter to only available results
        available = {k: v for k, v in results_map.items() if v is not None}

        composite_score = self._compute_weighted_score(available)
        risk_level = self._classify_risk(composite_score)
        active_threats = [
            t.value for t, r in available.items() if r.is_threat
        ]
        is_threat = bool(active_threats) and composite_score >= self.thresholds["low"]

        predictions_dict = {
            t.value: r.to_dict() for t, r in available.items()
        }

        summary = self._build_summary(active_threats, composite_score, risk_level)
        recommendations = self._build_recommendations(active_threats, risk_level)
        report_id = str(uuid.uuid4())

        report = FusedThreatReport(
            report_id=report_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            composite_risk_score=composite_score,
            risk_level=risk_level,
            is_threat=is_threat,
            active_threats=active_threats,
            predictions=predictions_dict,
            summary=summary,
            recommendations=recommendations,
        )

        # Log all confirmed threats to the security audit log
        if is_threat:
            sec_logger.warning(
                "THREAT DETECTED | report_id=%s | risk_level=%s | "
                "composite_score=%.4f | threats=%s",
                report_id, risk_level.value, composite_score, active_threats,
            )
        else:
            logger.info(
                "Analysis complete | report_id=%s | risk=%s | score=%.4f",
                report_id, risk_level.value, composite_score,
            )

        return report

    def _compute_weighted_score(
        self, available: dict[ThreatType, PredictionResult]
    ) -> float:
        """Compute weight-normalised composite risk score.

        Args:
            available: Dict of ThreatType → PredictionResult for available modules.

        Returns:
            Composite risk score in [0.0, 1.0].
        """
        if not available:
            return 0.0

        total_weight = sum(self.weights[t] for t in available)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(
            self.weights[t] * r.risk_score for t, r in available.items()
        )
        return round(weighted_sum / total_weight, 4)

    def _classify_risk(self, score: float) -> RiskLevel:
        """Map composite score to categorical RiskLevel.

        Args:
            score: Composite risk score [0, 1].

        Returns:
            RiskLevel enum value.
        """
        if score >= self.thresholds["critical"]:
            return RiskLevel.CRITICAL
        elif score >= self.thresholds["high"]:
            return RiskLevel.HIGH
        elif score >= self.thresholds["medium"]:
            return RiskLevel.MEDIUM
        elif score >= self.thresholds["low"]:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _build_summary(
        self,
        active_threats: list[str],
        score: float,
        risk_level: RiskLevel,
    ) -> str:
        """Build human-readable threat summary.

        Args:
            active_threats: List of triggered threat type strings.
            score: Composite risk score.
            risk_level: Classified risk level.

        Returns:
            Summary string for display in dashboard and reports.
        """
        if not active_threats:
            return (
                f"No threats detected. Composite risk score: {score:.1%}. "
                f"Risk level: {risk_level.value.upper()}."
            )
        threat_names = [t.replace("_", " ").title() for t in active_threats]
        threats_str = ", ".join(threat_names)
        return (
            f"ALERT: {len(active_threats)} threat(s) detected — {threats_str}. "
            f"Composite risk score: {score:.1%}. "
            f"Risk level: {risk_level.value.upper()}."
        )

    def _build_recommendations(
        self,
        active_threats: list[str],
        risk_level: RiskLevel,
    ) -> list[str]:
        """Generate remediation recommendations based on active threats.

        Args:
            active_threats: List of triggered threat type strings.
            risk_level: Classified risk level.

        Returns:
            List of actionable recommendation strings.
        """
        recs = []
        if "phishing_email" in active_threats:
            recs.append("Quarantine the email and do not click any links or attachments.")
            recs.append("Report the phishing attempt to your security team.")
            recs.append("Verify sender identity through an out-of-band channel.")

        if "malicious_url" in active_threats:
            recs.append("Block the URL at the network/proxy level immediately.")
            recs.append("Check browser history for recent visits to this domain.")
            recs.append("Scan endpoints that accessed this URL for malware.")

        if "suspicious_login" in active_threats:
            recs.append("Force password reset for the affected account.")
            recs.append("Enable or verify multi-factor authentication (MFA).")
            recs.append("Review recent login events for the affected user.")
            recs.append("Check for concurrent sessions from different geolocations.")

        if "network_anomaly" in active_threats:
            recs.append("Isolate the affected network segment for investigation.")
            recs.append("Capture full packet data for forensic analysis.")
            recs.append("Review firewall and IDS/IPS rules for this traffic pattern.")

        if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            recs.insert(0, "IMMEDIATE ACTION REQUIRED: Escalate to Tier-2 SOC analyst.")

        return recs
