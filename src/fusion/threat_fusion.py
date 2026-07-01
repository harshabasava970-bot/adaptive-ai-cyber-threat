"""
threat_fusion.py — Adaptive Threat Fusion Engine (Module 10)
=============================================================
Adaptive AI for Cyber Threat Detection
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
    """Unified threat report from the Adaptive Fusion Engine."""
    report_id: str
    timestamp: str
    composite_risk_score: float
    risk_level: RiskLevel
    is_threat: bool
    active_threats: list[str]
    predictions: dict[str, dict]
    summary: str
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    contributing_modules: list[str] = field(default_factory=list)
    fusion_method: str = "adaptive_confidence_weighted"

    def to_dict(self) -> dict:
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
            "confidence": round(self.confidence, 4),
            "contributing_modules": self.contributing_modules,
            "fusion_method": self.fusion_method,
        }


class AdaptiveThreatFusionEngine:
    """Confidence-weighted adaptive fusion with rule-based escalation."""

    _BASE_WEIGHTS = {
        ThreatType.PHISHING_EMAIL:   0.30,
        ThreatType.MALICIOUS_URL:    0.25,
        ThreatType.SUSPICIOUS_LOGIN: 0.25,
        ThreatType.NETWORK_ANOMALY:  0.20,
    }
    _CREDIBILITY = {
        ThreatType.PHISHING_EMAIL:   0.90,
        ThreatType.MALICIOUS_URL:    0.92,
        ThreatType.SUSPICIOUS_LOGIN: 0.85,
        ThreatType.NETWORK_ANOMALY:  0.88,
    }
    _THRESHOLDS = {"critical": 0.85, "high": 0.65, "medium": 0.45, "low": 0.25}

    def __init__(self) -> None:
        self.config = ConfigManager.get_instance()
        logger.info("AdaptiveThreatFusionEngine initialised.")

    def fuse(
        self,
        phishing_result: Optional[PredictionResult] = None,
        url_result:      Optional[PredictionResult] = None,
        login_result:    Optional[PredictionResult] = None,
        network_result:  Optional[PredictionResult] = None,
    ) -> FusedThreatReport:
        """Fuse results using adaptive confidence-weighted algorithm."""
        available = {
            ThreatType.PHISHING_EMAIL:   phishing_result,
            ThreatType.MALICIOUS_URL:    url_result,
            ThreatType.SUSPICIOUS_LOGIN: login_result,
            ThreatType.NETWORK_ANOMALY:  network_result,
        }
        available = {k: v for k, v in available.items() if v is not None}

        if not available:
            return self._empty_report()

        composite = self._confidence_weighted_score(available)
        composite = self._apply_escalation_rules(composite, available)

        n_threats = sum(1 for r in available.values() if r.is_threat)
        if n_threats >= 3:
            composite = min(composite * 1.20, 0.98)
        elif n_threats >= 2:
            composite = min(composite * 1.10, 0.98)

        avg_confidence = sum(
            r.metadata.get("confidence", 0.75) if r.metadata else 0.75
            for r in available.values()
        ) / len(available)

        risk_level = self._classify_risk(composite)
        active_threats = [t.value for t, r in available.items() if r.is_threat]
        is_threat = bool(active_threats) and composite >= self._THRESHOLDS["low"]

        report = FusedThreatReport(
            report_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat() + "Z",
            composite_risk_score=round(composite, 4),
            risk_level=risk_level,
            is_threat=is_threat,
            active_threats=active_threats,
            predictions={t.value: r.to_dict() for t, r in available.items()},
            summary=self._build_summary(active_threats, composite, risk_level),
            recommendations=self._build_recommendations(active_threats, risk_level),
            confidence=round(avg_confidence, 4),
            contributing_modules=[t.value for t in available],
        )

        if is_threat:
            sec_logger.warning(
                "THREAT | id=%s level=%s score=%.4f threats=%s",
                report.report_id, risk_level.value, composite, active_threats,
            )
        return report

    def _confidence_weighted_score(self, available: dict) -> float:
        total_weight = 0.0
        weighted_sum = 0.0
        for threat_type, result in available.items():
            base_w = self._BASE_WEIGHTS.get(threat_type, 0.25)
            credibility = self._CREDIBILITY.get(threat_type, 0.85)
            confidence = result.metadata.get("confidence", 0.75) if result.metadata else 0.75
            ew = base_w * credibility * confidence
            weighted_sum += ew * result.risk_score
            total_weight += ew
        return round(weighted_sum / total_weight, 4) if total_weight else 0.0

    def _apply_escalation_rules(self, score: float, available: dict) -> float:
        for result in available.values():
            if result.risk_score >= 0.90 and result.is_threat:
                score = max(score, 0.75)
            elif result.risk_score >= 0.80 and result.is_threat:
                score = max(score, 0.60)
        return score

    def _classify_risk(self, score: float) -> RiskLevel:
        if score >= self._THRESHOLDS["critical"]:  return RiskLevel.CRITICAL
        if score >= self._THRESHOLDS["high"]:       return RiskLevel.HIGH
        if score >= self._THRESHOLDS["medium"]:     return RiskLevel.MEDIUM
        if score >= self._THRESHOLDS["low"]:        return RiskLevel.LOW
        return RiskLevel.INFO

    def _empty_report(self) -> FusedThreatReport:
        return FusedThreatReport(
            report_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat() + "Z",
            composite_risk_score=0.0, risk_level=RiskLevel.INFO,
            is_threat=False, active_threats=[], predictions={},
            summary="No inputs provided.", recommendations=[], confidence=0.0,
        )

    def _build_summary(self, active: list, score: float, level: RiskLevel) -> str:
        if not active:
            return f"No threats. Risk: {score:.1%}. Level: {level.value.upper()}."
        names = [t.replace("_", " ").title() for t in active]
        return f"ALERT: {len(active)} threat(s) — {', '.join(names)}. Risk: {score:.1%}. Level: {level.value.upper()}."

    def _build_recommendations(self, active: list, level: RiskLevel) -> list[str]:
        recs = []
        if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            recs.append("IMMEDIATE ACTION: Escalate to Tier-2 SOC analyst.")
        if "phishing_email" in active:
            recs += ["Quarantine the email.", "Report phishing to security team."]
        if "malicious_url" in active:
            recs += ["Block URL at proxy/firewall.", "Scan endpoints that visited this URL."]
        if "suspicious_login" in active:
            recs += ["Force password reset.", "Enable MFA immediately."]
        if "network_anomaly" in active:
            recs += ["Isolate affected network segment.", "Capture packet trace."]
        return recs


# Backward compatibility alias
ThreatFusionEngine = AdaptiveThreatFusionEngine
