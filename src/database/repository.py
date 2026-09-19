"""
repository.py — Database Repository (Data Access Layer)
=========================================================
Adaptive AI for Cyber Threat Detection

Repository pattern: all database operations go through this class.
No raw SQL anywhere else in the codebase.

Author: B.Tech Capstone Project
"""

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from src.core.base_model import ModelMetrics, PredictionResult
from src.core.exceptions import DatabaseError, RecordNotFoundError
from src.core.logger import get_logger
from src.database.models import ModelMetricRecord, ThreatDetection, get_engine, get_session, init_db
from src.fusion.threat_fusion import FusedThreatReport

logger = get_logger(__name__)


class ThreatRepository:
    """All database read/write operations for threat detections.

    Usage:
        repo = ThreatRepository()
        repo.save_detection(report)
        recent = repo.get_recent(limit=50)
    """

    def __init__(self, db_url: Optional[str] = None) -> None:
        """Initialise repository with database connection.

        Args:
            db_url: Optional override database URL.
        """
        engine = get_engine(db_url)
        init_db(engine)
        self._SessionFactory = get_session(engine)

    def save_detection(self, report: FusedThreatReport) -> int:
        """Persist a FusedThreatReport to the database.

        Args:
            report: Completed fusion engine report.

        Returns:
            Auto-incremented database row ID.

        Raises:
            DatabaseError: If save fails.
        """
        session: Session = self._SessionFactory()
        try:
            record = ThreatDetection(
                report_id=report.report_id,
                timestamp=datetime.utcnow(),
                threat_type=",".join(report.active_threats) or "none",
                is_threat=report.is_threat,
                probability=report.composite_risk_score,
                risk_score=report.composite_risk_score,
                risk_level=report.risk_level.value,
                composite_score=report.composite_risk_score,
                model_name="fusion_engine",
                algorithm="weighted_average",
                active_threats=report.active_threats,
                recommendations=report.recommendations,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            logger.debug("Detection saved. report_id=%s id=%s", report.report_id, record.id)
            return record.id
        except Exception as exc:
            session.rollback()
            raise DatabaseError("INSERT", str(exc)) from exc
        finally:
            session.close()

    def get_recent(self, limit: int = 50) -> list[dict]:
        """Retrieve most recent threat detections.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of threat detection dicts ordered by timestamp desc.
        """
        session: Session = self._SessionFactory()
        try:
            records = (
                session.query(ThreatDetection)
                .order_by(ThreatDetection.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [r.to_dict() for r in records]
        except Exception as exc:
            raise DatabaseError("SELECT", str(exc)) from exc
        finally:
            session.close()

    def get_threat_counts(self) -> dict:
        """Return counts of threats by type for dashboard charts.

        Returns:
            Dict mapping threat_type → count.
        """
        session: Session = self._SessionFactory()
        try:
            records = session.query(ThreatDetection).filter(
                ThreatDetection.is_threat == True  # noqa: E712
            ).all()
            counts: dict = {}
            for r in records:
                for threat in (r.active_threats or []):
                    counts[threat] = counts.get(threat, 0) + 1
            return counts
        except Exception as exc:
            raise DatabaseError("SELECT threat_counts", str(exc)) from exc
        finally:
            session.close()

    def get_total_count(self) -> int:
        """Return total number of detection events in the database."""
        session: Session = self._SessionFactory()
        try:
            return session.query(ThreatDetection).count()
        finally:
            session.close()

    def save_model_metrics(self, metrics: ModelMetrics, threat_type: str) -> None:
        """Persist model evaluation metrics.

        Args:
            metrics: ModelMetrics dataclass from model.evaluate().
            threat_type: The threat type this model targets.
        """
        session: Session = self._SessionFactory()
        try:
            import numpy as np
            record = ModelMetricRecord(
                model_name=metrics.model_name,
                algorithm=metrics.algorithm.value,
                threat_type=threat_type,
                accuracy=metrics.accuracy,
                precision=metrics.precision,
                recall=metrics.recall,
                f1_score=metrics.f1_score,
                roc_auc=metrics.roc_auc,
                cv_mean=float(np.mean(metrics.cv_scores)) if metrics.cv_scores is not None else None,
                cv_std=float(np.std(metrics.cv_scores)) if metrics.cv_scores is not None else None,
                train_samples=metrics.training_samples,
                test_samples=metrics.test_samples,
                train_secs=metrics.training_time_seconds,
                evaluated_at=datetime.utcnow(),
            )
            session.add(record)
            session.commit()
            logger.info("Model metrics saved: %s", metrics.model_name)
        except Exception as exc:
            session.rollback()
            raise DatabaseError("INSERT model_metrics", str(exc)) from exc
        finally:
            session.close()

    def get_report_summary(self) -> dict:
        """Return a self-consistent summary of detection counts for reports.

        Counting methodology (single source of truth):
        ─────────────────────────────────────────────
        • total_scans         — every row in threat_detections (all risk levels).
        • confirmed_threats   — rows where risk_level is CRITICAL or HIGH only.
                                Matches the dashboard/timeline THREAT status.
        • category_counts     — per threat-type counts drawn from the
                                active_threats JSON column of CONFIRMED THREAT rows
                                only (critical / high). A single fusion scan that
                                contains both phishing_email and malicious_url
                                contributes 1 to total_scans and 1 to
                                confirmed_threats, but 1 to each of the two
                                category keys it contains.

        The label hierarchy in reports is therefore:
            Total Scans ≥ Confirmed Threats
            Confirmed Threats ≥ sum(category_counts.values())
              (because a threat row with active_threats=[] contributes 0
               to category counts but 1 to confirmed_threats)

        Do NOT compare Total Scans directly with category sums — they measure
        different things and are intentionally displayed with separate labels.

        Returns:
            dict with keys: total_scans, confirmed_threats, phishing_emails,
            malicious_urls, suspicious_logins, network_anomalies.
        """
        _confirmed = {"critical", "high"}
        session: Session = self._SessionFactory()
        try:
            all_records = session.query(ThreatDetection).all()
            total_scans = len(all_records)
            confirmed_threats = 0
            category_counts: dict = {
                "phishing_email": 0,
                "malicious_url": 0,
                "suspicious_login": 0,
                "network_anomaly": 0,
            }
            for r in all_records:
                if (r.risk_level or "").lower() in _confirmed:
                    confirmed_threats += 1
                    for threat in (r.active_threats or []):
                        if threat in category_counts:
                            category_counts[threat] += 1
                        else:
                            category_counts[threat] = 1
            return {
                "total_scans": total_scans,
                "confirmed_threats": confirmed_threats,
                "phishing_emails": category_counts.get("phishing_email", 0),
                "malicious_urls": category_counts.get("malicious_url", 0),
                "suspicious_logins": category_counts.get("suspicious_login", 0),
                "network_anomalies": category_counts.get("network_anomaly", 0),
            }
        except Exception as exc:
            raise DatabaseError("SELECT report_summary", str(exc)) from exc
        finally:
            session.close()

    def get_model_metrics(self) -> list[dict]:
        """Retrieve all stored model evaluation metrics for dashboard display.

        Returns:
            List of metric dicts ordered by evaluation date descending.
        """
        session: Session = self._SessionFactory()
        try:
            records = session.query(ModelMetricRecord).order_by(
                ModelMetricRecord.evaluated_at.desc()
            ).all()
            return [r.to_dict() for r in records]
        except Exception as exc:
            raise DatabaseError("SELECT model_metrics", str(exc)) from exc
        finally:
            session.close()
