"""
models.py — Database ORM Models
=================================
Adaptive AI for Cyber Threat Detection

SQLAlchemy ORM models for all database tables.
Designed for SQLite in development, PostgreSQL in production.

Author: B.Tech Capstone Project
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer,
    String, Text, JSON, create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from src.core.config import ConfigManager
from src.core.logger import get_logger

logger = get_logger(__name__)
Base = declarative_base()


class ThreatDetection(Base):
    """Stores every threat detection event from any module."""

    __tablename__ = "threat_detections"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    report_id      = Column(String(36), unique=True, nullable=False, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, nullable=False)
    threat_type    = Column(String(64), nullable=False, index=True)
    is_threat      = Column(Boolean, nullable=False)
    probability    = Column(Float, nullable=False)
    risk_score     = Column(Float, nullable=False)
    risk_level     = Column(String(16), nullable=False)
    composite_score= Column(Float, nullable=True)
    model_name     = Column(String(128), nullable=False)
    algorithm      = Column(String(64), nullable=False)
    input_preview  = Column(String(512), nullable=True)
    shap_top_feature = Column(String(128), nullable=True)
    inference_ms   = Column(Float, nullable=True)
    active_threats = Column(JSON, nullable=True)
    recommendations= Column(JSON, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_id": self.report_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "threat_type": self.threat_type,
            "is_threat": self.is_threat,
            "probability": self.probability,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "composite_score": self.composite_score,
            "model_name": self.model_name,
            "algorithm": self.algorithm,
            "input_preview": self.input_preview,
            "active_threats": self.active_threats,
        }


class ModelMetricRecord(Base):
    """Stores model evaluation metrics for the performance dashboard."""

    __tablename__ = "model_metrics"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    model_name   = Column(String(128), nullable=False, index=True)
    algorithm    = Column(String(64), nullable=False)
    threat_type  = Column(String(64), nullable=False)
    accuracy     = Column(Float, nullable=True)
    precision    = Column(Float, nullable=True)
    recall       = Column(Float, nullable=True)
    f1_score     = Column(Float, nullable=True)
    roc_auc      = Column(Float, nullable=True)
    cv_mean      = Column(Float, nullable=True)
    cv_std       = Column(Float, nullable=True)
    train_samples= Column(Integer, nullable=True)
    test_samples = Column(Integer, nullable=True)
    train_secs   = Column(Float, nullable=True)
    evaluated_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "algorithm": self.algorithm,
            "threat_type": self.threat_type,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "roc_auc": self.roc_auc,
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
        }


def get_engine(db_url: str | None = None):
    """Create and return a SQLAlchemy engine.

    Args:
        db_url: Override database URL. Falls back to config.

    Returns:
        SQLAlchemy Engine instance.
    """
    config = ConfigManager.get_instance()
    url = db_url or config.get("DATABASE_URL", "sqlite:///./data/threat_db.sqlite")

    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        engine = create_engine(
            url,
            connect_args=connect_args,
            poolclass=StaticPool,
            echo=False,
        )
    else:
        engine = create_engine(url, pool_pre_ping=True, echo=False)

    logger.info("Database engine created: %s", url.split("://")[0])
    return engine


def init_db(engine=None) -> None:
    """Create all tables if they do not already exist.

    Args:
        engine: SQLAlchemy engine. If None, creates one from config.
    """
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialised.")


def get_session(engine=None):
    """Return a SQLAlchemy Session factory.

    Args:
        engine: SQLAlchemy engine.

    Returns:
        sessionmaker class (call it to get a session).
    """
    if engine is None:
        engine = get_engine()
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)
