"""
analytics.py — Analytics & Dashboard Data API Routes
======================================================
Adaptive AI for Cyber Threat Detection

Provides data endpoints consumed by the Streamlit dashboard.

Author: B.Tech Capstone Project
"""

from fastapi import APIRouter, HTTPException
from src.api.schemas import ModelMetricsResponse, RecentDetectionsResponse
from src.core.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get(
    "/recent",
    response_model=RecentDetectionsResponse,
    summary="Get recent threat detections",
)
async def get_recent_detections(limit: int = 50):
    """Return the most recent threat detection events."""
    try:
        from src.database.repository import ThreatRepository
        repo = ThreatRepository()
        detections = repo.get_recent(limit=limit)
        total = repo.get_total_count()
        return RecentDetectionsResponse(total=total, detections=detections)
    except Exception as exc:
        logger.error("Recent detections error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/metrics",
    response_model=ModelMetricsResponse,
    summary="Get model performance metrics",
)
async def get_model_metrics():
    """Return all stored model evaluation metrics."""
    try:
        from src.database.repository import ThreatRepository
        repo = ThreatRepository()
        metrics = repo.get_model_metrics()
        return ModelMetricsResponse(models=metrics)
    except Exception as exc:
        logger.error("Model metrics error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/threat-counts", summary="Get threat type distribution")
async def get_threat_counts():
    """Return count of each threat type — used for pie/bar charts."""
    try:
        from src.database.repository import ThreatRepository
        counts = ThreatRepository().get_threat_counts()
        return {"threat_counts": counts}
    except Exception as exc:
        logger.error("Threat counts error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
