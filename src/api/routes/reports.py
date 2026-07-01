"""
reports.py — Report Download API Routes
=========================================
Adaptive AI for Cyber Threat Detection

Author: B.Tech Capstone Project
"""

from fastapi import APIRouter
from fastapi.responses import Response, StreamingResponse
import io

from src.core.logger import get_logger
from src.reports.report_generator import ReportGenerator

logger = get_logger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/csv", summary="Download CSV threat report")
async def download_csv():
    """Stream a CSV file of recent threat detections."""
    try:
        gen = ReportGenerator()
        csv_bytes = gen.generate_csv_bytes(limit=1000)
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threat_report.csv"},
        )
    except Exception as exc:
        logger.error("CSV generation error: %s", exc)
        from fastapi import HTTPException, status
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/pdf", summary="Download PDF threat report")
async def download_pdf():
    """Stream a PDF report of recent threat detections and model metrics."""
    try:
        gen = ReportGenerator()
        pdf_bytes = gen.generate_pdf_bytes(limit=500)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=threat_report.pdf"},
        )
    except Exception as exc:
        logger.error("PDF generation error: %s", exc)
        from fastapi import HTTPException, status
        raise HTTPException(status_code=500, detail=str(exc))
