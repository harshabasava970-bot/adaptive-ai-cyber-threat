"""
report_generator.py — Report Generator (Module 13)
====================================================
Adaptive AI for Cyber Threat Detection

Generates PDF and CSV threat reports with full audit trail.
PDF reports use ReportLab; CSV exports use pandas.

IEEE 29148 FR: FR-DSH-003 (Downloadable Reports)

Author: B.Tech Capstone Project
"""

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

from src.core.constants import PROJECT_ROOT, REPORT_DATETIME_FORMAT
from src.core.exceptions import ReportGenerationError
from src.core.logger import get_logger
from src.database.repository import ThreatRepository

logger = get_logger(__name__)

REPORTS_DIR = PROJECT_ROOT / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportGenerator:
    """Generates PDF and CSV threat detection reports.

    Usage:
        gen = ReportGenerator()
        csv_path = gen.generate_csv(limit=500)
        pdf_path = gen.generate_pdf(limit=500)

    Attributes:
        repo: ThreatRepository for fetching detection records.
        reports_dir: Directory where reports are saved.
    """

    def __init__(self, repo: Optional[ThreatRepository] = None) -> None:
        """Initialise with optional repository override (for testing).

        Args:
            repo: ThreatRepository instance. Creates default if None.
        """
        self.repo = repo or ThreatRepository()
        self.reports_dir = REPORTS_DIR

    # ------------------------------------------------------------------
    # CSV Report
    # ------------------------------------------------------------------

    def generate_csv(self, limit: int = 1000) -> Path:
        """Export recent threat detections to a CSV file.

        Args:
            limit: Maximum number of records to include.

        Returns:
            Path to the generated CSV file.

        Raises:
            ReportGenerationError: If export fails.
        """
        try:
            records = self.repo.get_recent(limit=limit)
            if not records:
                logger.warning("No records found for CSV export.")
                records = []

            timestamp = datetime.utcnow().strftime(REPORT_DATETIME_FORMAT)
            filename = f"threat_report_{timestamp}.csv"
            out_path = self.reports_dir / filename

            df = pd.DataFrame(records)
            df.to_csv(out_path, index=False)
            logger.info("CSV report generated: %s (%d records)", out_path, len(records))
            return out_path

        except Exception as exc:
            raise ReportGenerationError("csv", str(exc)) from exc

    def generate_csv_bytes(self, limit: int = 1000) -> bytes:
        """Generate CSV as bytes for streaming API download.

        Args:
            limit: Maximum number of records to include.

        Returns:
            CSV content as UTF-8 encoded bytes.
        """
        records = self.repo.get_recent(limit=limit)
        df = pd.DataFrame(records) if records else pd.DataFrame()
        return df.to_csv(index=False).encode("utf-8")

    # ------------------------------------------------------------------
    # PDF Report
    # ------------------------------------------------------------------

    def generate_pdf(self, limit: int = 500) -> Path:
        """Generate a formatted PDF threat report using ReportLab.

        Args:
            limit: Maximum number of records to include.

        Returns:
            Path to the generated PDF file.

        Raises:
            ReportGenerationError: If PDF generation fails.
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
            )

            records = self.repo.get_recent(limit=limit)
            metrics  = self.repo.get_model_metrics()
            counts   = self.repo.get_threat_counts()
            total    = self.repo.get_total_count()

            timestamp = datetime.utcnow().strftime(REPORT_DATETIME_FORMAT)
            filename = f"threat_report_{timestamp}.pdf"
            out_path = self.reports_dir / filename

            doc = SimpleDocTemplate(
                str(out_path),
                pagesize=A4,
                leftMargin=2*cm, rightMargin=2*cm,
                topMargin=2*cm, bottomMargin=2*cm,
            )

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "Title",
                parent=styles["Title"],
                fontSize=18, textColor=colors.HexColor("#1a1a2e"),
                spaceAfter=12,
            )
            heading_style = ParagraphStyle(
                "Heading",
                parent=styles["Heading2"],
                fontSize=13, textColor=colors.HexColor("#16213e"),
                spaceBefore=16, spaceAfter=6,
            )
            body_style = styles["BodyText"]
            body_style.fontSize = 9

            story = []

            # Title
            story.append(Paragraph(
                "Adaptive AI for Cyber Threat Detection", title_style
            ))
            story.append(Paragraph(
                f"Threat Analysis Report | Generated: "
                f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                body_style,
            ))
            story.append(Spacer(1, 0.4*cm))

            # Summary statistics
            story.append(Paragraph("Executive Summary", heading_style))
            summary_data = [
                ["Metric", "Value"],
                ["Total Detections", str(total)],
                ["Phishing Emails", str(counts.get("phishing_email", 0))],
                ["Malicious URLs",  str(counts.get("malicious_url", 0))],
                ["Suspicious Logins", str(counts.get("suspicious_login", 0))],
                ["Network Anomalies", str(counts.get("network_anomaly", 0))],
                ["Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
            ]
            summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
            summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f0f0f0"), colors.white]),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
                ("ALIGN",      (0, 0), (-1, -1), "LEFT"),
                ("PADDING",    (0, 0), (-1, -1), 6),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.4*cm))

            # Model Performance Table
            if metrics:
                story.append(Paragraph("Model Performance Metrics", heading_style))
                metric_headers = [
                    "Model", "Algorithm", "Accuracy", "Precision",
                    "Recall", "F1 Score", "ROC-AUC",
                ]
                metric_rows = [metric_headers]
                for m in metrics[:10]:
                    metric_rows.append([
                        m.get("model_name", "")[:30],
                        m.get("algorithm", ""),
                        f"{m.get('accuracy', 0):.4f}",
                        f"{m.get('precision', 0):.4f}",
                        f"{m.get('recall', 0):.4f}",
                        f"{m.get('f1_score', 0):.4f}",
                        f"{m.get('roc_auc', 0):.4f}",
                    ])
                col_w = [5*cm, 3.5*cm, 2*cm, 2*cm, 2*cm, 2*cm, 2*cm]
                metrics_table = Table(metric_rows, colWidths=col_w)
                metrics_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#e8f4fd"), colors.white]),
                    ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
                    ("ALIGN",      (2, 1), (-1, -1), "CENTER"),
                    ("PADDING",    (0, 0), (-1, -1), 5),
                ]))
                story.append(metrics_table)
                story.append(Spacer(1, 0.4*cm))

            # Recent Detections Table
            if records:
                story.append(Paragraph(
                    f"Recent Threat Detections (last {min(len(records), 20)})",
                    heading_style,
                ))
                det_headers = [
                    "Timestamp", "Threat Type", "Risk Level",
                    "Risk Score", "Is Threat",
                ]
                det_rows = [det_headers]
                for r in records[:20]:
                    ts = r.get("timestamp", "")[:19] if r.get("timestamp") else ""
                    det_rows.append([
                        ts,
                        str(r.get("threat_type", ""))[:25],
                        str(r.get("risk_level", "")).upper(),
                        f"{r.get('risk_score', 0):.3f}",
                        "YES" if r.get("is_threat") else "NO",
                    ])
                col_w2 = [4.5*cm, 5*cm, 3*cm, 2.5*cm, 2.5*cm]
                det_table = Table(det_rows, colWidths=col_w2)
                det_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e94560")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#fff5f5"), colors.white]),
                    ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
                    ("PADDING",    (0, 0), (-1, -1), 5),
                ]))
                story.append(det_table)

            # Footer
            story.append(Spacer(1, 0.8*cm))
            story.append(Paragraph(
                "Generated by Adaptive AI for Cyber Threat Detection Platform | "
                "B.Tech Capstone Project 2025-2026 | IEEE 29148 Compliant",
                ParagraphStyle("footer", fontSize=7,
                               textColor=colors.grey, alignment=1),
            ))

            doc.build(story)
            logger.info("PDF report generated: %s", out_path)
            return out_path

        except ImportError:
            raise ReportGenerationError(
                "pdf",
                "reportlab not installed. Run: pip install reportlab",
            )
        except Exception as exc:
            raise ReportGenerationError("pdf", str(exc)) from exc

    def generate_pdf_bytes(self, limit: int = 500) -> bytes:
        """Generate PDF and return as bytes for streaming API download.

        Args:
            limit: Maximum records to include.

        Returns:
            PDF content as bytes.
        """
        path = self.generate_pdf(limit=limit)
        with open(path, "rb") as f:
            data = f.read()
        path.unlink(missing_ok=True)  # Clean up temp file
        return data
