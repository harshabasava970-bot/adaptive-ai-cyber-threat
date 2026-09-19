"""
report_generator.py — Report Generator (Module 13)
====================================================
Adaptive Explainable Multi-Source Cyber Threat Detection Framework
using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME

Generates PDF and CSV threat reports with full audit trail.
PDF reports use ReportLab; CSV exports use pandas.

Counting methodology (Fix #1 — consistent across all outputs):
  • Total Scans        = every detection event, regardless of risk level.
  • Confirmed Threats  = only CRITICAL or HIGH risk detections.
  • Category Counts    = per-type breakdown of confirmed threats only.
  The PDF clearly labels each section so the reader is never misled.

Is Threat display (Fix #2 — aligned with dashboard status logic):
  The stored ``is_threat`` boolean in the DB was set by the fusion engine
  from a low probability threshold (≥ 0.25). For user-facing reports we
  use ``is_confirmed_threat`` (derived from risk_level: critical/high = YES,
  all others = NO) to match the THREAT/REVIEW/SAFE status shown in the
  Dashboard and Timeline.

Timestamps (Fix #3 — dual UTC / IST in reports):
  All timestamps are stored as UTC-naive datetimes in the database.
  The PDF shows both UTC and IST (+05:30) for every row so the reader
  can locate the event in either timezone without conversion errors.
  No double-conversion: UTC is read once from the DB and IST is computed
  exactly once by adding the fixed +05:30 offset.

Author: B.Tech Capstone Project 2026-2027
"""

import io
from datetime import datetime, timedelta
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

# IST offset — applied exactly once when converting UTC → IST for display.
_IST_OFFSET = timedelta(hours=5, minutes=30)

# Risk levels that represent a confirmed actionable threat (same as dashboard).
_CONFIRMED_RISK_LEVELS = frozenset({"critical", "high"})


def _utc_iso_to_display(ts_iso: str) -> str:
    """Convert a UTC ISO string (from to_dict) to a dual-timezone display string.

    The database stores timestamps as UTC-naive datetimes.  ``to_dict()``
    serialises them with ``isoformat()``, producing strings like
    ``"2026-09-19T12:34:08"`` (no suffix).  This function:
      1. Parses the bare ISO string as UTC (no timezone change).
      2. Adds +05:30 once to get IST.
      3. Returns a two-line string showing both values, clearly labelled.

    Example return value:
        "2026-09-19 18:04:08 IST\n2026-09-19 12:34:08 UTC"

    Args:
        ts_iso: ISO format string from ThreatDetection.to_dict(), e.g.
                "2026-09-19T12:34:08" or "2026-09-19T12:34:08.123456".

    Returns:
        Human-readable dual-timezone string, or the original string on error.
    """
    if not ts_iso:
        return "—"
    try:
        # Truncate to seconds before parsing to avoid microsecond surprises.
        bare = ts_iso[:19].replace("T", " ")
        utc_dt = datetime.strptime(bare, "%Y-%m-%d %H:%M:%S")
        ist_dt = utc_dt + _IST_OFFSET
        return (
            f"{ist_dt.strftime('%Y-%m-%d %H:%M:%S')} IST\n"
            f"{utc_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
    except (ValueError, TypeError):
        return ts_iso[:19] if len(ts_iso) >= 19 else ts_iso


def _format_threat_types(record: dict) -> str:
    """Build a clean, human-readable threat type string from a detection record.

    Prefers the ``active_threats`` JSON list (which holds individual type
    names) over the ``threat_type`` comma-joined string column.  Falls back
    gracefully if neither is present.

    Each type is formatted on its own line so ReportLab can word-wrap it
    within the PDF cell without truncating.

    Args:
        record: Detection dict from ThreatDetection.to_dict().

    Returns:
        Newline-separated human-readable threat types, e.g.
        "Phishing Email\nMalicious URL"
    """
    # Prefer the structured JSON list
    active = record.get("active_threats") or []
    if active:
        return "\n".join(
            t.replace("_", " ").title() for t in active
        )
    # Fall back to the comma-joined string column
    raw = str(record.get("threat_type", "") or "").strip()
    if raw and raw.lower() != "none":
        parts = [p.strip().replace("_", " ").title() for p in raw.split(",") if p.strip()]
        return "\n".join(parts) if parts else "None"
    return "None"


def _is_confirmed_threat_display(record: dict) -> str:
    """Determine the user-facing Is Threat label for a detection record.

    Uses risk_level as the single source of truth — consistent with the
    dashboard THREAT/REVIEW/SAFE status logic.

    Classification:
        CRITICAL or HIGH  → "YES (Confirmed Threat)"
        MEDIUM            → "NO  (Review)"
        LOW or INFO       → "NO  (Safe)"

    Args:
        record: Detection dict from ThreatDetection.to_dict().

    Returns:
        Human-readable Is Threat string with status annotation.
    """
    level = (record.get("risk_level") or "").lower()
    if level == "critical":
        return "YES — Critical"
    if level == "high":
        return "YES — High"
    if level == "medium":
        return "NO  — Review"
    if level == "low":
        return "NO  — Low"
    return "NO  — Info"


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

        The CSV includes both ``is_threat`` (raw fusion-engine boolean) and
        ``is_confirmed_threat`` (risk-level derived, matches dashboard) so
        analysts can audit both values.  The ``scan_time_ist`` column is
        added alongside the raw UTC ``timestamp`` column.

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

            df = _enrich_records_for_export(records)

            timestamp = datetime.utcnow().strftime(REPORT_DATETIME_FORMAT)
            filename = f"threat_report_{timestamp}_IST.csv"
            out_path = self.reports_dir / filename

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
        df = _enrich_records_for_export(records) if records else pd.DataFrame()
        return df.to_csv(index=False).encode("utf-8")

    # ------------------------------------------------------------------
    # PDF Report
    # ------------------------------------------------------------------

    def generate_pdf(self, limit: int = 500) -> Path:
        """Generate a formatted PDF threat report using ReportLab.

        All five consistency fixes are applied here:
          1. Counts — uses get_report_summary() for a single consistent query.
          2. Is Threat — derived from risk_level, not the raw boolean.
          3. Timestamps — both IST and UTC shown, clearly labelled.
          4. Threat Type — full text with word-wrap, no truncation.
          5. Table layout — column widths fit within A4 margins.

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
            metrics = self.repo.get_model_metrics()
            # Fix #1: single consistent summary query — no mixing of
            # get_total_count() + get_threat_counts() which use different filters.
            summary = self.repo.get_report_summary()

            now_utc = datetime.utcnow()
            now_ist = now_utc + _IST_OFFSET
            gen_time = (
                f"{now_ist.strftime('%Y-%m-%d %H:%M:%S')} IST  "
                f"({now_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
            )

            timestamp_str = now_utc.strftime(REPORT_DATETIME_FORMAT)
            filename = f"threat_report_{timestamp_str}.pdf"
            out_path = self.reports_dir / filename

            doc = SimpleDocTemplate(
                str(out_path),
                pagesize=A4,
                leftMargin=2*cm, rightMargin=2*cm,
                topMargin=2*cm, bottomMargin=2*cm,
            )

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "CTitle",
                parent=styles["Title"],
                fontSize=15, textColor=colors.HexColor("#1a1a2e"),
                spaceAfter=10, leading=20,
            )
            heading_style = ParagraphStyle(
                "CHeading",
                parent=styles["Heading2"],
                fontSize=12, textColor=colors.HexColor("#16213e"),
                spaceBefore=14, spaceAfter=5,
            )
            note_style = ParagraphStyle(
                "CNote",
                parent=styles["BodyText"],
                fontSize=7.5, textColor=colors.HexColor("#555555"),
                spaceAfter=4, leftIndent=4,
            )
            body_style = ParagraphStyle(
                "CBody",
                parent=styles["BodyText"],
                fontSize=9,
            )
            # Fix #4: cell style for wrappable table content
            cell_style = ParagraphStyle(
                "CCell",
                parent=styles["BodyText"],
                fontSize=8, leading=10, wordWrap="LTR",
            )

            story = []

            # ── Title ─────────────────────────────────────────────
            story.append(Paragraph(
                "Adaptive Explainable Multi-Source Cyber Threat Detection Framework "
                "using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME",
                title_style,
            ))
            story.append(Paragraph(
                f"Threat Analysis Report  |  Generated: {gen_time}",
                body_style,
            ))
            story.append(Spacer(1, 0.4 * cm))

            # ── Executive Summary ──────────────────────────────────
            # Fix #1: clearly distinguish Total Scans from Confirmed Threats
            # and explain what each category count means.
            story.append(Paragraph("Executive Summary", heading_style))
            story.append(Paragraph(
                "Note: 'Total Scans' counts every detection event at all risk levels. "
                "'Confirmed Threats' counts only CRITICAL and HIGH risk events. "
                "Category counts (phishing, URL, etc.) reflect the threat types present "
                "within those confirmed-threat events only.",
                note_style,
            ))

            summary_data = [
                ["Metric", "Value"],
                ["Total Scans (all risk levels)", str(summary["total_scans"])],
                ["Confirmed Threats (CRITICAL + HIGH)", str(summary["confirmed_threats"])],
                ["— Phishing Emails", str(summary["phishing_emails"])],
                ["— Malicious URLs",  str(summary["malicious_urls"])],
                ["— Suspicious Logins", str(summary["suspicious_logins"])],
                ["— Network Anomalies", str(summary["network_anomalies"])],
                ["Report Generated", gen_time],
            ]
            summary_table = Table(summary_data, colWidths=[9.5 * cm, 7 * cm])
            summary_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                # Indent the category sub-rows visually
                ("LEFTPADDING",   (0, 3), (0, 6), 18),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f0f0f0"), colors.white]),
                ("GRID",          (0, 0), (-1, -1), 0.5, colors.grey),
                ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
                ("PADDING",       (0, 0), (-1, -1), 6),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.4 * cm))

            # ── Model Performance ──────────────────────────────────
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
                col_w_m = [4.5 * cm, 3.0 * cm, 2.0 * cm, 2.0 * cm,
                           2.0 * cm, 2.0 * cm, 1.5 * cm]
                metrics_table = Table(metric_rows, colWidths=col_w_m)
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
                story.append(Spacer(1, 0.4 * cm))

            # ── Recent Detections ──────────────────────────────────
            if records:
                n_shown = min(len(records), 20)
                story.append(Paragraph(
                    f"Recent Threat Detections (last {n_shown})", heading_style,
                ))
                story.append(Paragraph(
                    "Is Threat column is derived from Risk Level: "
                    "CRITICAL/HIGH = YES (Confirmed Threat); "
                    "MEDIUM = NO (Review); LOW/INFO = NO (Safe). "
                    "Timestamps shown as IST (Asia/Kolkata) and UTC.",
                    note_style,
                ))

                # Fix #3 + #4 + #5: use Paragraph objects for wrappable cells,
                # provide both IST and UTC timestamps, full threat type text.
                # Column widths sum to 16.5 cm (within A4 17 cm usable width).
                det_headers = [
                    Paragraph("<b>Timestamp (IST / UTC)</b>", cell_style),
                    Paragraph("<b>Threat Types</b>", cell_style),
                    Paragraph("<b>Risk</b>", cell_style),
                    Paragraph("<b>Score</b>", cell_style),
                    Paragraph("<b>Is Threat</b>", cell_style),
                ]
                det_rows = [det_headers]
                for r in records[:n_shown]:
                    ts_display = _utc_iso_to_display(r.get("timestamp", ""))
                    threat_text = _format_threat_types(r)
                    is_threat_text = _is_confirmed_threat_display(r)
                    risk_level = (r.get("risk_level") or "").upper()
                    risk_score = float(r.get("risk_score") or 0.0)

                    det_rows.append([
                        Paragraph(ts_display, cell_style),
                        Paragraph(threat_text, cell_style),
                        Paragraph(risk_level, cell_style),
                        Paragraph(f"{risk_score:.3f}", cell_style),
                        Paragraph(is_threat_text, cell_style),
                    ])

                # Fix #5: widths sum to 16.5 cm (A4 17 cm usable)
                col_w2 = [4.8 * cm, 4.5 * cm, 2.2 * cm, 2.0 * cm, 3.0 * cm]
                det_table = Table(
                    det_rows,
                    colWidths=col_w2,
                    repeatRows=1,   # repeat header on page breaks
                )
                det_table.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#e94560")),
                    ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",    (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#fff5f5"), colors.white]),
                    ("GRID",        (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN",      (0, 0), (-1, -1), "TOP"),
                    ("PADDING",     (0, 0), (-1, -1), 5),
                    ("WORDWRAP",    (0, 0), (-1, -1), "LTR"),
                ]))
                story.append(det_table)

            # ── Footer ────────────────────────────────────────────
            story.append(Spacer(1, 0.8 * cm))
            story.append(Paragraph(
                "Generated by CyberShield AI — "
                "Adaptive Explainable Multi-Source Cyber Threat Detection Framework | "
                "B.Tech Capstone Project 2026-2027 | "
                "All timestamps stored as UTC; displayed as IST (Asia/Kolkata, +05:30) "
                "and UTC. Designed with requirements engineering, software testing, "
                "and explainability principles.",
                ParagraphStyle(
                    "CFooter", fontSize=7,
                    textColor=colors.grey, alignment=1,
                ),
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _enrich_records_for_export(records: list[dict]) -> pd.DataFrame:
    """Add derived columns to a list of detection dicts before CSV export.

    Adds:
      • ``scan_time_ist``      — IST string, e.g. "2026-09-19 18:04:08 IST"
      • ``scan_time_utc``      — UTC string, e.g. "2026-09-19 12:34:08 UTC"
      • ``is_confirmed_threat``— bool derived from risk_level (critical/high)
      • ``threat_types_clean`` — human-readable threat type list
      • ``detection_status``   — THREAT / REVIEW / SAFE label

    The original ``timestamp`` and ``is_threat`` columns are preserved for
    audit purposes.

    Args:
        records: List of dicts from ThreatDetection.to_dict().

    Returns:
        Enriched pandas DataFrame.
    """
    df = pd.DataFrame(records)
    if df.empty:
        return df

    # Fix #3: dual timezone columns
    def _ts_ist(ts: str) -> str:
        if not ts:
            return ""
        try:
            bare = str(ts)[:19].replace("T", " ")
            utc = datetime.strptime(bare, "%Y-%m-%d %H:%M:%S")
            return (utc + _IST_OFFSET).strftime("%Y-%m-%d %H:%M:%S IST")
        except (ValueError, TypeError):
            return str(ts)[:19]

    def _ts_utc(ts: str) -> str:
        if not ts:
            return ""
        try:
            bare = str(ts)[:19].replace("T", " ")
            return bare + " UTC"
        except (ValueError, TypeError):
            return str(ts)[:19]

    df["scan_time_ist"] = df["timestamp"].apply(_ts_ist)
    df["scan_time_utc"] = df["timestamp"].apply(_ts_utc)

    # Fix #2: is_confirmed_threat from risk_level
    def _confirmed(row: pd.Series) -> bool:
        return (str(row.get("risk_level") or "")).lower() in _CONFIRMED_RISK_LEVELS

    df["is_confirmed_threat"] = df.apply(_confirmed, axis=1)

    # Fix #2: human-readable status label
    def _status(row: pd.Series) -> str:
        lvl = (str(row.get("risk_level") or "")).lower()
        if lvl in ("critical", "high"):
            return "THREAT"
        if lvl == "medium":
            return "REVIEW"
        return "SAFE"

    df["detection_status"] = df.apply(_status, axis=1)

    # Fix #4: clean threat type text
    df["threat_types_clean"] = df.apply(
        lambda row: _format_threat_types(row.to_dict()), axis=1
    )

    # Reorder: put new derived columns after risk_level
    cols = list(df.columns)
    for extra in ["scan_time_ist", "scan_time_utc",
                  "is_confirmed_threat", "detection_status",
                  "threat_types_clean"]:
        if extra in cols:
            cols.remove(extra)
    # Insert after risk_level if present, else append
    insert_at = cols.index("risk_level") + 1 if "risk_level" in cols else len(cols)
    for i, extra in enumerate(["scan_time_ist", "scan_time_utc",
                                "is_confirmed_threat", "detection_status",
                                "threat_types_clean"]):
        cols.insert(insert_at + i, extra)
    return df[cols]
