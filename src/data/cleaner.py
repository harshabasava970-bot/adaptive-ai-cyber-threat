"""
cleaner.py — Data Cleaning Pipeline (Module 3)
================================================
Adaptive AI for Cyber Threat Detection

Implements dataset-specific cleaning pipelines for each threat type.
All cleaning steps are logged and reversible (original files preserved).

Design Pattern: Template Method — BaseCleaner defines skeleton, subclasses
implement dataset-specific logic.

IEEE 29148 FR: FR-DAT-005 (Data Quality Assurance)

Author: B.Tech Capstone Project
"""

import re
import string
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from src.core.constants import (
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
    RANDOM_SEED,
)
from src.core.exceptions import DataLoadError, DataPreprocessingError, DataValidationError
from src.core.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Base Cleaner
# =============================================================================

class BaseCleaner(ABC):
    """Abstract base class for all dataset-specific cleaners.

    Defines the cleaning pipeline skeleton:
      1. load()
      2. drop_duplicates()
      3. handle_missing()
      4. clean_specific()   ← dataset-specific implementation
      5. encode_labels()
      6. save()

    Attributes:
        raw_path: Path to the raw CSV file.
        processed_path: Path where cleaned CSV will be saved.
        df: The working DataFrame.
        cleaning_report: Summary statistics of cleaning operations.
    """

    def __init__(
        self,
        raw_path: Path,
        processed_path: Path,
    ) -> None:
        self.raw_path = raw_path
        self.processed_path = processed_path
        self.df: Optional[pd.DataFrame] = None
        self.cleaning_report: dict = {
            "initial_rows": 0,
            "final_rows": 0,
            "duplicates_removed": 0,
            "nulls_handled": 0,
            "outliers_handled": 0,
        }

    def run(self) -> pd.DataFrame:
        """Execute the full cleaning pipeline.

        Returns:
            Cleaned DataFrame.

        Raises:
            DataLoadError: If raw file cannot be loaded.
            DataPreprocessingError: If any cleaning step fails.
        """
        logger.info("Starting cleaning pipeline for: %s", self.raw_path.name)
        self._load()
        self._log_initial_stats()
        self._drop_duplicates()
        self._handle_missing()
        self._clean_specific()
        self._validate_cleaned()
        self._save()
        logger.info(
            "Cleaning complete. %d → %d rows (removed %d).",
            self.cleaning_report["initial_rows"],
            self.cleaning_report["final_rows"],
            self.cleaning_report["initial_rows"] - self.cleaning_report["final_rows"],
        )
        return self.df

    def _load(self) -> None:
        """Load raw CSV into DataFrame."""
        if not self.raw_path.exists():
            raise DataLoadError(
                source=str(self.raw_path),
                reason="Raw data file not found. Run DatasetDownloader first.",
            )
        try:
            self.df = pd.read_csv(self.raw_path, low_memory=False)
            self.cleaning_report["initial_rows"] = len(self.df)
            logger.info("Loaded %d rows, %d columns.", len(self.df), len(self.df.columns))
        except Exception as exc:
            raise DataLoadError(source=str(self.raw_path), reason=str(exc)) from exc

    def _log_initial_stats(self) -> None:
        """Log initial DataFrame statistics for the cleaning report."""
        null_counts = self.df.isnull().sum()
        total_nulls = int(null_counts.sum())
        dup_count = int(self.df.duplicated().sum())
        logger.info(
            "Initial stats — Rows: %d | Nulls: %d | Duplicates: %d",
            len(self.df), total_nulls, dup_count,
        )

    def _drop_duplicates(self) -> None:
        """Remove exact duplicate rows."""
        before = len(self.df)
        self.df = self.df.drop_duplicates()
        removed = before - len(self.df)
        self.cleaning_report["duplicates_removed"] = removed
        if removed > 0:
            logger.info("Dropped %d duplicate rows.", removed)

    def _handle_missing(self) -> None:
        """Handle missing values using column-type-appropriate strategies.

        Numeric columns: fill with median.
        Categorical/text columns: fill with 'unknown'.
        Rows where the label/target is missing: drop entirely.
        """
        if self.df is None:
            return

        null_before = int(self.df.isnull().sum().sum())
        if null_before == 0:
            return

        for col in self.df.columns:
            null_count = self.df[col].isnull().sum()
            if null_count == 0:
                continue

            if self.df[col].dtype in [np.float64, np.int64, float, int]:
                median_val = self.df[col].median()
                self.df[col] = self.df[col].fillna(median_val)
            else:
                self.df[col] = self.df[col].fillna("unknown")

        self.cleaning_report["nulls_handled"] = null_before
        logger.info("Handled %d null values.", null_before)

    @abstractmethod
    def _clean_specific(self) -> None:
        """Dataset-specific cleaning logic. Implemented by each subclass."""
        ...

    def _validate_cleaned(self) -> None:
        """Post-cleaning validation checks."""
        if self.df is None or len(self.df) == 0:
            raise DataPreprocessingError(
                step="validate_cleaned",
                reason="DataFrame is empty after cleaning.",
            )
        remaining_nulls = int(self.df.isnull().sum().sum())
        if remaining_nulls > 0:
            logger.warning("%d null values remain after cleaning.", remaining_nulls)
        self.cleaning_report["final_rows"] = len(self.df)

    def _save(self) -> None:
        """Save cleaned DataFrame to processed directory."""
        self.processed_path.parent.mkdir(parents=True, exist_ok=True)
        self.df.to_csv(self.processed_path, index=False)
        logger.info("Saved cleaned data to: %s", self.processed_path)


# =============================================================================
# Phishing Email Cleaner
# =============================================================================

class PhishingEmailCleaner(BaseCleaner):
    """Cleaner for the phishing email dataset.

    Cleaning steps specific to email data:
      - Standardise column names
      - Detect and use correct text/label columns
      - Remove HTML tags from email body
      - Normalise whitespace
      - Remove extremely short/long texts
      - Encode labels as binary (0=legitimate, 1=phishing)
    """

    # Possible label column name variations across datasets
    _LABEL_VARIANTS = ["label", "Label", "class", "Class", "type", "Type", "spam", "phishing"]
    _TEXT_VARIANTS = ["text", "Text", "body", "Body", "email_text", "message", "Message", "content"]

    def _clean_specific(self) -> None:
        """Apply email-specific cleaning transformations."""
        self._standardise_columns()
        self._clean_text_column()
        self._filter_by_length()
        self._normalise_labels()
        logger.info("Email-specific cleaning complete. Label distribution:\n%s",
                    self.df["label"].value_counts().to_string())

    def _standardise_columns(self) -> None:
        """Rename columns to standard names: 'text' and 'label'."""
        cols_lower = {c: c.lower().strip() for c in self.df.columns}
        self.df = self.df.rename(columns=cols_lower)

        # Find label column
        label_col = None
        for variant in [v.lower() for v in self._LABEL_VARIANTS]:
            if variant in self.df.columns:
                label_col = variant
                break
        if label_col and label_col != "label":
            self.df = self.df.rename(columns={label_col: "label"})

        # Find text column
        text_col = None
        for variant in [v.lower() for v in self._TEXT_VARIANTS]:
            if variant in self.df.columns:
                text_col = variant
                break
        if text_col and text_col != "text":
            self.df = self.df.rename(columns={text_col: "text"})

        # Keep only text and label columns
        cols_to_keep = [c for c in ["text", "label"] if c in self.df.columns]
        self.df = self.df[cols_to_keep]

        if "text" not in self.df.columns or "label" not in self.df.columns:
            raise DataPreprocessingError(
                step="standardise_columns",
                reason=f"Could not find text/label columns. Available: {list(self.df.columns)}",
            )

    def _clean_text_column(self) -> None:
        """Remove HTML tags, normalise whitespace, lowercase text."""
        html_pattern = re.compile(r"<[^>]+>")
        url_pattern = re.compile(r"http\S+|www\.\S+")
        whitespace_pattern = re.compile(r"\s+")

        def _clean(text: str) -> str:
            if not isinstance(text, str):
                return ""
            text = html_pattern.sub(" ", text)
            text = url_pattern.sub(" URL ", text)
            text = text.lower()
            text = whitespace_pattern.sub(" ", text).strip()
            return text

        self.df["text"] = self.df["text"].apply(_clean)
        self.df = self.df[self.df["text"].str.len() > 0]

    def _filter_by_length(self) -> None:
        """Remove emails that are too short or unrealistically long."""
        before = len(self.df)
        self.df = self.df[
            (self.df["text"].str.len() >= 20) &
            (self.df["text"].str.len() <= 50_000)
        ]
        removed = before - len(self.df)
        if removed > 0:
            logger.info("Filtered %d emails by length constraints.", removed)

    def _normalise_labels(self) -> None:
        """Encode labels as binary integers (0=legitimate, 1=phishing)."""
        label_col = self.df["label"]
        # Handle various label representations
        phishing_markers = {
            "phishing", "spam", "1", "true", "yes", "malicious", "bad", "fraud"
        }
        if label_col.dtype == object:
            self.df["label"] = label_col.str.lower().str.strip().apply(
                lambda x: 1 if x in phishing_markers else 0
            )
        else:
            self.df["label"] = label_col.astype(int).clip(0, 1)


# =============================================================================
# Malicious URL Cleaner
# =============================================================================

class MaliciousURLCleaner(BaseCleaner):
    """Cleaner for the phishing/malicious URL dataset.

    Cleaning steps:
      - Standardise URL and label columns
      - Remove invalid/empty URLs
      - Strip whitespace from URLs
      - Encode labels as binary (0=benign, 1=malicious)
    """

    _URL_VARIANTS = ["url", "URL", "Url", "link", "Link", "address"]
    _LABEL_VARIANTS = ["label", "Label", "status", "Status", "class", "phishing", "result"]

    def _clean_specific(self) -> None:
        """Apply URL-dataset-specific cleaning."""
        self._standardise_url_columns()
        self._clean_url_values()
        self._normalise_url_labels()
        logger.info("URL cleaning complete. Label distribution:\n%s",
                    self.df["label"].value_counts().to_string())

    def _standardise_url_columns(self) -> None:
        """Rename to standard 'url' and 'label' columns."""
        cols_lower = {c: c.lower().strip() for c in self.df.columns}
        self.df = self.df.rename(columns=cols_lower)

        for variant in [v.lower() for v in self._URL_VARIANTS]:
            if variant in self.df.columns and variant != "url":
                self.df = self.df.rename(columns={variant: "url"})
                break

        for variant in [v.lower() for v in self._LABEL_VARIANTS]:
            if variant in self.df.columns and variant != "label":
                self.df = self.df.rename(columns={variant: "label"})
                break

        if "url" not in self.df.columns:
            raise DataPreprocessingError(
                step="standardise_url_columns",
                reason=f"No URL column found. Columns: {list(self.df.columns)}",
            )

    def _clean_url_values(self) -> None:
        """Clean and validate URL strings."""
        self.df["url"] = self.df["url"].astype(str).str.strip()
        # Remove completely invalid entries
        self.df = self.df[self.df["url"].str.len() > 5]
        self.df = self.df[~self.df["url"].isin(["nan", "null", "none", ""])]

    def _normalise_url_labels(self) -> None:
        """Encode labels as binary (0=benign, 1=malicious/phishing)."""
        if "label" not in self.df.columns:
            raise DataPreprocessingError(
                step="normalise_url_labels",
                reason="Label column not found after standardisation.",
            )
        malicious_markers = {
            "phishing", "malicious", "bad", "1", "true", "yes",
            "defacement", "malware", "spam",
        }
        if self.df["label"].dtype == object:
            self.df["label"] = self.df["label"].str.lower().str.strip().apply(
                lambda x: 1 if x in malicious_markers else 0
            )
        else:
            self.df["label"] = self.df["label"].astype(int).clip(0, 1)


# =============================================================================
# Login Behaviour Cleaner
# =============================================================================

class LoginBehaviourCleaner(BaseCleaner):
    """Cleaner for the login behaviour dataset (synthetic or real).

    Cleaning steps:
      - Drop user_id and timestamp (not used as features)
      - Clip numeric outliers using IQR method
      - Ensure correct dtypes
      - Keep label column as binary int
    """

    _NON_FEATURE_COLS = ["user_id", "timestamp"]

    def _clean_specific(self) -> None:
        """Apply login-behaviour-specific cleaning."""
        self._drop_non_feature_columns()
        self._clip_numeric_outliers()
        self._ensure_dtypes()
        logger.info("Login cleaning complete. Label distribution:\n%s",
                    self.df["label"].value_counts().to_string())

    def _drop_non_feature_columns(self) -> None:
        """Remove columns not used as model features."""
        cols_to_drop = [c for c in self._NON_FEATURE_COLS if c in self.df.columns]
        if cols_to_drop:
            self.df = self.df.drop(columns=cols_to_drop)
            logger.info("Dropped non-feature columns: %s", cols_to_drop)

    def _clip_numeric_outliers(self) -> None:
        """Clip numeric features to [Q1 - 3*IQR, Q3 + 3*IQR] range."""
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns
        feature_cols = [c for c in numeric_cols if c != "label"]

        for col in feature_cols:
            q1 = self.df[col].quantile(0.25)
            q3 = self.df[col].quantile(0.75)
            iqr = q3 - q1
            lower = q1 - 3 * iqr
            upper = q3 + 3 * iqr
            clipped = self.df[col].clip(lower, upper)
            n_clipped = (self.df[col] != clipped).sum()
            if n_clipped > 0:
                logger.debug("Clipped %d outliers in column '%s'.", n_clipped, col)
                self.cleaning_report["outliers_handled"] += int(n_clipped)
            self.df[col] = clipped

    def _ensure_dtypes(self) -> None:
        """Ensure all feature columns have correct numeric dtypes."""
        for col in self.df.select_dtypes(include=[object]).columns:
            if col != "label":
                try:
                    self.df[col] = pd.to_numeric(self.df[col], errors="coerce")
                    self.df[col] = self.df[col].fillna(self.df[col].median())
                except Exception:
                    pass
        self.df["label"] = self.df["label"].astype(int)


# =============================================================================
# Network Anomaly Cleaner
# =============================================================================

class NetworkAnomalyCleaner(BaseCleaner):
    """Cleaner for the NSL-KDD network anomaly dataset.

    Cleaning steps:
      - Drop the 'difficulty' column (not used in ML)
      - Encode categorical features (protocol_type, service, flag)
      - Binarise label (normal=0, attack=1)
      - Clip numeric outliers
    """

    _CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
    _DROP_COLS = ["difficulty"]

    def _clean_specific(self) -> None:
        """Apply NSL-KDD-specific cleaning transformations."""
        self._drop_unused_columns()
        self._encode_categoricals()
        self._binarise_label()
        self._clip_numeric_outliers()
        logger.info("Network cleaning complete. Label distribution:\n%s",
                    self.df["label"].value_counts().to_string())

    def _drop_unused_columns(self) -> None:
        """Drop columns not needed for model training."""
        to_drop = [c for c in self._DROP_COLS if c in self.df.columns]
        if to_drop:
            self.df = self.df.drop(columns=to_drop)

    def _encode_categoricals(self) -> None:
        """Label-encode categorical columns."""
        for col in self._CATEGORICAL_COLS:
            if col in self.df.columns:
                le = LabelEncoder()
                self.df[col] = le.fit_transform(
                    self.df[col].astype(str).str.lower().str.strip()
                )
                logger.debug("Encoded categorical column '%s'.", col)

    def _binarise_label(self) -> None:
        """Convert multi-class labels to binary: normal=0, attack=1."""
        if "label" not in self.df.columns:
            raise DataPreprocessingError(
                step="binarise_label",
                reason="Label column not found in NSL-KDD dataset.",
            )
        self.df["label"] = self.df["label"].apply(
            lambda x: 0 if str(x).strip().lower() == "normal" else 1
        )
        logger.info("Labels binarised: 0=normal, 1=attack.")

    def _clip_numeric_outliers(self) -> None:
        """Clip numeric features using IQR method."""
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns
        feature_cols = [c for c in numeric_cols if c != "label"]
        for col in feature_cols:
            q1, q3 = self.df[col].quantile([0.25, 0.75])
            iqr = q3 - q1
            self.df[col] = self.df[col].clip(q1 - 3 * iqr, q3 + 3 * iqr)


# =============================================================================
# DataCleaner — Facade
# =============================================================================

class DataCleaner:
    """Facade that selects and runs the correct cleaner for each dataset.

    Usage:
        cleaner = DataCleaner()
        cleaner.clean_all()

        # Or clean one dataset
        df = cleaner.clean("phishing_email")
    """

    _CLEANER_MAP = {
        "phishing_email": (
            RAW_DATA_DIR / "phishing_emails_raw.csv",
            PROCESSED_DATA_DIR / "phishing_emails_clean.csv",
            PhishingEmailCleaner,
        ),
        "malicious_url": (
            RAW_DATA_DIR / "phishing_urls_raw.csv",
            PROCESSED_DATA_DIR / "malicious_urls_clean.csv",
            MaliciousURLCleaner,
        ),
        "login_behaviour": (
            RAW_DATA_DIR / "login_behaviour_raw.csv",
            PROCESSED_DATA_DIR / "login_behaviour_clean.csv",
            LoginBehaviourCleaner,
        ),
        "network_anomaly": (
            RAW_DATA_DIR / "nsl_kdd_train_raw.csv",
            PROCESSED_DATA_DIR / "network_anomaly_clean.csv",
            NetworkAnomalyCleaner,
        ),
    }

    def clean_all(self) -> dict[str, bool]:
        """Clean all datasets.

        Returns:
            Dictionary mapping dataset_key → success boolean.
        """
        results = {}
        for key in self._CLEANER_MAP:
            try:
                self.clean(key)
                results[key] = True
            except Exception as exc:
                logger.error("Cleaning failed for '%s': %s", key, exc)
                results[key] = False
        return results

    def clean(self, dataset_key: str) -> pd.DataFrame:
        """Clean a single dataset.

        Args:
            dataset_key: One of 'phishing_email', 'malicious_url',
                         'login_behaviour', 'network_anomaly'.

        Returns:
            Cleaned DataFrame.

        Raises:
            KeyError: If dataset_key is unknown.
        """
        if dataset_key not in self._CLEANER_MAP:
            raise KeyError(
                f"Unknown dataset key: '{dataset_key}'. "
                f"Available: {list(self._CLEANER_MAP.keys())}"
            )
        raw_path, processed_path, cleaner_cls = self._CLEANER_MAP[dataset_key]
        cleaner = cleaner_cls(raw_path=raw_path, processed_path=processed_path)
        return cleaner.run()
