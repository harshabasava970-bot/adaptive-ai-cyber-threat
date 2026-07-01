"""
feature_engineer.py — Feature Engineering (Module 5)
======================================================
Adaptive AI for Cyber Threat Detection

Extracts domain-specific features from raw inputs for each threat type.

Design Pattern: Strategy — each threat type has its own FeatureExtractor.
All extractors share the BaseFeatureExtractor interface.

Features extracted:
  Phishing Email  : TF-IDF bag-of-words + statistical text features
  Malicious URL   : Lexical, host-based, and entropy-based URL features
  Login Behaviour : Behavioural + temporal features (already numeric)
  Network Anomaly : Statistical + rate-based features (from NSL-KDD)

IEEE 29148 FR: FR-DAT-006 (Feature Engineering)

Author: B.Tech Capstone Project
"""

import math
import re
import string
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.feature_selection import SelectKBest, mutual_info_classif, chi2
import joblib

from src.core.constants import (
    PROCESSED_DATA_DIR,
    MODELS_DIR,
    URL_SUSPICIOUS_KEYWORDS,
    RANDOM_SEED,
)
from src.core.exceptions import DataPreprocessingError
from src.core.logger import get_logger

logger = get_logger(__name__)

# Directory for saving fitted transformers (scaler, vectoriser, selector)
TRANSFORMERS_DIR = MODELS_DIR / "transformers"
TRANSFORMERS_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Base Feature Extractor
# =============================================================================

class BaseFeatureExtractor(ABC):
    """Abstract base for all feature extraction strategies.

    Attributes:
        is_fitted: Whether the extractor has been fitted on training data.
    """

    def __init__(self) -> None:
        self.is_fitted: bool = False

    @abstractmethod
    def fit(self, df: pd.DataFrame) -> "BaseFeatureExtractor":
        """Fit transformer(s) on training data.

        Args:
            df: Training DataFrame with raw features and 'label' column.

        Returns:
            Self for method chaining.
        """
        ...

    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply fitted transformations to new data.

        Args:
            df: DataFrame with raw features (no label required).

        Returns:
            DataFrame with engineered features.
        """
        ...

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit on df and then transform it.

        Args:
            df: Training DataFrame.

        Returns:
            Transformed DataFrame.
        """
        return self.fit(df).transform(df)

    def save(self, name: str) -> None:
        """Persist fitted transformer to disk.

        Args:
            name: Identifier for the saved artifact (no extension needed).
        """
        path = TRANSFORMERS_DIR / f"{name}.joblib"
        joblib.dump(self, path)
        logger.info("Transformer saved: %s", path)

    @classmethod
    def load(cls, name: str) -> "BaseFeatureExtractor":
        """Load a previously saved transformer.

        Args:
            name: Identifier used when saving.

        Returns:
            Loaded transformer instance.
        """
        path = TRANSFORMERS_DIR / f"{name}.joblib"
        if not path.exists():
            raise FileNotFoundError(f"Transformer not found: {path}")
        extractor = joblib.load(path)
        logger.info("Transformer loaded: %s", path)
        return extractor


# =============================================================================
# URL Feature Extractor
# =============================================================================

class URLFeatureExtractor(BaseFeatureExtractor):
    """Extracts 24 lexical and structural features from URL strings.

    Features are entirely computed from the URL string itself —
    no HTTP request is made. This enables fast, offline inference.

    Feature categories:
      - Length-based: url_length, domain_length, path_length, etc.
      - Entropy-based: url_entropy (Shannon entropy)
      - Keyword-based: has_suspicious_keyword, keyword_count
      - Structure-based: num_dots, num_hyphens, num_at, num_subdomains
      - Encoding: has_ip_address, has_port, uses_https
      - TLD: is_common_tld, tld_length
    """

    _COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co", "uk", "us"}
    _IP_PATTERN = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )

    def fit(self, df: pd.DataFrame) -> "URLFeatureExtractor":
        """No fitting required for rule-based URL features."""
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract URL features for every row in df.

        Args:
            df: DataFrame with a 'url' column.

        Returns:
            DataFrame of numeric URL features.
        """
        if "url" not in df.columns:
            raise DataPreprocessingError(
                step="url_transform", reason="'url' column not found."
            )
        feature_rows = [self._extract_single(url) for url in df["url"]]
        features_df = pd.DataFrame(feature_rows)
        if "label" in df.columns:
            features_df["label"] = df["label"].values
        logger.debug(
            "URL features extracted. Shape: %s | Columns: %s",
            features_df.shape, list(features_df.columns),
        )
        return features_df

    def _extract_single(self, url: str) -> dict[str, Any]:
        """Extract all features from a single URL string.

        Args:
            url: Raw URL string.

        Returns:
            Dictionary of feature_name → numeric value.
        """
        url = str(url).strip()
        try:
            parsed = urlparse(url if "://" in url else "http://" + url)
            extracted = tldextract.extract(url)
        except Exception:
            return self._zero_features()

        domain = parsed.netloc or ""
        path = parsed.path or ""
        query = parsed.query or ""
        subdomain = extracted.subdomain or ""
        tld = extracted.suffix or ""

        full_domain_no_scheme = url.replace("https://", "").replace("http://", "")

        return {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "query_length": len(query),
            "subdomain_length": len(subdomain),
            "tld_length": len(tld),
            # Count features
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_underscores": url.count("_"),
            "num_slashes": url.count("/"),
            "num_at": url.count("@"),
            "num_question_marks": url.count("?"),
            "num_ampersands": url.count("&"),
            "num_equals": url.count("="),
            "num_percent": url.count("%"),
            "num_digits": sum(c.isdigit() for c in url),
            "num_subdomains": len(subdomain.split(".")) if subdomain else 0,
            # Boolean features (0/1)
            "uses_https": int(url.startswith("https")),
            "has_ip_address": int(bool(self._IP_PATTERN.search(domain))),
            "has_port": int(":" in domain and not domain.startswith("[")),
            "is_common_tld": int(tld.lower() in self._COMMON_TLDS),
            # Entropy-based features
            "url_entropy": self._shannon_entropy(full_domain_no_scheme),
            "domain_entropy": self._shannon_entropy(domain),
            # Keyword features
            "has_suspicious_keyword": int(
                any(kw in url.lower() for kw in URL_SUSPICIOUS_KEYWORDS)
            ),
            "suspicious_keyword_count": sum(
                1 for kw in URL_SUSPICIOUS_KEYWORDS if kw in url.lower()
            ),
        }

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of a string.

        High entropy in a domain name suggests random/generated strings,
        which is a strong indicator of malicious domains.

        Args:
            text: Input string.

        Returns:
            Shannon entropy value in bits.
        """
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(text)
        return -sum(
            (count / total) * math.log2(count / total)
            for count in freq.values()
        )

    @staticmethod
    def _zero_features() -> dict[str, Any]:
        """Return zero-valued feature dict for unparseable URLs."""
        return {
            "url_length": 0, "domain_length": 0, "path_length": 0,
            "query_length": 0, "subdomain_length": 0, "tld_length": 0,
            "num_dots": 0, "num_hyphens": 0, "num_underscores": 0,
            "num_slashes": 0, "num_at": 0, "num_question_marks": 0,
            "num_ampersands": 0, "num_equals": 0, "num_percent": 0,
            "num_digits": 0, "num_subdomains": 0, "uses_https": 0,
            "has_ip_address": 0, "has_port": 0, "is_common_tld": 0,
            "url_entropy": 0.0, "domain_entropy": 0.0,
            "has_suspicious_keyword": 0, "suspicious_keyword_count": 0,
        }

    def transform_single(self, url: str) -> np.ndarray:
        """Extract features from a single URL and return as numpy array.

        Used during real-time API inference.

        Args:
            url: Raw URL string.

        Returns:
            1D numpy array of feature values.
        """
        features = self._extract_single(url)
        return np.array(list(features.values()), dtype=np.float32).reshape(1, -1)

    @property
    def feature_names(self) -> list[str]:
        """Return ordered list of feature names (excluding label)."""
        return list(self._zero_features().keys())


# =============================================================================
# Email Feature Extractor (for classical ML baseline)
# =============================================================================

class EmailFeatureExtractor(BaseFeatureExtractor):
    """Extracts TF-IDF and statistical features from email text.

    Used for classical ML baselines (Random Forest, Logistic Regression).
    DistilBERT/BERT models receive raw tokenised text directly.

    Attributes:
        vectoriser: Fitted TfidfVectorizer.
        scaler: Fitted StandardScaler for statistical features.
        selector: Fitted SelectKBest for dimensionality reduction.
        n_tfidf_features: Number of TF-IDF features to retain.
    """

    def __init__(self, n_tfidf_features: int = 5000) -> None:
        super().__init__()
        self.n_tfidf_features = n_tfidf_features
        self.vectoriser = TfidfVectorizer(
            max_features=n_tfidf_features,
            ngram_range=(1, 2),
            sublinear_tf=True,
            strip_accents="unicode",
            analyzer="word",
            stop_words="english",
            min_df=2,
        )
        self.scaler = StandardScaler()
        self.selector: Optional[SelectKBest] = None

    def fit(self, df: pd.DataFrame) -> "EmailFeatureExtractor":
        """Fit TF-IDF vectoriser and scaler on training emails.

        Args:
            df: DataFrame with 'text' and 'label' columns.
        """
        if "text" not in df.columns:
            raise DataPreprocessingError(
                step="email_fit", reason="'text' column not found."
            )
        logger.info("Fitting email feature extractor on %d samples.", len(df))
        self.vectoriser.fit(df["text"].astype(str))
        stat_features = self._compute_statistical_features(df)
        self.scaler.fit(stat_features)
        self.is_fitted = True
        logger.info("Email feature extractor fitted. TF-IDF vocab: %d terms.",
                    len(self.vectoriser.vocabulary_))
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform emails to combined TF-IDF + statistical feature matrix.

        Args:
            df: DataFrame with 'text' column.

        Returns:
            Dense DataFrame of features.
        """
        tfidf_matrix = self.vectoriser.transform(df["text"].astype(str))
        stat_features = self._compute_statistical_features(df)
        stat_scaled = self.scaler.transform(stat_features)

        tfidf_df = pd.DataFrame(
            tfidf_matrix.toarray(),
            columns=[f"tfidf_{i}" for i in range(tfidf_matrix.shape[1])],
        )
        stat_df = pd.DataFrame(stat_scaled, columns=stat_features.columns)
        result = pd.concat([tfidf_df, stat_df], axis=1)

        if "label" in df.columns:
            result["label"] = df["label"].values
        return result

    def _compute_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute statistical text features for each email.

        Args:
            df: DataFrame with 'text' column.

        Returns:
            DataFrame with 8 statistical features.
        """
        texts = df["text"].astype(str)
        return pd.DataFrame({
            "text_length": texts.str.len(),
            "word_count": texts.str.split().str.len(),
            "unique_word_ratio": texts.apply(
                lambda t: len(set(t.split())) / max(len(t.split()), 1)
            ),
            "capital_ratio": texts.apply(
                lambda t: sum(1 for c in t if c.isupper()) / max(len(t), 1)
            ),
            "punctuation_count": texts.apply(
                lambda t: sum(1 for c in t if c in string.punctuation)
            ),
            "digit_ratio": texts.apply(
                lambda t: sum(c.isdigit() for c in t) / max(len(t), 1)
            ),
            "avg_word_length": texts.apply(
                lambda t: np.mean([len(w) for w in t.split()]) if t.split() else 0
            ),
            "url_count": texts.str.count(r"http\S+|www\.\S+"),
        })


# =============================================================================
# Login Behaviour Feature Engineer
# =============================================================================

class LoginFeatureEngineer(BaseFeatureExtractor):
    """Scales and enriches login behaviour features.

    The login dataset is already mostly numeric from the synthetic generator.
    This class adds derived features and applies StandardScaler.

    Attributes:
        scaler: Fitted StandardScaler.
        feature_names_: Ordered list of feature names after engineering.
    """

    def __init__(self) -> None:
        super().__init__()
        self.scaler = StandardScaler()
        self.feature_names_: list[str] = []

    def fit(self, df: pd.DataFrame) -> "LoginFeatureEngineer":
        """Fit scaler on training login data."""
        engineered = self._add_derived_features(df.copy())
        feature_cols = [c for c in engineered.columns if c != "label"]
        self.feature_names_ = feature_cols
        self.scaler.fit(engineered[feature_cols])
        self.is_fitted = True
        logger.info("Login feature engineer fitted on %d samples.", len(df))
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply feature engineering and scaling."""
        engineered = self._add_derived_features(df.copy())
        feature_cols = [c for c in self.feature_names_ if c in engineered.columns]
        scaled = self.scaler.transform(engineered[feature_cols])
        result = pd.DataFrame(scaled, columns=feature_cols)
        if "label" in df.columns:
            result["label"] = df["label"].values
        return result

    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add engineered features derived from base login attributes.

        Derived features:
          - is_night_login: 1 if hour < 6 or hour > 22
          - is_weekend: 1 if day_of_week >= 5
          - risk_score: weighted sum of anomaly indicators
          - failed_ratio: failed_attempts / login_frequency_24h
        """
        if "hour_of_day" in df.columns:
            df["is_night_login"] = (
                (df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)
            ).astype(int)
        if "day_of_week" in df.columns:
            df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        if "failed_attempts" in df.columns and "login_frequency_24h" in df.columns:
            df["failed_ratio"] = df["failed_attempts"] / (
                df["login_frequency_24h"].replace(0, 1)
            )
        # Composite risk indicator
        risk_cols = [
            c for c in [
                "ip_country_mismatch", "new_device", "new_location",
                "typing_speed_anomaly", "is_night_login", "is_weekend",
            ]
            if c in df.columns
        ]
        if risk_cols:
            df["composite_risk"] = df[risk_cols].mean(axis=1)
        return df

    def transform_single(self, features: dict) -> np.ndarray:
        """Transform a single login event dict to feature array.

        Args:
            features: Dict of raw login feature values.

        Returns:
            2D numpy array (1, n_features).
        """
        df = pd.DataFrame([features])
        return self.transform(df).drop(columns=["label"], errors="ignore").values


# =============================================================================
# Network Feature Engineer
# =============================================================================

class NetworkFeatureEngineer(BaseFeatureExtractor):
    """Scales NSL-KDD network features using MinMaxScaler.

    Network features span very different ranges (bytes: millions; flags: 0-1),
    so MinMaxScaler is preferred over StandardScaler here.

    Attributes:
        scaler: Fitted MinMaxScaler.
        feature_names_: Ordered feature columns after dropping label.
    """

    def __init__(self) -> None:
        super().__init__()
        self.scaler = MinMaxScaler()
        self.feature_names_: list[str] = []

    def fit(self, df: pd.DataFrame) -> "NetworkFeatureEngineer":
        """Fit MinMaxScaler on training network data."""
        feature_cols = [c for c in df.columns if c != "label"]
        self.feature_names_ = feature_cols
        self.scaler.fit(df[feature_cols])
        self.is_fitted = True
        logger.info("Network feature engineer fitted on %d samples.", len(df))
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Scale network features to [0, 1] range."""
        feature_cols = [c for c in self.feature_names_ if c in df.columns]
        scaled = self.scaler.transform(df[feature_cols])
        result = pd.DataFrame(scaled, columns=feature_cols)
        if "label" in df.columns:
            result["label"] = df["label"].values
        return result

    def transform_single(self, features: dict) -> np.ndarray:
        """Transform a single network event dict.

        Args:
            features: Dict of raw network feature values.

        Returns:
            2D numpy array (1, n_features).
        """
        df = pd.DataFrame([features])
        for col in self.feature_names_:
            if col not in df.columns:
                df[col] = 0.0
        return self.scaler.transform(df[self.feature_names_])


# =============================================================================
# FeatureEngineeringPipeline — Orchestrator
# =============================================================================

class FeatureEngineeringPipeline:
    """Orchestrates feature engineering for all four datasets.

    Saves fitted transformers to data/models/transformers/ for
    later use during API inference.

    Usage:
        pipeline = FeatureEngineeringPipeline()
        datasets = pipeline.run_all()
    """

    def __init__(self) -> None:
        self.extractors: dict[str, BaseFeatureExtractor] = {
            "malicious_url":   URLFeatureExtractor(),
            "phishing_email":  EmailFeatureExtractor(n_tfidf_features=5000),
            "login_behaviour": LoginFeatureEngineer(),
            "network_anomaly": NetworkFeatureEngineer(),
        }
        self._processed_paths: dict[str, Path] = {
            "malicious_url":   PROCESSED_DATA_DIR / "malicious_urls_clean.csv",
            "phishing_email":  PROCESSED_DATA_DIR / "phishing_emails_clean.csv",
            "login_behaviour": PROCESSED_DATA_DIR / "login_behaviour_clean.csv",
            "network_anomaly": PROCESSED_DATA_DIR / "network_anomaly_clean.csv",
        }
        self._feature_paths: dict[str, Path] = {
            k: PROCESSED_DATA_DIR / f"{k}_features.csv"
            for k in self.extractors
        }

    def run_all(self) -> dict[str, pd.DataFrame]:
        """Run feature engineering for all available datasets.

        Returns:
            Dictionary mapping dataset_key → feature DataFrame.
        """
        results = {}
        for key in self.extractors:
            if self._processed_paths[key].exists():
                try:
                    df = self.run(key)
                    results[key] = df
                except Exception as exc:
                    logger.error("Feature engineering failed for '%s': %s", key, exc)
            else:
                logger.warning(
                    "Skipping '%s' — processed file not found.", key
                )
        return results

    def run(self, dataset_key: str) -> pd.DataFrame:
        """Run feature engineering for a single dataset.

        Fits on full data (train/test split happens during model training).

        Args:
            dataset_key: One of 'malicious_url', 'phishing_email',
                         'login_behaviour', 'network_anomaly'.

        Returns:
            Feature-engineered DataFrame with 'label' column.
        """
        path = self._processed_paths[dataset_key]
        logger.info("Feature engineering: %s | Source: %s", dataset_key, path)
        df = pd.read_csv(path, low_memory=False)
        extractor = self.extractors[dataset_key]
        features_df = extractor.fit_transform(df)
        # Save features
        out_path = self._feature_paths[dataset_key]
        features_df.to_csv(out_path, index=False)
        # Save fitted extractor
        extractor.save(f"{dataset_key}_extractor")
        logger.info(
            "Feature engineering complete for '%s'. Output shape: %s",
            dataset_key, features_df.shape,
        )
        return features_df
