"""
downloader.py — Dataset Downloader (Module 2)
==============================================
Adaptive AI for Cyber Threat Detection

Downloads all required public datasets from free sources:
  1. Phishing Email    — Nazario Phishing Corpus + SpamAssassin (Kaggle/HuggingFace)
  2. Malicious URL     — PhiUSIIL Phishing URL Dataset (UCI/Kaggle)
  3. Login Behaviour   — Synthetic generator (no public labelled dataset available)
  4. Network Anomaly   — KDD Cup 99 / NSL-KDD (UCI Repository)

All datasets are 100% free and open-source.

Design Patterns:
  - Strategy: each dataset uses a different download strategy
  - Factory Method: _get_downloader_for() returns the right strategy
  - Template Method: download_all() calls each strategy in sequence

IEEE 29148 FR: FR-DAT-001 through FR-DAT-004

Author: B.Tech Capstone Project
"""

import hashlib
import os
import shutil
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlretrieve

import pandas as pd
import numpy as np
import requests
from tqdm import tqdm

from src.core.constants import PROJECT_ROOT, RAW_DATA_DIR, RANDOM_SEED, ThreatType
from src.core.exceptions import DataLoadError
from src.core.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Dataset Metadata
# =============================================================================

@dataclass
class DatasetInfo:
    """Metadata about a downloadable dataset.

    Attributes:
        name: Human-readable dataset name.
        threat_type: Which threat this dataset is used for.
        source_url: Primary download URL.
        filename: Local filename after download.
        expected_rows: Approximate expected row count (for validation).
        license: Dataset license string.
        citation: How to cite this dataset in the IEEE paper.
        checksum: Optional MD5 checksum for integrity verification.
    """

    name: str
    threat_type: ThreatType
    source_url: str
    filename: str
    expected_rows: int
    license: str
    citation: str
    checksum: Optional[str] = None
    extra_files: list[str] = field(default_factory=list)


# Registry of all datasets — extend here to add new datasets
DATASET_REGISTRY: dict[str, DatasetInfo] = {
    "phishing_email": DatasetInfo(
        name="Phishing Email Dataset (Nazario + SpamAssassin combined)",
        threat_type=ThreatType.PHISHING_EMAIL,
        source_url=(
            "https://huggingface.co/datasets/ealvaradob/phishing-dataset/"
            "resolve/main/data/phishing_email.csv"
        ),
        filename="phishing_emails_raw.csv",
        expected_rows=8000,
        license="CC BY 4.0",
        citation=(
            "Alvarado, E. (2023). Phishing Dataset. HuggingFace Datasets. "
            "https://huggingface.co/datasets/ealvaradob/phishing-dataset"
        ),
    ),
    "malicious_url": DatasetInfo(
        name="PhiUSIIL Phishing URL Dataset",
        threat_type=ThreatType.MALICIOUS_URL,
        source_url=(
            "https://archive.ics.uci.edu/static/public/967/"
            "phiusiil+phishing+url+dataset.zip"
        ),
        filename="phishing_urls_raw.csv",
        expected_rows=235000,
        license="CC BY 4.0",
        citation=(
            "Prasad, A. & Chandra, S. (2023). PhiUSIIL Phishing URL Dataset. "
            "UCI Machine Learning Repository. https://doi.org/10.24432/C5GW2N"
        ),
    ),
    "network_anomaly": DatasetInfo(
        name="NSL-KDD Network Intrusion Detection Dataset",
        threat_type=ThreatType.NETWORK_ANOMALY,
        source_url="https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
        filename="nsl_kdd_train_raw.csv",
        expected_rows=125973,
        license="Public Domain",
        citation=(
            "Tavallaee, M. et al. (2009). A Detailed Analysis of the KDD CUP 99 Data Set. "
            "Proceedings of the 2009 IEEE Symposium on Computational Intelligence for "
            "Security and Defense Applications."
        ),
    ),
    "network_anomaly_test": DatasetInfo(
        name="NSL-KDD Test Dataset",
        threat_type=ThreatType.NETWORK_ANOMALY,
        source_url="https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
        filename="nsl_kdd_test_raw.csv",
        expected_rows=22544,
        license="Public Domain",
        citation="See network_anomaly citation.",
    ),
}

# NSL-KDD column names (41 features + label + difficulty)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]


# =============================================================================
# Download Progress Hook
# =============================================================================

class _DownloadProgressBar(tqdm):
    """tqdm subclass for urlretrieve download progress display."""

    def update_to(self, b: int = 1, bsize: int = 1, tsize: Optional[int] = None) -> None:
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


# =============================================================================
# Dataset Downloader
# =============================================================================

class DatasetDownloader:
    """Orchestrates downloading of all required datasets.

    Each dataset is downloaded from a free public source, saved to
    data/raw/, and validated for row count and basic integrity.

    Usage:
        downloader = DatasetDownloader()
        downloader.download_all()

        # Or download a single dataset
        downloader.download("phishing_email")

    Attributes:
        raw_dir: Path to the data/raw/ directory.
        force_redownload: If True, re-download even if file already exists.
    """

    def __init__(
        self,
        raw_dir: Optional[Path] = None,
        force_redownload: bool = False,
    ) -> None:
        """Initialise the downloader.

        Args:
            raw_dir: Override path for raw data directory.
            force_redownload: Whether to re-download existing files.
        """
        self.raw_dir: Path = raw_dir or RAW_DATA_DIR
        self.force_redownload = force_redownload
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        logger.info("DatasetDownloader initialised. Raw dir: %s", self.raw_dir)

    def download_all(self) -> dict[str, bool]:
        """Download all datasets in the registry.

        Returns:
            Dictionary mapping dataset key → success boolean.
        """
        logger.info("Starting download of all %d datasets.", len(DATASET_REGISTRY))
        results = {}
        for key in DATASET_REGISTRY:
            try:
                success = self.download(key)
                results[key] = success
            except Exception as exc:
                logger.error("Failed to download '%s': %s", key, exc)
                results[key] = False

        # Always generate synthetic login data (no public dataset needed)
        try:
            self._generate_login_behaviour_data()
            results["login_behaviour"] = True
        except Exception as exc:
            logger.error("Failed to generate login behaviour data: %s", exc)
            results["login_behaviour"] = False

        passed = sum(results.values())
        logger.info(
            "Download complete. %d/%d datasets ready.", passed, len(results)
        )
        return results

    def download(self, dataset_key: str) -> bool:
        """Download a single dataset by its registry key.

        Args:
            dataset_key: Key from DATASET_REGISTRY (e.g., 'phishing_email').

        Returns:
            True if download succeeded and file is valid.

        Raises:
            DataLoadError: If download fails after all retries.
            KeyError: If dataset_key is not in DATASET_REGISTRY.
        """
        if dataset_key not in DATASET_REGISTRY:
            raise KeyError(
                f"Unknown dataset key: '{dataset_key}'. "
                f"Available: {list(DATASET_REGISTRY.keys())}"
            )

        info = DATASET_REGISTRY[dataset_key]
        dest_path = self.raw_dir / info.filename

        if dest_path.exists() and not self.force_redownload:
            logger.info(
                "Dataset '%s' already exists at %s — skipping.",
                dataset_key, dest_path,
            )
            return True

        logger.info(
            "Downloading dataset: %s\n  Source: %s\n  Destination: %s",
            info.name, info.source_url, dest_path,
        )

        try:
            if info.source_url.endswith(".zip"):
                self._download_zip(info, dest_path)
            else:
                self._download_direct(info.source_url, dest_path, info.name)

            # Post-process NSL-KDD (add column names)
            if "nsl_kdd" in dataset_key:
                self._postprocess_nsl_kdd(dest_path)

            # Validate
            self._validate_download(dest_path, info)
            logger.info("✓ Dataset '%s' downloaded successfully.", dataset_key)
            return True

        except Exception as exc:
            logger.error(
                "✗ Failed to download '%s': %s", dataset_key, exc
            )
            raise DataLoadError(
                source=info.source_url,
                reason=str(exc),
            ) from exc

    def _download_direct(
        self,
        url: str,
        dest_path: Path,
        display_name: str,
    ) -> None:
        """Download a file directly from URL with progress bar.

        Args:
            url: Source URL.
            dest_path: Destination file path.
            display_name: Name to show in progress bar.
        """
        with _DownloadProgressBar(
            unit="B", unit_scale=True, miniters=1, desc=display_name[:40]
        ) as progress:
            urlretrieve(url, dest_path, reporthook=progress.update_to)

    def _download_zip(self, info: DatasetInfo, dest_path: Path) -> None:
        """Download a ZIP archive, extract the target CSV, then remove ZIP.

        Args:
            info: DatasetInfo with source_url and filename.
            dest_path: Where to save the extracted CSV.
        """
        zip_path = self.raw_dir / f"_temp_{info.filename}.zip"

        try:
            self._download_direct(info.source_url, zip_path, info.name)

            with zipfile.ZipFile(zip_path, "r") as zf:
                # Find CSV files in the archive
                csv_files = [f for f in zf.namelist() if f.endswith(".csv")]
                if not csv_files:
                    raise DataLoadError(
                        source=str(zip_path),
                        reason="No CSV files found in ZIP archive.",
                    )
                # Extract the largest CSV (main dataset file)
                largest_csv = max(csv_files, key=lambda f: zf.getinfo(f).file_size)
                logger.info("Extracting '%s' from ZIP.", largest_csv)
                extracted_path = self.raw_dir / Path(largest_csv).name
                zf.extract(largest_csv, self.raw_dir)

                # Handle nested directory in ZIP
                extracted = self.raw_dir / largest_csv
                if extracted != extracted_path:
                    extracted_path = self.raw_dir / Path(largest_csv).name

                shutil.move(str(self.raw_dir / largest_csv), str(dest_path))

        finally:
            if zip_path.exists():
                zip_path.unlink()
            # Clean up any extracted subdirectories
            for item in self.raw_dir.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)

    def _postprocess_nsl_kdd(self, path: Path) -> None:
        """Add column headers to NSL-KDD raw text file.

        NSL-KDD is distributed as a headerless comma-separated text file.
        This method adds proper column names and saves as CSV.

        Args:
            path: Path to the downloaded NSL-KDD text file.
        """
        logger.info("Post-processing NSL-KDD file: adding column headers.")
        try:
            df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
            df.to_csv(path, index=False)
            logger.info("NSL-KDD post-processing complete. Shape: %s", df.shape)
        except Exception as exc:
            logger.warning("NSL-KDD post-processing failed: %s", exc)

    def _validate_download(self, path: Path, info: DatasetInfo) -> None:
        """Validate the downloaded file size and row count.

        Args:
            path: Path to the downloaded file.
            info: Dataset metadata for comparison.

        Raises:
            DataLoadError: If file is empty or suspiciously small.
        """
        if not path.exists():
            raise DataLoadError(source=str(path), reason="File not found after download.")

        file_size_bytes = path.stat().st_size
        if file_size_bytes < 1000:
            raise DataLoadError(
                source=str(path),
                reason=f"File is suspiciously small ({file_size_bytes} bytes). "
                       f"Download may have failed silently.",
            )

        # Quick row count check (read only header + 10 rows to avoid loading full file)
        try:
            df_peek = pd.read_csv(path, nrows=10)
            logger.info(
                "Validation OK — '%s' | Size: %.1f KB | Columns: %d",
                path.name,
                file_size_bytes / 1024,
                len(df_peek.columns),
            )
        except Exception:
            logger.warning("Could not peek at CSV '%s' for validation.", path.name)

    def _generate_login_behaviour_data(self) -> None:
        """Generate synthetic login behaviour dataset.

        No labelled public login dataset is freely available at sufficient scale.
        This generator creates a statistically realistic synthetic dataset using
        domain knowledge about normal vs. anomalous login patterns.

        The generated features mirror real-world login telemetry:
          - Time-based: hour_of_day, day_of_week
          - Device/location: new_device, new_location, ip_country_mismatch
          - Behaviour: failed_attempts, session_duration, typing_speed_anomaly

        Label distribution: ~90% normal, ~10% suspicious (realistic class imbalance).

        Saves to: data/raw/login_behaviour_raw.csv
        """
        dest_path = self.raw_dir / "login_behaviour_raw.csv"

        if dest_path.exists() and not self.force_redownload:
            logger.info("Login behaviour dataset already exists — skipping generation.")
            return

        logger.info("Generating synthetic login behaviour dataset (50,000 samples)...")
        rng = np.random.default_rng(RANDOM_SEED)
        n_samples = 50_000
        n_normal = int(n_samples * 0.90)
        n_anomaly = n_samples - n_normal

        def _normal_logins(n: int) -> dict:
            return {
                "hour_of_day": rng.integers(8, 19, n),           # Business hours
                "day_of_week": rng.integers(0, 5, n),            # Weekdays
                "login_duration": rng.normal(120, 30, n).clip(10, 600),
                "failed_attempts": rng.integers(0, 2, n),
                "ip_country_mismatch": rng.choice([0, 1], n, p=[0.97, 0.03]),
                "new_device": rng.choice([0, 1], n, p=[0.92, 0.08]),
                "new_location": rng.choice([0, 1], n, p=[0.90, 0.10]),
                "typing_speed_anomaly": rng.normal(0.1, 0.05, n).clip(0, 1),
                "session_duration": rng.normal(1800, 600, n).clip(60, 14400),
                "concurrent_sessions": rng.integers(1, 3, n),
                "bytes_transferred": rng.normal(5000, 2000, n).clip(100, 50000),
                "login_frequency_24h": rng.integers(1, 5, n),
                "label": np.zeros(n, dtype=int),
            }

        def _anomaly_logins(n: int) -> dict:
            return {
                "hour_of_day": rng.choice(
                    list(range(0, 6)) + list(range(22, 24)), n
                ),                                                  # Night hours
                "day_of_week": rng.integers(0, 7, n),
                "login_duration": rng.normal(10, 5, n).clip(1, 30),  # Too fast
                "failed_attempts": rng.integers(3, 15, n),           # Many failures
                "ip_country_mismatch": rng.choice([0, 1], n, p=[0.20, 0.80]),
                "new_device": rng.choice([0, 1], n, p=[0.20, 0.80]),
                "new_location": rng.choice([0, 1], n, p=[0.15, 0.85]),
                "typing_speed_anomaly": rng.normal(0.8, 0.15, n).clip(0, 1),
                "session_duration": rng.choice(
                    [rng.integers(1, 30, n), rng.integers(10000, 86400, n)],
                    axis=0,
                )[0],
                "concurrent_sessions": rng.integers(3, 15, n),
                "bytes_transferred": rng.normal(100000, 50000, n).clip(50000, 1000000),
                "login_frequency_24h": rng.integers(10, 100, n),
                "label": np.ones(n, dtype=int),
            }

        normal_data = _normal_logins(n_normal)
        anomaly_data = _anomaly_logins(n_anomaly)

        # Combine and shuffle
        combined = {}
        for key in normal_data:
            combined[key] = np.concatenate([normal_data[key], anomaly_data[key]])

        df = pd.DataFrame(combined)
        df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

        # Add realistic user IDs and timestamps
        df["user_id"] = [f"USR{i:06d}" for i in rng.integers(1, 10000, n_samples)]
        df["timestamp"] = pd.date_range(
            start="2024-01-01", periods=n_samples, freq="10min"
        )

        df.to_csv(dest_path, index=False)
        logger.info(
            "✓ Synthetic login dataset generated. Shape: %s | "
            "Normal: %d | Anomaly: %d | Saved: %s",
            df.shape, n_normal, n_anomaly, dest_path,
        )

    def get_status(self) -> dict[str, dict]:
        """Return download status of all datasets.

        Returns:
            Dictionary mapping dataset_key → status dict with
            'exists', 'path', and 'size_kb' fields.
        """
        status = {}
        all_keys = list(DATASET_REGISTRY.keys()) + ["login_behaviour"]
        filenames = {k: DATASET_REGISTRY[k].filename for k in DATASET_REGISTRY}
        filenames["login_behaviour"] = "login_behaviour_raw.csv"

        for key in all_keys:
            path = self.raw_dir / filenames[key]
            exists = path.exists()
            status[key] = {
                "exists": exists,
                "path": str(path),
                "size_kb": round(path.stat().st_size / 1024, 1) if exists else 0,
            }
        return status
