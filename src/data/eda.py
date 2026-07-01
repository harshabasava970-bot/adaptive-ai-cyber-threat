"""
eda.py — Exploratory Data Analysis (Module 4)
===============================================
Adaptive AI for Cyber Threat Detection

Performs comprehensive EDA on all four cleaned datasets and saves
publication-ready plots to docs/architecture/eda_plots/.

Analyses performed:
  - Class distribution (imbalance detection)
  - Missing value heatmap
  - Feature correlation matrix
  - Numeric feature distributions (histograms + box plots)
  - Text length distribution (for email/URL datasets)
  - Pairplot for top correlated features

IEEE 29148: EDA results inform NFR-PER-001 (model performance baseline).

Author: B.Tech Capstone Project
"""

from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from src.core.constants import PROCESSED_DATA_DIR, PROJECT_ROOT
from src.core.exceptions import DataLoadError
from src.core.logger import get_logger

logger = get_logger(__name__)

# Output directory for EDA plots
EDA_PLOTS_DIR = PROJECT_ROOT / "docs" / "architecture" / "eda_plots"

# Consistent visual style across all plots
PLOT_STYLE = "dark_background"
PALETTE = "plasma"
FIGURE_DPI = 150
FIGURE_FORMAT = "png"


class EDAAnalyser:
    """Performs and persists exploratory data analysis for a dataset.

    Usage:
        analyser = EDAAnalyser(dataset_key="network_anomaly")
        report = analyser.run()

    Attributes:
        dataset_key: Short name identifying the dataset.
        df: The loaded DataFrame.
        plots_dir: Directory where plots will be saved.
        report: Dictionary of computed statistics.
    """

    _DATASET_PATHS: dict[str, Path] = {
        "phishing_email":  PROCESSED_DATA_DIR / "phishing_emails_clean.csv",
        "malicious_url":   PROCESSED_DATA_DIR / "malicious_urls_clean.csv",
        "login_behaviour": PROCESSED_DATA_DIR / "login_behaviour_clean.csv",
        "network_anomaly": PROCESSED_DATA_DIR / "network_anomaly_clean.csv",
    }

    def __init__(self, dataset_key: str) -> None:
        """Initialise EDA analyser for the given dataset.

        Args:
            dataset_key: One of 'phishing_email', 'malicious_url',
                         'login_behaviour', 'network_anomaly'.

        Raises:
            KeyError: If dataset_key is not recognised.
        """
        if dataset_key not in self._DATASET_PATHS:
            raise KeyError(
                f"Unknown dataset key '{dataset_key}'. "
                f"Available: {list(self._DATASET_PATHS.keys())}"
            )
        self.dataset_key = dataset_key
        self.df: Optional[pd.DataFrame] = None
        self.plots_dir = EDA_PLOTS_DIR / dataset_key
        self.plots_dir.mkdir(parents=True, exist_ok=True)
        self.report: dict = {}

    def run(self) -> dict:
        """Execute the full EDA pipeline.

        Returns:
            Dictionary with computed statistics (class counts, correlations, etc.)
        """
        logger.info("Starting EDA for dataset: %s", self.dataset_key)
        self._load()
        self._basic_statistics()
        self._class_distribution()
        self._missing_value_analysis()
        self._numeric_distributions()
        self._correlation_matrix()
        if "text" in self.df.columns:
            self._text_length_distribution()
        if "url" in self.df.columns:
            self._url_length_distribution()
        logger.info(
            "EDA complete for '%s'. Plots saved to: %s",
            self.dataset_key, self.plots_dir,
        )
        return self.report

    # -------------------------------------------------------------------------
    # Private Methods
    # -------------------------------------------------------------------------

    def _load(self) -> None:
        """Load processed CSV into DataFrame."""
        path = self._DATASET_PATHS[self.dataset_key]
        if not path.exists():
            raise DataLoadError(
                source=str(path),
                reason="Processed dataset not found. Run DataCleaner first.",
            )
        self.df = pd.read_csv(path, low_memory=False)
        logger.info("Loaded %d rows × %d cols for EDA.", len(self.df), len(self.df.columns))

    def _basic_statistics(self) -> None:
        """Compute and log basic descriptive statistics."""
        self.report["shape"] = self.df.shape
        self.report["dtypes"] = self.df.dtypes.astype(str).to_dict()
        self.report["null_counts"] = self.df.isnull().sum().to_dict()
        self.report["describe"] = self.df.describe().to_dict()

        stats_path = self.plots_dir / "basic_stats.txt"
        with open(stats_path, "w", encoding="utf-8") as f:
            f.write(f"Dataset: {self.dataset_key}\n")
            f.write(f"Shape: {self.df.shape}\n\n")
            f.write("=== Descriptive Statistics ===\n")
            f.write(self.df.describe(include="all").to_string())
            f.write("\n\n=== Null Counts ===\n")
            f.write(self.df.isnull().sum().to_string())
        logger.debug("Basic stats saved to %s", stats_path)

    def _class_distribution(self) -> None:
        """Plot and analyse class label distribution."""
        if "label" not in self.df.columns:
            return

        counts = self.df["label"].value_counts()
        self.report["class_counts"] = counts.to_dict()
        imbalance_ratio = counts.max() / counts.min() if len(counts) > 1 else 1.0
        self.report["imbalance_ratio"] = round(imbalance_ratio, 2)

        plt.style.use(PLOT_STYLE)
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle(
            f"Class Distribution — {self.dataset_key.replace('_', ' ').title()}",
            fontsize=14, color="white", fontweight="bold",
        )

        # Bar chart
        label_names = {0: "Benign / Normal", 1: "Threat / Attack"}
        x_labels = [label_names.get(int(k), str(k)) for k in counts.index]
        colors = ["#00c9a7", "#ff4b4b"]
        axes[0].bar(x_labels, counts.values, color=colors[:len(counts)], edgecolor="white")
        axes[0].set_title("Class Counts", color="white")
        axes[0].set_ylabel("Count", color="white")
        axes[0].tick_params(colors="white")
        for spine in axes[0].spines.values():
            spine.set_edgecolor("gray")
        for i, v in enumerate(counts.values):
            axes[0].text(i, v + counts.max() * 0.01, f"{v:,}", ha="center",
                         color="white", fontsize=10)

        # Pie chart
        axes[1].pie(
            counts.values,
            labels=x_labels,
            autopct="%1.1f%%",
            colors=colors[:len(counts)],
            startangle=90,
            textprops={"color": "white"},
        )
        axes[1].set_title(
            f"Imbalance Ratio: {imbalance_ratio:.1f}:1", color="white"
        )

        plt.tight_layout()
        self._save_figure(fig, "class_distribution.png")
        logger.info(
            "Class distribution — %s | Imbalance ratio: %.2f:1",
            counts.to_dict(), imbalance_ratio,
        )

    def _missing_value_analysis(self) -> None:
        """Plot missing value heatmap."""
        null_counts = self.df.isnull().sum()
        total_nulls = int(null_counts.sum())
        self.report["total_nulls"] = total_nulls

        if total_nulls == 0:
            logger.info("No missing values in '%s' — skipping heatmap.", self.dataset_key)
            return

        plt.style.use(PLOT_STYLE)
        fig, ax = plt.subplots(figsize=(12, 6))
        null_pct = (null_counts / len(self.df) * 100).sort_values(ascending=False)
        null_pct = null_pct[null_pct > 0]

        ax.barh(null_pct.index, null_pct.values, color="#ff4b4b", edgecolor="white")
        ax.set_title(
            f"Missing Values (%) — {self.dataset_key.replace('_', ' ').title()}",
            color="white", fontsize=13,
        )
        ax.set_xlabel("Missing %", color="white")
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_edgecolor("gray")

        plt.tight_layout()
        self._save_figure(fig, "missing_values.png")

    def _numeric_distributions(self) -> None:
        """Plot histogram distributions for all numeric feature columns."""
        numeric_cols = [
            c for c in self.df.select_dtypes(include=[np.number]).columns
            if c != "label"
        ]
        if not numeric_cols:
            return

        # Plot at most 16 features
        cols_to_plot = numeric_cols[:16]
        n_cols = 4
        n_rows = (len(cols_to_plot) + n_cols - 1) // n_cols

        plt.style.use(PLOT_STYLE)
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(16, n_rows * 3))
        fig.suptitle(
            f"Feature Distributions — {self.dataset_key.replace('_', ' ').title()}",
            fontsize=14, color="white", fontweight="bold",
        )
        axes_flat = axes.flatten() if hasattr(axes, "flatten") else [axes]

        for i, col in enumerate(cols_to_plot):
            ax = axes_flat[i]
            self.df[col].hist(
                ax=ax, bins=40, color="#7c6af7", edgecolor="none", alpha=0.85
            )
            ax.set_title(col, color="white", fontsize=9)
            ax.tick_params(colors="white", labelsize=7)
            for spine in ax.spines.values():
                spine.set_edgecolor("gray")

        # Hide unused subplots
        for j in range(len(cols_to_plot), len(axes_flat)):
            axes_flat[j].set_visible(False)

        plt.tight_layout()
        self._save_figure(fig, "feature_distributions.png")

    def _correlation_matrix(self) -> None:
        """Plot Pearson correlation heatmap for numeric features."""
        numeric_df = self.df.select_dtypes(include=[np.number])
        if numeric_df.shape[1] < 2:
            return

        # Limit to 20 columns for readability
        if numeric_df.shape[1] > 20:
            # Select top 20 most correlated with label if available
            if "label" in numeric_df.columns:
                corr_with_label = numeric_df.corr()["label"].abs().sort_values(ascending=False)
                top_cols = corr_with_label.head(20).index.tolist()
                numeric_df = numeric_df[top_cols]
            else:
                numeric_df = numeric_df.iloc[:, :20]

        corr_matrix = numeric_df.corr()
        self.report["top_correlations"] = (
            corr_matrix.unstack()
            .sort_values(ascending=False)
            .drop_duplicates()
            .head(10)
            .to_dict()
        )

        plt.style.use(PLOT_STYLE)
        fig, ax = plt.subplots(figsize=(14, 11))
        mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
        sns.heatmap(
            corr_matrix,
            mask=mask,
            cmap="coolwarm",
            center=0,
            vmin=-1, vmax=1,
            annot=corr_matrix.shape[0] <= 12,
            fmt=".2f",
            linewidths=0.5,
            ax=ax,
            cbar_kws={"shrink": 0.8},
        )
        ax.set_title(
            f"Correlation Matrix — {self.dataset_key.replace('_', ' ').title()}",
            color="white", fontsize=13, pad=15,
        )
        ax.tick_params(colors="white", labelsize=8)
        plt.tight_layout()
        self._save_figure(fig, "correlation_matrix.png")

    def _text_length_distribution(self) -> None:
        """Plot email text length distribution (phishing email dataset)."""
        self.df["text_length"] = self.df["text"].str.len()
        plt.style.use(PLOT_STYLE)
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("Email Text Length Distribution", color="white", fontsize=13)

        for label_val, label_name, color in [
            (0, "Legitimate", "#00c9a7"), (1, "Phishing", "#ff4b4b")
        ]:
            subset = self.df[self.df["label"] == label_val]["text_length"]
            if len(subset) == 0:
                continue
            axes[0].hist(subset, bins=60, alpha=0.7, label=label_name, color=color)

        axes[0].set_title("Length Histogram by Class", color="white")
        axes[0].set_xlabel("Character Count", color="white")
        axes[0].set_ylabel("Frequency", color="white")
        axes[0].legend()
        axes[0].tick_params(colors="white")

        self.df.boxplot(
            column="text_length", by="label", ax=axes[1],
            boxprops=dict(color="white"), medianprops=dict(color="#ffcc00"),
            whiskerprops=dict(color="white"), capprops=dict(color="white"),
            flierprops=dict(marker="o", color="#ff4b4b", alpha=0.3),
        )
        axes[1].set_title("Length Box Plot by Class", color="white")
        axes[1].tick_params(colors="white")
        plt.tight_layout()
        self._save_figure(fig, "text_length_distribution.png")
        self.df = self.df.drop(columns=["text_length"])

    def _url_length_distribution(self) -> None:
        """Plot URL length distribution (malicious URL dataset)."""
        self.df["url_length"] = self.df["url"].str.len()
        plt.style.use(PLOT_STYLE)
        fig, ax = plt.subplots(figsize=(12, 5))
        for label_val, label_name, color in [
            (0, "Benign", "#00c9a7"), (1, "Malicious", "#ff4b4b")
        ]:
            subset = self.df[self.df["label"] == label_val]["url_length"]
            if len(subset) > 0:
                ax.hist(subset, bins=60, alpha=0.7, label=label_name, color=color)
        ax.set_title("URL Length Distribution by Class", color="white", fontsize=13)
        ax.set_xlabel("URL Length (chars)", color="white")
        ax.set_ylabel("Frequency", color="white")
        ax.legend()
        ax.tick_params(colors="white")
        plt.tight_layout()
        self._save_figure(fig, "url_length_distribution.png")
        self.df = self.df.drop(columns=["url_length"])

    def _save_figure(self, fig: plt.Figure, filename: str) -> None:
        """Save a matplotlib figure to the plots directory."""
        path = self.plots_dir / filename
        fig.savefig(path, dpi=FIGURE_DPI, format=FIGURE_FORMAT, bbox_inches="tight")
        plt.close(fig)
        logger.debug("Plot saved: %s", path)


class EDARunner:
    """Runs EDA for all four datasets and aggregates results."""

    DATASET_KEYS = ["phishing_email", "malicious_url", "login_behaviour", "network_anomaly"]

    def run_all(self) -> dict[str, dict]:
        """Run EDA for every available processed dataset.

        Returns:
            Dictionary mapping dataset_key → EDA report dict.
        """
        results = {}
        for key in self.DATASET_KEYS:
            csv_path = EDAAnalyser._DATASET_PATHS.get(key)
            if csv_path and csv_path.exists():
                try:
                    analyser = EDAAnalyser(key)
                    results[key] = analyser.run()
                except Exception as exc:
                    logger.error("EDA failed for '%s': %s", key, exc)
                    results[key] = {"error": str(exc)}
            else:
                logger.warning(
                    "Skipping EDA for '%s' — processed file not found at %s.",
                    key, csv_path,
                )
        return results
