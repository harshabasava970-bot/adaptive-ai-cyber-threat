"""
explainer.py — Explainable AI: SHAP + LIME (Module 11)
========================================================
Adaptive AI for Cyber Threat Detection

Generates per-prediction explanations using SHAP and LIME.
Every model prediction is accompanied by:
  - SHAP: global and local feature attributions (game-theoretic)
  - LIME: local linear approximation of model decision boundary

IEEE 7000: All AI predictions must be explainable to human reviewers.
IEEE 29148 FR: FR-XAI-001, FR-XAI-002, FR-XAI-003

Author: B.Tech Capstone Project
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.core.constants import MODELS_DIR, PROJECT_ROOT, SHAP_MAX_DISPLAY_FEATURES
from src.core.exceptions import ExplainabilityError
from src.core.logger import get_logger

logger = get_logger(__name__)

EXPLANATIONS_DIR = PROJECT_ROOT / "data" / "explanations"
EXPLANATIONS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ExplanationResult:
    """Structured output from an explainability analysis.

    Attributes:
        model_name: Name of the model being explained.
        method: 'shap' or 'lime'.
        feature_names: Ordered list of feature names.
        feature_importances: Absolute importance values for each feature.
        top_features: List of (feature_name, importance) tuples, sorted descending.
        plot_path: Path to saved explanation plot (if generated).
        raw_values: Raw SHAP values or LIME weights.
        explanation_text: Human-readable textual explanation.
    """

    model_name: str
    method: str
    feature_names: list[str]
    feature_importances: list[float]
    top_features: list[tuple[str, float]] = field(default_factory=list)
    plot_path: Optional[str] = None
    raw_values: Optional[Any] = None
    explanation_text: str = ""

    def to_dict(self) -> dict:
        """Serialise explanation to JSON-compatible dictionary."""
        return {
            "model_name": self.model_name,
            "method": self.method,
            "top_features": [
                {"feature": f, "importance": round(float(v), 6)}
                for f, v in self.top_features
            ],
            "plot_path": self.plot_path,
            "explanation_text": self.explanation_text,
        }


class SHAPExplainer:
    """Generates SHAP explanations for sklearn-compatible models.

    Automatically selects the appropriate SHAP explainer:
      - TreeExplainer: for tree-based models (XGBoost, RandomForest)
      - LinearExplainer: for linear models (LogisticRegression)
      - KernelExplainer: fallback for any model type

    IEEE 7000: SHAP satisfies the requirement for mathematically
    rigorous feature attribution (Shapley values from cooperative game theory).

    Attributes:
        model: The trained sklearn/xgboost model.
        feature_names: Names of input features.
        model_name: Human-readable model identifier.
        _explainer: Fitted shap.Explainer instance.
    """

    def __init__(
        self,
        model: Any,
        feature_names: list[str],
        model_name: str,
        background_data: Optional[np.ndarray] = None,
    ) -> None:
        """Initialise SHAP explainer.

        Args:
            model: Trained sklearn/xgboost model with predict_proba().
            feature_names: List of feature column names.
            model_name: Identifier for logging and saved plots.
            background_data: Background dataset for KernelExplainer.
                             If None and tree model, not needed.
        """
        self.model = model
        self.feature_names = feature_names
        self.model_name = model_name
        self.background_data = background_data
        self._explainer: Optional[Any] = None
        self._init_explainer()

    def _init_explainer(self) -> None:
        """Initialise the appropriate SHAP explainer for the model type."""
        try:
            import shap
            model_type = type(self.model).__name__.lower()

            if any(t in model_type for t in ["xgb", "randomforest", "gradientboost", "tree"]):
                self._explainer = shap.TreeExplainer(self.model)
                logger.info("SHAP TreeExplainer initialised for: %s", self.model_name)
            elif any(t in model_type for t in ["logistic", "linear", "ridge", "lasso"]):
                self._explainer = shap.LinearExplainer(
                    self.model,
                    self.background_data if self.background_data is not None
                    else np.zeros((1, len(self.feature_names))),
                )
                logger.info("SHAP LinearExplainer initialised for: %s", self.model_name)
            else:
                # Fallback: KernelExplainer (model-agnostic, slower)
                bg = (
                    self.background_data[:100]
                    if self.background_data is not None
                    else np.zeros((1, len(self.feature_names)))
                )
                self._explainer = shap.KernelExplainer(
                    self.model.predict_proba, bg
                )
                logger.info("SHAP KernelExplainer initialised for: %s", self.model_name)
        except Exception as exc:
            raise ExplainabilityError("SHAP", f"Explainer init failed: {exc}") from exc

    def explain(
        self,
        X: np.ndarray,
        save_plot: bool = True,
        plot_filename: Optional[str] = None,
    ) -> ExplanationResult:
        """Generate SHAP explanation for input sample(s).

        Args:
            X: Input feature array shape (1, n_features) or (n, n_features).
            save_plot: Whether to save a SHAP bar plot to disk.
            plot_filename: Override filename for saved plot.

        Returns:
            ExplanationResult with feature importances and optional plot path.

        Raises:
            ExplainabilityError: If SHAP computation fails.
        """
        try:
            import shap

            shap_values = self._explainer.shap_values(X)

            # For binary classification, TreeExplainer returns list [class0, class1]
            if isinstance(shap_values, list):
                shap_values = shap_values[1]  # Use class 1 (threat) values

            # Mean absolute SHAP values across samples (global importance)
            if shap_values.ndim == 1:
                importances = np.abs(shap_values)
            else:
                importances = np.abs(shap_values).mean(axis=0)

            # Build sorted top-features list
            n_features = min(SHAP_MAX_DISPLAY_FEATURES, len(self.feature_names))
            top_indices = np.argsort(importances)[::-1][:n_features]
            top_features = [
                (self.feature_names[i], float(importances[i]))
                for i in top_indices
            ]

            plot_path = None
            if save_plot:
                plot_path = self._save_shap_plot(
                    importances, top_indices, plot_filename
                )

            explanation_text = self._generate_text_explanation(top_features)

            return ExplanationResult(
                model_name=self.model_name,
                method="shap",
                feature_names=self.feature_names,
                feature_importances=importances.tolist(),
                top_features=top_features,
                plot_path=str(plot_path) if plot_path else None,
                raw_values=shap_values,
                explanation_text=explanation_text,
            )
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityError("SHAP", str(exc)) from exc

    def _save_shap_plot(
        self,
        importances: np.ndarray,
        top_indices: np.ndarray,
        filename: Optional[str],
    ) -> Path:
        """Save SHAP feature importance bar chart.

        Args:
            importances: Full importance array.
            top_indices: Sorted indices of top features.
            filename: Optional filename override.

        Returns:
            Path to saved plot file.
        """
        plt.style.use("dark_background")
        n = min(SHAP_MAX_DISPLAY_FEATURES, len(top_indices))
        indices = top_indices[:n]
        vals = importances[indices]
        names = [self.feature_names[i] for i in indices]

        fig, ax = plt.subplots(figsize=(10, max(4, n * 0.4)))
        colors = plt.cm.plasma(np.linspace(0.2, 0.9, n))
        ax.barh(range(n), vals[::-1], color=colors)
        ax.set_yticks(range(n))
        ax.set_yticklabels(names[::-1], fontsize=9)
        ax.set_xlabel("Mean |SHAP Value|", color="white")
        ax.set_title(
            f"SHAP Feature Importance — {self.model_name}",
            color="white", fontsize=11,
        )
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_edgecolor("gray")

        fname = filename or f"shap_{self.model_name}.png"
        out_path = EXPLANATIONS_DIR / fname
        fig.savefig(out_path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        logger.debug("SHAP plot saved: %s", out_path)
        return out_path

    def _generate_text_explanation(
        self, top_features: list[tuple[str, float]]
    ) -> str:
        """Convert SHAP importances to human-readable text.

        Args:
            top_features: Sorted (feature, importance) pairs.

        Returns:
            Natural language explanation string.
        """
        if not top_features:
            return "No feature importance data available."
        top3 = top_features[:3]
        parts = [f"'{f}' (impact: {v:.4f})" for f, v in top3]
        return (
            f"The top contributing features for this prediction were: "
            f"{', '.join(parts)}. "
            f"Higher SHAP values indicate stronger influence on the threat classification."
        )


class LIMEExplainer:
    """Generates LIME explanations for any sklearn-compatible classifier.

    LIME perturbs the input and fits a locally linear model to approximate
    the decision boundary near the input point.

    Complements SHAP by providing a different perspective on feature importance.
    LIME is particularly useful for text-based models.

    Attributes:
        model: Trained model with predict_proba().
        feature_names: List of feature names.
        model_name: Human-readable model identifier.
        mode: 'tabular' or 'text'.
        num_features: Number of top features to include in explanation.
        num_samples: Number of perturbed samples for LIME fitting.
    """

    def __init__(
        self,
        model: Any,
        feature_names: list[str],
        model_name: str,
        mode: str = "tabular",
        num_features: int = 15,
        num_samples: int = 5000,
        training_data: Optional[np.ndarray] = None,
    ) -> None:
        self.model = model
        self.feature_names = feature_names
        self.model_name = model_name
        self.mode = mode
        self.num_features = num_features
        self.num_samples = num_samples
        self.training_data = training_data
        self._explainer: Optional[Any] = None
        self._init_explainer()

    def _init_explainer(self) -> None:
        """Initialise the LIME TabularExplainer or TextExplainer."""
        try:
            if self.mode == "tabular":
                from lime.lime_tabular import LimeTabularExplainer
                bg_data = (
                    self.training_data
                    if self.training_data is not None
                    else np.zeros((100, len(self.feature_names)))
                )
                self._explainer = LimeTabularExplainer(
                    training_data=bg_data,
                    feature_names=self.feature_names,
                    class_names=["Benign", "Threat"],
                    mode="classification",
                    random_state=42,
                )
            elif self.mode == "text":
                from lime.lime_text import LimeTextExplainer
                self._explainer = LimeTextExplainer(
                    class_names=["Legitimate", "Phishing"]
                )
            logger.info(
                "LIME %s Explainer initialised for: %s", self.mode, self.model_name
            )
        except Exception as exc:
            raise ExplainabilityError(
                "LIME", f"Explainer init failed: {exc}"
            ) from exc

    def explain(
        self,
        X: Union[np.ndarray, str],
        save_plot: bool = True,
        plot_filename: Optional[str] = None,
    ) -> ExplanationResult:
        """Generate LIME explanation for a single input instance.

        Args:
            X: Single sample — numpy array (tabular) or string (text).
            save_plot: Whether to save explanation plot.
            plot_filename: Override filename for saved plot.

        Returns:
            ExplanationResult with LIME feature weights.
        """
        try:
            if self.mode == "tabular":
                return self._explain_tabular(X, save_plot, plot_filename)
            else:
                return self._explain_text(X, save_plot, plot_filename)
        except ExplainabilityError:
            raise
        except Exception as exc:
            raise ExplainabilityError("LIME", str(exc)) from exc

    def _explain_tabular(self, X, save_plot, plot_filename) -> ExplanationResult:
        """Generate LIME explanation for tabular data."""
        if X.ndim == 2:
            X = X[0]
        exp = self._explainer.explain_instance(
            data_row=X,
            predict_fn=self.model.predict_proba,
            num_features=self.num_features,
            num_samples=self.num_samples,
            top_labels=1,
        )
        lime_weights = exp.as_list(label=1)
        feature_names = [w[0] for w in lime_weights]
        importances = [abs(w[1]) for w in lime_weights]
        top_features = sorted(
            zip(feature_names, importances), key=lambda x: x[1], reverse=True
        )

        plot_path = None
        if save_plot:
            plot_path = self._save_lime_plot(lime_weights, plot_filename)

        return ExplanationResult(
            model_name=self.model_name,
            method="lime",
            feature_names=feature_names,
            feature_importances=importances,
            top_features=list(top_features),
            plot_path=str(plot_path) if plot_path else None,
            raw_values=lime_weights,
            explanation_text=self._generate_text_explanation(list(top_features)),
        )

    def _explain_text(self, text: str, save_plot, plot_filename) -> ExplanationResult:
        """Generate LIME explanation for text data."""
        exp = self._explainer.explain_instance(
            text_instance=str(text),
            classifier_fn=self.model.predict_proba,
            num_features=self.num_features,
            num_samples=self.num_samples,
        )
        lime_weights = exp.as_list()
        feature_names = [w[0] for w in lime_weights]
        importances = [abs(w[1]) for w in lime_weights]
        top_features = sorted(
            zip(feature_names, importances), key=lambda x: x[1], reverse=True
        )
        return ExplanationResult(
            model_name=self.model_name,
            method="lime_text",
            feature_names=feature_names,
            feature_importances=importances,
            top_features=list(top_features),
            raw_values=lime_weights,
            explanation_text=self._generate_text_explanation(list(top_features)),
        )

    def _save_lime_plot(
        self, lime_weights: list, filename: Optional[str]
    ) -> Path:
        """Save LIME feature weight bar chart."""
        plt.style.use("dark_background")
        names = [w[0] for w in lime_weights[:self.num_features]]
        values = [w[1] for w in lime_weights[:self.num_features]]
        colors = ["#ff4b4b" if v > 0 else "#00c9a7" for v in values]

        fig, ax = plt.subplots(figsize=(10, max(4, len(names) * 0.4)))
        ax.barh(range(len(names)), values, color=colors)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=9)
        ax.set_xlabel("LIME Weight (positive=threat, negative=benign)", color="white")
        ax.set_title(
            f"LIME Explanation — {self.model_name}", color="white", fontsize=11
        )
        ax.axvline(x=0, color="white", linewidth=0.8, linestyle="--")
        ax.tick_params(colors="white")

        fname = filename or f"lime_{self.model_name}.png"
        out_path = EXPLANATIONS_DIR / fname
        fig.savefig(out_path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        return out_path

    def _generate_text_explanation(
        self, top_features: list[tuple[str, float]]
    ) -> str:
        """Convert LIME weights to human-readable explanation."""
        if not top_features:
            return "No LIME explanation available."
        top3 = top_features[:3]
        parts = [f"'{f}' (weight: {v:.4f})" for f, v in top3]
        return (
            f"LIME identified the following features as most influential: "
            f"{', '.join(parts)}. "
            f"Positive weights increase threat probability; "
            f"negative weights decrease it."
        )
