"""
classical_model.py — Classical ML Phishing Email Detector (Module 6)
======================================================================
Adaptive AI for Cyber Threat Detection

Implements Random Forest and Logistic Regression classifiers as
performance baselines against DistilBERT/BERT deep learning models.

IEEE 29148 FR: FR-PHI-001, FR-PHI-003

Author: B.Tech Capstone Project
"""

import time
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score

from src.core.base_model import BaseDetectionModel, ModelMetrics, PredictionResult
from src.core.constants import ModelAlgorithm, RANDOM_SEED, ThreatType
from src.core.exceptions import ModelInferenceError, ModelNotFoundError, ModelTrainingError
from src.core.logger import get_logger, get_model_logger

logger = get_logger(__name__)
model_logger = get_model_logger()


class RandomForestPhishingDetector(BaseDetectionModel):
    """Random Forest classifier for phishing email detection.

    Operates on TF-IDF + statistical features extracted by EmailFeatureExtractor.

    Attributes:
        clf: Fitted RandomForestClassifier instance.
    """

    MODEL_NAME = "random_forest_phishing_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.PHISHING_EMAIL,
            algorithm=ModelAlgorithm.RANDOM_FOREST,
        )
        self._model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=RANDOM_SEED,
            n_jobs=-1,
            class_weight="balanced",
        )

    def train(
        self,
        X_train: Any,
        y_train: Any,
        X_val: Optional[Any] = None,
        y_val: Optional[Any] = None,
    ) -> "RandomForestPhishingDetector":
        """Train the Random Forest classifier.

        Args:
            X_train: Feature matrix (numpy array or DataFrame).
            y_train: Binary labels.

        Returns:
            Self for method chaining.
        """
        try:
            start = time.time()
            model_logger.info(
                "Training RandomForest Phishing Detector on %d samples.",
                len(y_train),
            )
            self._model.fit(X_train, y_train)
            self._training_time = time.time() - start
            self.is_trained = True
            model_logger.info(
                "Training complete in %.2fs. Features: %d",
                self._training_time,
                self._model.n_features_in_,
            )
            return self
        except Exception as exc:
            raise ModelTrainingError(
                model_name=self.MODEL_NAME, reason=str(exc)
            ) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict phishing probability for a single feature vector.

        Args:
            X: Feature array of shape (1, n_features).

        Returns:
            PredictionResult with probability and risk score.
        """
        self._assert_trained()
        try:
            raw_output, latency_ms = self._timed_predict(X)
            phishing_prob = float(raw_output[0][1])
            return PredictionResult(
                threat_type=ThreatType.PHISHING_EMAIL,
                is_threat=phishing_prob >= 0.60,
                probability=phishing_prob,
                risk_score=phishing_prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.RANDOM_FOREST,
                inference_time_ms=latency_ms,
                raw_output=raw_output[0],
            )
        except Exception as exc:
            raise ModelInferenceError(
                model_name=self.MODEL_NAME, reason=str(exc)
            ) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Batch prediction."""
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.PHISHING_EMAIL,
                is_threat=bool(p[1] >= 0.60),
                probability=float(p[1]),
                risk_score=float(p[1]),
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.RANDOM_FOREST,
                raw_output=p,
            )
            for p in probs
        ]

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        """Evaluate with full metrics + cross-validation."""
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
        cv_scores = cross_val_score(
            self._model, X_test, y_test,
            cv=cv, scoring="f1_weighted", n_jobs=-1,
        )

        metrics = ModelMetrics(
            model_name=self.MODEL_NAME,
            algorithm=ModelAlgorithm.RANDOM_FOREST,
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_test, y_prob),
            test_samples=len(y_test),
            training_time_seconds=getattr(self, "_training_time", 0.0),
            cv_scores=cv_scores,
            confusion_matrix=confusion_matrix(y_test, y_pred),
        )
        self._metrics = metrics
        model_logger.info(
            "RF Phishing eval — Acc: %.4f | F1: %.4f | AUC: %.4f | CV: %.4f±%.4f",
            metrics.accuracy, metrics.f1_score, metrics.roc_auc,
            cv_scores.mean(), cv_scores.std(),
        )
        return metrics

    def save(self, path: Path) -> Path:
        """Save fitted model to disk."""
        self._assert_trained()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        model_path = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, model_path)
        logger.info("Model saved: %s", model_path)
        return model_path

    def load(self, path: Path) -> "RandomForestPhishingDetector":
        """Load saved model from disk."""
        model_path = Path(path)
        if not model_path.exists():
            raise ModelNotFoundError(str(model_path))
        self._model = joblib.load(model_path)
        self.is_trained = True
        return self


class LogisticRegressionPhishingDetector(BaseDetectionModel):
    """Logistic Regression baseline for phishing email classification."""

    MODEL_NAME = "logistic_regression_phishing_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.PHISHING_EMAIL,
            algorithm=ModelAlgorithm.LOGISTIC_REGRESSION,
        )
        self._model = LogisticRegression(
            C=1.0,
            max_iter=1000,
            solver="lbfgs",
            class_weight="balanced",
            random_state=RANDOM_SEED,
        )

    def train(self, X_train: Any, y_train: Any, X_val=None, y_val=None):
        try:
            start = time.time()
            self._model.fit(X_train, y_train)
            self._training_time = time.time() - start
            self.is_trained = True
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X: Any) -> PredictionResult:
        self._assert_trained()
        try:
            raw_output, latency_ms = self._timed_predict(X)
            prob = float(raw_output[0][1])
            return PredictionResult(
                threat_type=ThreatType.PHISHING_EMAIL,
                is_threat=prob >= 0.60,
                probability=prob,
                risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.LOGISTIC_REGRESSION,
                inference_time_ms=latency_ms,
                raw_output=raw_output[0],
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.PHISHING_EMAIL,
                is_threat=bool(p[1] >= 0.60),
                probability=float(p[1]),
                risk_score=float(p[1]),
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.LOGISTIC_REGRESSION,
                raw_output=p,
            )
            for p in probs
        ]

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]
        metrics = ModelMetrics(
            model_name=self.MODEL_NAME,
            algorithm=ModelAlgorithm.LOGISTIC_REGRESSION,
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_test, y_prob),
            test_samples=len(y_test),
            confusion_matrix=confusion_matrix(y_test, y_pred),
        )
        self._metrics = metrics
        return metrics

    def save(self, path: Path) -> Path:
        self._assert_trained()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        model_path = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, model_path)
        return model_path

    def load(self, path: Path) -> "LogisticRegressionPhishingDetector":
        model_path = Path(path)
        if not model_path.exists():
            raise ModelNotFoundError(str(model_path))
        self._model = joblib.load(model_path)
        self.is_trained = True
        return self
