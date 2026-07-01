"""
url_detector.py — Malicious URL Detection Models (Module 7)
=============================================================
Adaptive AI for Cyber Threat Detection

Implements XGBoost and Random Forest classifiers on the 25-feature
URL feature vectors extracted by URLFeatureExtractor.

XGBoost is the primary model (higher precision on URL datasets).
Random Forest serves as comparison baseline.

IEEE 29148 FR: FR-URL-001, FR-URL-003, FR-URL-004

Author: B.Tech Capstone Project
"""

import time
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

from src.core.base_model import BaseDetectionModel, ModelMetrics, PredictionResult
from src.core.constants import ModelAlgorithm, RANDOM_SEED, ThreatType
from src.core.exceptions import ModelInferenceError, ModelNotFoundError, ModelTrainingError
from src.core.logger import get_logger, get_model_logger

logger = get_logger(__name__)
model_logger = get_model_logger()


class XGBoostURLDetector(BaseDetectionModel):
    """XGBoost classifier for malicious URL detection.

    XGBoost outperforms Random Forest on URL datasets due to its ability
    to capture feature interactions (e.g., url_length × entropy).

    Attributes:
        _model: Fitted XGBClassifier instance.
    """

    MODEL_NAME = "xgboost_url_detector_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.MALICIOUS_URL,
            algorithm=ModelAlgorithm.XGBOOST,
        )
        self._model = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=RANDOM_SEED,
            n_jobs=-1,
            verbosity=0,
        )

    def train(
        self,
        X_train: Any,
        y_train: Any,
        X_val: Optional[Any] = None,
        y_val: Optional[Any] = None,
    ) -> "XGBoostURLDetector":
        """Fit XGBoost on URL feature matrix.

        Args:
            X_train: Feature matrix of shape (n_samples, 25).
            y_train: Binary labels (0=benign, 1=malicious).
            X_val: Optional validation features for early stopping.
            y_val: Optional validation labels.

        Returns:
            Self for method chaining.
        """
        try:
            start = time.time()
            model_logger.info(
                "Training XGBoost URL detector on %d samples.", len(y_train)
            )
            if X_val is not None and y_val is not None:
                self._model.fit(
                    X_train, y_train,
                    eval_set=[(X_val, y_val)],
                    verbose=False,
                )
            else:
                self._model.fit(X_train, y_train)

            self._training_time = time.time() - start
            self.is_trained = True
            model_logger.info("XGBoost URL training complete in %.2fs.", self._training_time)
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict malicious probability for a single URL feature vector.

        Args:
            X: Feature array of shape (1, 25).

        Returns:
            PredictionResult with malicious probability.
        """
        self._assert_trained()
        try:
            raw_output, latency_ms = self._timed_predict(X)
            mal_prob = float(raw_output[0][1])
            return PredictionResult(
                threat_type=ThreatType.MALICIOUS_URL,
                is_threat=mal_prob >= 0.55,
                probability=mal_prob,
                risk_score=mal_prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.XGBOOST,
                inference_time_ms=latency_ms,
                raw_output=raw_output[0],
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Batch URL prediction."""
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.MALICIOUS_URL,
                is_threat=bool(p[1] >= 0.55),
                probability=float(p[1]),
                risk_score=float(p[1]),
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.XGBOOST,
                raw_output=p,
            )
            for p in probs
        ]

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        """Evaluate XGBoost with full metrics and 5-fold CV."""
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
        cv_scores = cross_val_score(
            self._model, X_test, y_test, cv=cv, scoring="f1_weighted", n_jobs=-1,
        )

        metrics = ModelMetrics(
            model_name=self.MODEL_NAME,
            algorithm=ModelAlgorithm.XGBOOST,
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
            "XGBoost URL eval — Acc: %.4f | F1: %.4f | AUC: %.4f | CV: %.4f±%.4f",
            metrics.accuracy, metrics.f1_score, metrics.roc_auc,
            cv_scores.mean(), cv_scores.std(),
        )
        return metrics

    @property
    def feature_importances(self) -> Optional[np.ndarray]:
        """Return feature importance scores if model is trained."""
        if self.is_trained:
            return self._model.feature_importances_
        return None

    def save(self, path: Path) -> Path:
        """Persist model to disk."""
        self._assert_trained()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        model_path = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, model_path)
        logger.info("XGBoost URL model saved: %s", model_path)
        return model_path

    def load(self, path: Path) -> "XGBoostURLDetector":
        """Load model from disk."""
        model_path = Path(path)
        if not model_path.exists():
            raise ModelNotFoundError(str(model_path))
        self._model = joblib.load(model_path)
        self.is_trained = True
        return self


class RandomForestURLDetector(BaseDetectionModel):
    """Random Forest classifier for malicious URL detection (comparison model)."""

    MODEL_NAME = "random_forest_url_detector_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.MALICIOUS_URL,
            algorithm=ModelAlgorithm.RANDOM_FOREST,
        )
        self._model = RandomForestClassifier(
            n_estimators=300,
            max_depth=25,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=RANDOM_SEED,
            n_jobs=-1,
            class_weight="balanced",
        )

    def train(self, X_train, y_train, X_val=None, y_val=None):
        try:
            start = time.time()
            self._model.fit(X_train, y_train)
            self._training_time = time.time() - start
            self.is_trained = True
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X) -> PredictionResult:
        self._assert_trained()
        try:
            raw, ms = self._timed_predict(X)
            prob = float(raw[0][1])
            return PredictionResult(
                threat_type=ThreatType.MALICIOUS_URL,
                is_threat=prob >= 0.55,
                probability=prob, risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.RANDOM_FOREST,
                inference_time_ms=ms, raw_output=raw[0],
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X) -> list[PredictionResult]:
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.MALICIOUS_URL,
                is_threat=bool(p[1] >= 0.55), probability=float(p[1]),
                risk_score=float(p[1]), model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.RANDOM_FOREST, raw_output=p,
            )
            for p in probs
        ]

    def evaluate(self, X_test, y_test) -> ModelMetrics:
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]
        metrics = ModelMetrics(
            model_name=self.MODEL_NAME, algorithm=ModelAlgorithm.RANDOM_FOREST,
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
        mp = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, mp)
        return mp

    def load(self, path: Path) -> "RandomForestURLDetector":
        mp = Path(path)
        if not mp.exists():
            raise ModelNotFoundError(str(mp))
        self._model = joblib.load(mp)
        self.is_trained = True
        return self
