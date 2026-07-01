"""
network_detector.py — Network Anomaly Detection (Module 9)
============================================================
Adaptive AI for Cyber Threat Detection

Implements XGBoost (primary) and Isolation Forest (unsupervised fallback)
on the NSL-KDD feature set for network intrusion detection.

NSL-KDD contains 41 features representing TCP/IP connection statistics.
Binary classification: 0=normal, 1=attack (DoS, Probe, R2L, U2R).

IEEE 29148 FR: FR-NET-001, FR-NET-002, FR-NET-003

Author: B.Tech Capstone Project
"""

import time
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
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


class XGBoostNetworkDetector(BaseDetectionModel):
    """XGBoost classifier for network anomaly/intrusion detection.

    Primary model for network threat detection.
    Trained on NSL-KDD 41-feature vectors.

    Attributes:
        _model: Fitted XGBClassifier.
    """

    MODEL_NAME = "xgboost_network_detector_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.NETWORK_ANOMALY,
            algorithm=ModelAlgorithm.XGBOOST,
        )
        self._model = XGBClassifier(
            n_estimators=400,
            max_depth=10,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
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
    ) -> "XGBoostNetworkDetector":
        """Train XGBoost on NSL-KDD feature matrix.

        Args:
            X_train: Feature matrix shape (n, 41).
            y_train: Binary labels (0=normal, 1=attack).
            X_val: Optional validation features.
            y_val: Optional validation labels.

        Returns:
            Self for method chaining.
        """
        try:
            start = time.time()
            model_logger.info(
                "Training XGBoost Network Detector on %d samples.", len(y_train)
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
            model_logger.info(
                "XGBoost Network training complete in %.2fs.", self._training_time
            )
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict network attack probability for a single connection.

        Args:
            X: Feature array shape (1, 41).

        Returns:
            PredictionResult with attack probability.
        """
        self._assert_trained()
        try:
            raw, ms = self._timed_predict(X)
            prob = float(raw[0][1])
            return PredictionResult(
                threat_type=ThreatType.NETWORK_ANOMALY,
                is_threat=prob >= 0.55,
                probability=prob,
                risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.XGBOOST,
                inference_time_ms=ms,
                raw_output=raw[0],
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Batch network prediction."""
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.NETWORK_ANOMALY,
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
        """Evaluate with full metrics and 5-fold cross-validation."""
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
        cv_scores = cross_val_score(
            self._model, X_test, y_test, cv=cv, scoring="f1_weighted", n_jobs=-1
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
            "XGBoost Network eval — Acc: %.4f | F1: %.4f | AUC: %.4f | CV: %.4f±%.4f",
            metrics.accuracy, metrics.f1_score, metrics.roc_auc,
            cv_scores.mean(), cv_scores.std(),
        )
        return metrics

    def save(self, path: Path) -> Path:
        """Save model artifact."""
        self._assert_trained()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        mp = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, mp)
        logger.info("Network XGBoost model saved: %s", mp)
        return mp

    def load(self, path: Path) -> "XGBoostNetworkDetector":
        """Load model artifact."""
        mp = Path(path)
        if not mp.exists():
            raise ModelNotFoundError(str(mp))
        self._model = joblib.load(mp)
        self.is_trained = True
        return self


class IsolationForestNetworkDetector(BaseDetectionModel):
    """Isolation Forest for unsupervised network anomaly detection.

    Used when no labelled network data is available (zero-day detection).
    contamination=0.05 → assumes 5% of traffic is anomalous.
    """

    MODEL_NAME = "isolation_forest_network_v1"

    def __init__(self, contamination: float = 0.05) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.NETWORK_ANOMALY,
            algorithm=ModelAlgorithm.ISOLATION_FOREST,
        )
        self.contamination = contamination
        self._model = IsolationForest(
            n_estimators=300,
            contamination=contamination,
            max_samples=256,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )

    def train(self, X_train: Any, y_train: Any = None,
              X_val=None, y_val=None) -> "IsolationForestNetworkDetector":
        """Fit on normal traffic. y_train is ignored (unsupervised)."""
        try:
            start = time.time()
            model_logger.info(
                "Training IsolationForest Network Detector on %d samples.", len(X_train)
            )
            self._model.fit(X_train)
            self._training_time = time.time() - start
            self.is_trained = True
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict anomaly score for a single network connection."""
        self._assert_trained()
        try:
            start = time.perf_counter()
            raw_score = float(self._model.score_samples(X)[0])
            prob = float(np.clip(1.0 - (raw_score + 0.7) / 0.8, 0.0, 1.0))
            is_anomaly = bool(self._model.predict(X)[0] == -1)
            ms = (time.perf_counter() - start) * 1000
            return PredictionResult(
                threat_type=ThreatType.NETWORK_ANOMALY,
                is_threat=is_anomaly,
                probability=prob, risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.ISOLATION_FOREST,
                inference_time_ms=ms,
                raw_output=np.array([raw_score]),
                metadata={"anomaly_score": raw_score},
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Batch anomaly detection for network connections."""
        self._assert_trained()
        raw_scores = self._model.score_samples(X)
        preds = self._model.predict(X)
        return [
            PredictionResult(
                threat_type=ThreatType.NETWORK_ANOMALY,
                is_threat=bool(pred == -1),
                probability=float(np.clip(1.0 - (s + 0.7) / 0.8, 0.0, 1.0)),
                risk_score=float(np.clip(1.0 - (s + 0.7) / 0.8, 0.0, 1.0)),
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.ISOLATION_FOREST,
                raw_output=np.array([s]),
            )
            for s, pred in zip(raw_scores, preds)
        ]

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        """Evaluate using labelled test data."""
        self._assert_trained()
        raw_preds = self._model.predict(X_test)
        y_pred = np.where(raw_preds == -1, 1, 0)
        raw_scores = self._model.score_samples(X_test)
        y_prob = np.clip(1.0 - (raw_scores + 0.7) / 0.8, 0.0, 1.0)

        metrics = ModelMetrics(
            model_name=self.MODEL_NAME,
            algorithm=ModelAlgorithm.ISOLATION_FOREST,
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_test, y_prob),
            test_samples=len(y_test),
            training_time_seconds=getattr(self, "_training_time", 0.0),
            confusion_matrix=confusion_matrix(y_test, y_pred),
        )
        self._metrics = metrics
        return metrics

    def save(self, path: Path) -> Path:
        self._assert_trained()
        path = Path(path); path.mkdir(parents=True, exist_ok=True)
        mp = path / f"{self.MODEL_NAME}.joblib"; joblib.dump(self._model, mp); return mp

    def load(self, path: Path) -> "IsolationForestNetworkDetector":
        mp = Path(path)
        if not mp.exists(): raise ModelNotFoundError(str(mp))
        self._model = joblib.load(mp); self.is_trained = True; return self
