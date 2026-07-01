"""
login_detector.py — Suspicious Login Behaviour Detection (Module 8)
=====================================================================
Adaptive AI for Cyber Threat Detection

Uses Isolation Forest (unsupervised) as primary model — critical for
detecting zero-day login attacks where labelled anomaly data may not exist.
XGBoost serves as supervised comparison model when labels are available.

IEEE 29148 FR: FR-LOG-001, FR-LOG-002, FR-LOG-003

Author: B.Tech Capstone Project
"""

import time
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
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


class IsolationForestLoginDetector(BaseDetectionModel):
    """Isolation Forest for unsupervised login anomaly detection.

    Isolation Forest isolates anomalies by randomly partitioning features.
    Anomalous login events require fewer partitions to isolate (shorter paths).

    contamination=0.1 assumes ~10% of logins are anomalous — matches the
    synthetic dataset's class distribution.

    Attributes:
        _model: Fitted IsolationForest instance.
        contamination: Expected proportion of anomalies.
    """

    MODEL_NAME = "isolation_forest_login_v1"

    def __init__(self, contamination: float = 0.1) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.SUSPICIOUS_LOGIN,
            algorithm=ModelAlgorithm.ISOLATION_FOREST,
        )
        self.contamination = contamination
        self._model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples="auto",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )

    def train(
        self,
        X_train: Any,
        y_train: Any = None,
        X_val: Optional[Any] = None,
        y_val: Optional[Any] = None,
    ) -> "IsolationForestLoginDetector":
        """Fit Isolation Forest on training data.

        Note: Isolation Forest is unsupervised — y_train is ignored.
        It is accepted for API compatibility with BaseDetectionModel.

        Args:
            X_train: Feature matrix (labels not used).
            y_train: Ignored (unsupervised method).

        Returns:
            Self for method chaining.
        """
        try:
            start = time.time()
            model_logger.info(
                "Training IsolationForest Login Detector on %d samples.", len(X_train)
            )
            self._model.fit(X_train)
            self._training_time = time.time() - start
            self.is_trained = True
            model_logger.info("IsolationForest training complete in %.2fs.", self._training_time)
            return self
        except Exception as exc:
            raise ModelTrainingError(self.MODEL_NAME, str(exc)) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict anomaly score for a single login event.

        IsolationForest.score_samples() returns negative anomaly scores.
        We normalise to [0, 1] where 1 = most anomalous.

        Args:
            X: Feature array of shape (1, n_features).

        Returns:
            PredictionResult with anomaly probability.
        """
        self._assert_trained()
        try:
            start = time.perf_counter()
            # score_samples: more negative = more anomalous
            raw_score = self._model.score_samples(X)[0]
            # Normalise to probability: higher score = more anomalous
            # Typical IF scores range ~ [-0.7, 0.1]
            prob = float(np.clip(1.0 - (raw_score + 0.7) / 0.8, 0.0, 1.0))
            latency_ms = (time.perf_counter() - start) * 1000

            # IF predict() returns -1 (anomaly) or 1 (normal)
            is_anomaly = bool(self._model.predict(X)[0] == -1)

            return PredictionResult(
                threat_type=ThreatType.SUSPICIOUS_LOGIN,
                is_threat=is_anomaly,
                probability=prob,
                risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.ISOLATION_FOREST,
                inference_time_ms=latency_ms,
                raw_output=np.array([raw_score]),
                metadata={"anomaly_score": raw_score},
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Batch anomaly detection."""
        self._assert_trained()
        raw_scores = self._model.score_samples(X)
        predictions = self._model.predict(X)
        results = []
        for i, (score, pred) in enumerate(zip(raw_scores, predictions)):
            prob = float(np.clip(1.0 - (score + 0.7) / 0.8, 0.0, 1.0))
            results.append(PredictionResult(
                threat_type=ThreatType.SUSPICIOUS_LOGIN,
                is_threat=bool(pred == -1),
                probability=prob, risk_score=prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.ISOLATION_FOREST,
                raw_output=np.array([score]),
                metadata={"anomaly_score": float(score)},
            ))
        return results

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        """Evaluate using true labels (if available for benchmarking).

        Args:
            X_test: Test features.
            y_test: True labels (1=anomaly, 0=normal).
        """
        self._assert_trained()
        # Convert IF output: -1 (anomaly) → 1, 1 (normal) → 0
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
        model_logger.info(
            "IsolationForest Login eval — Acc: %.4f | F1: %.4f | AUC: %.4f",
            metrics.accuracy, metrics.f1_score, metrics.roc_auc,
        )
        return metrics

    def save(self, path: Path) -> Path:
        self._assert_trained()
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        mp = path / f"{self.MODEL_NAME}.joblib"
        joblib.dump(self._model, mp)
        logger.info("IsolationForest Login model saved: %s", mp)
        return mp

    def load(self, path: Path) -> "IsolationForestLoginDetector":
        mp = Path(path)
        if not mp.exists():
            raise ModelNotFoundError(str(mp))
        self._model = joblib.load(mp)
        self.is_trained = True
        return self


class XGBoostLoginDetector(BaseDetectionModel):
    """XGBoost supervised login anomaly detector (comparison model)."""

    MODEL_NAME = "xgboost_login_detector_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.SUSPICIOUS_LOGIN,
            algorithm=ModelAlgorithm.XGBOOST,
        )
        self._model = XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.85, colsample_bytree=0.85,
            use_label_encoder=False, eval_metric="logloss",
            random_state=RANDOM_SEED, n_jobs=-1, verbosity=0,
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
                threat_type=ThreatType.SUSPICIOUS_LOGIN,
                is_threat=prob >= 0.50, probability=prob, risk_score=prob,
                model_name=self.MODEL_NAME, algorithm=ModelAlgorithm.XGBOOST,
                inference_time_ms=ms, raw_output=raw[0],
            )
        except Exception as exc:
            raise ModelInferenceError(self.MODEL_NAME, str(exc)) from exc

    def predict_batch(self, X) -> list[PredictionResult]:
        self._assert_trained()
        probs = self._model.predict_proba(X)
        return [
            PredictionResult(
                threat_type=ThreatType.SUSPICIOUS_LOGIN,
                is_threat=bool(p[1] >= 0.50), probability=float(p[1]),
                risk_score=float(p[1]), model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.XGBOOST, raw_output=p,
            ) for p in probs
        ]

    def evaluate(self, X_test, y_test) -> ModelMetrics:
        self._assert_trained()
        y_pred = self._model.predict(X_test)
        y_prob = self._model.predict_proba(X_test)[:, 1]
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
        cv_scores = cross_val_score(self._model, X_test, y_test, cv=cv, scoring="f1_weighted")
        metrics = ModelMetrics(
            model_name=self.MODEL_NAME, algorithm=ModelAlgorithm.XGBOOST,
            accuracy=accuracy_score(y_test, y_pred),
            precision=precision_score(y_test, y_pred, zero_division=0),
            recall=recall_score(y_test, y_pred, zero_division=0),
            f1_score=f1_score(y_test, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_test, y_prob),
            test_samples=len(y_test), cv_scores=cv_scores,
            confusion_matrix=confusion_matrix(y_test, y_pred),
        )
        self._metrics = metrics
        return metrics

    def save(self, path: Path) -> Path:
        self._assert_trained()
        path = Path(path); path.mkdir(parents=True, exist_ok=True)
        mp = path / f"{self.MODEL_NAME}.joblib"; joblib.dump(self._model, mp); return mp

    def load(self, path: Path) -> "XGBoostLoginDetector":
        mp = Path(path)
        if not mp.exists(): raise ModelNotFoundError(str(mp))
        self._model = joblib.load(mp); self.is_trained = True; return self
