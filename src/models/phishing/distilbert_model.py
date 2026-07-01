"""
distilbert_model.py — DistilBERT Phishing Email Detector (Module 6)
=====================================================================
Adaptive AI for Cyber Threat Detection

Fine-tunes DistilBERT for binary phishing email classification.
DistilBERT is 40% smaller and 60% faster than BERT while retaining
97% of its NLP performance (Sanh et al., 2019).

IEEE 29148 FR: FR-PHI-001, FR-PHI-003, FR-PHI-004

Author: B.Tech Capstone Project
"""

import time
from pathlib import Path
from typing import Any, Optional

import numpy as np

# Torch and transformers are imported lazily to allow the API to start
# even when torch is not installed (CPU-only inference mode).
try:
    import torch
    import torch.nn as nn
    from torch.optim import AdamW
    from torch.utils.data import DataLoader, Dataset
    from transformers import (
        DistilBertForSequenceClassification,
        DistilBertTokenizerFast,
        get_linear_schedule_with_warmup,
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
import pandas as pd

from src.core.base_model import BaseDetectionModel, ModelMetrics, PredictionResult
from src.core.constants import ModelAlgorithm, RANDOM_SEED, ThreatType
from src.core.exceptions import ModelInferenceError, ModelNotFoundError, ModelTrainingError
from src.core.logger import get_logger, get_model_logger
from src.core.config import ConfigManager

logger = get_logger(__name__)
model_logger = get_model_logger()


class EmailDataset(Dataset):
    """PyTorch Dataset for tokenised email texts.

    Attributes:
        encodings: HuggingFace BatchEncoding from tokeniser.
        labels: Tensor of integer labels (0 or 1).
    """

    def __init__(self, encodings: Any, labels: list[int]) -> None:
        self.encodings = encodings
        self.labels = labels

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


class DistilBERTPhishingDetector(BaseDetectionModel):
    """DistilBERT-based phishing email classifier.

    Inherits from BaseDetectionModel and implements all abstract methods.
    Supports both GPU (CUDA) and CPU inference — automatically selects device.

    Attributes:
        config: ConfigManager for hyperparameter access.
        device: torch.device (cuda or cpu).
        tokeniser: DistilBertTokenizerFast instance.
        model_hf: The HuggingFace DistilBertForSequenceClassification model.
        max_length: Maximum token sequence length.
    """

    MODEL_NAME = "distilbert_phishing_v1"

    def __init__(self) -> None:
        super().__init__(
            model_name=self.MODEL_NAME,
            threat_type=ThreatType.PHISHING_EMAIL,
            algorithm=ModelAlgorithm.DISTILBERT,
        )
        self.config = ConfigManager.get_instance()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.max_length: int = int(
            self.config.get("model_config.phishing.distilbert.max_length", default=256)
        )
        self.tokeniser: Optional[DistilBertTokenizerFast] = None
        self.model_hf: Optional[DistilBertForSequenceClassification] = None
        model_logger.info(
            "DistilBERT detector initialised. Device: %s | Max length: %d",
            self.device, self.max_length,
        )

    def _load_tokeniser(self) -> None:
        """Load DistilBERT tokeniser from HuggingFace Hub (cached locally)."""
        if not TORCH_AVAILABLE:
            return
        if self.tokeniser is None:
            hf_model = self.config.get(
                "model_config.phishing.distilbert.model_name",
                default="distilbert-base-uncased",
            )
            cache_dir = self.config.get(
                "HF_MODEL_CACHE_DIR", default="data/models/hf_cache"
            )
            logger.info("Loading tokeniser: %s", hf_model)
            self.tokeniser = DistilBertTokenizerFast.from_pretrained(
                hf_model, cache_dir=cache_dir
            )

    def train(
        self,
        X_train: Any,
        y_train: Any,
        X_val: Optional[Any] = None,
        y_val: Optional[Any] = None,
    ) -> "DistilBERTPhishingDetector":
        """Fine-tune DistilBERT on phishing email training data.

        Args:
            X_train: List or Series of email text strings.
            y_train: List or array of binary labels (0/1).
            X_val: Optional validation texts.
            y_val: Optional validation labels.

        Returns:
            Self for method chaining.

        Raises:
            ModelTrainingError: If training fails.
        """
        try:
            if not TORCH_AVAILABLE:
                raise ModelTrainingError(
                    self.MODEL_NAME,
                    "PyTorch is not installed. Run: pip install torch transformers"
                )
            self._load_tokeniser()
            cfg = self.config.get("model_config", {}).get("phishing", {}).get("distilbert", {})
            hf_model_name = cfg.get("model_name", "distilbert-base-uncased")
            batch_size = int(cfg.get("batch_size", 16))
            epochs = int(cfg.get("epochs", 3))
            lr = float(cfg.get("learning_rate", 2e-5))
            warmup_steps = int(cfg.get("warmup_steps", 500))
            weight_decay = float(cfg.get("weight_decay", 0.01))
            cache_dir = self.config.get("HF_MODEL_CACHE_DIR", "data/models/hf_cache")

            X_train_list = list(X_train)
            y_train_list = list(y_train)

            model_logger.info(
                "Training DistilBERT | Samples: %d | Epochs: %d | LR: %s | Device: %s",
                len(X_train_list), epochs, lr, self.device,
            )

            # Tokenise
            train_enc = self.tokeniser(
                X_train_list,
                truncation=True,
                padding=True,
                max_length=self.max_length,
            )
            train_dataset = EmailDataset(train_enc, y_train_list)
            train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

            # Load pretrained model
            self.model_hf = DistilBertForSequenceClassification.from_pretrained(
                hf_model_name,
                num_labels=2,
                cache_dir=cache_dir,
            ).to(self.device)

            optimizer = AdamW(
                self.model_hf.parameters(),
                lr=lr,
                weight_decay=weight_decay,
            )
            total_steps = len(train_loader) * epochs
            scheduler = get_linear_schedule_with_warmup(
                optimizer,
                num_warmup_steps=warmup_steps,
                num_training_steps=total_steps,
            )

            train_start = time.time()
            for epoch in range(epochs):
                self.model_hf.train()
                total_loss = 0.0
                for batch in train_loader:
                    optimizer.zero_grad()
                    input_ids = batch["input_ids"].to(self.device)
                    attention_mask = batch["attention_mask"].to(self.device)
                    labels = batch["labels"].to(self.device)
                    outputs = self.model_hf(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        labels=labels,
                    )
                    loss = outputs.loss
                    total_loss += loss.item()
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(self.model_hf.parameters(), 1.0)
                    optimizer.step()
                    scheduler.step()

                avg_loss = total_loss / len(train_loader)
                model_logger.info(
                    "Epoch %d/%d | Avg Loss: %.4f", epoch + 1, epochs, avg_loss
                )

            self._training_time = time.time() - train_start
            self.is_trained = True
            model_logger.info(
                "DistilBERT training complete in %.1fs.", self._training_time
            )
            return self

        except Exception as exc:
            raise ModelTrainingError(
                model_name=self.MODEL_NAME, reason=str(exc)
            ) from exc

    def predict(self, X: Any) -> PredictionResult:
        """Predict whether a single email text is phishing.

        Args:
            X: Single email text string.

        Returns:
            PredictionResult with phishing probability and risk score.
        """
        self._assert_trained()
        self._load_tokeniser()
        try:
            start = time.perf_counter()
            self.model_hf.eval()
            encoding = self.tokeniser(
                [str(X)],
                truncation=True,
                padding=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self.model_hf(
                    input_ids=encoding["input_ids"].to(self.device),
                    attention_mask=encoding["attention_mask"].to(self.device),
                )
            probs = torch.softmax(outputs.logits, dim=1).cpu().numpy()[0]
            phishing_prob = float(probs[1])
            latency_ms = (time.perf_counter() - start) * 1000

            threshold = float(
                self.config.get("thresholds.phishing.medium_risk", default=0.60)
            )
            return PredictionResult(
                threat_type=ThreatType.PHISHING_EMAIL,
                is_threat=phishing_prob >= threshold,
                probability=phishing_prob,
                risk_score=phishing_prob,
                model_name=self.MODEL_NAME,
                algorithm=ModelAlgorithm.DISTILBERT,
                inference_time_ms=latency_ms,
                raw_output=probs,
            )
        except Exception as exc:
            raise ModelInferenceError(
                model_name=self.MODEL_NAME, reason=str(exc)
            ) from exc

    def predict_batch(self, X: Any) -> list[PredictionResult]:
        """Predict for a batch of email texts."""
        return [self.predict(text) for text in X]

    def evaluate(self, X_test: Any, y_test: Any) -> ModelMetrics:
        """Evaluate DistilBERT on test set and compute all metrics.

        Args:
            X_test: List of email texts.
            y_test: True binary labels.

        Returns:
            ModelMetrics with accuracy, F1, ROC-AUC, confusion matrix.
        """
        self._assert_trained()
        results = self.predict_batch(X_test)
        y_pred = [int(r.is_threat) for r in results]
        y_prob = [r.probability for r in results]
        y_true = list(y_test)

        metrics = ModelMetrics(
            model_name=self.MODEL_NAME,
            algorithm=ModelAlgorithm.DISTILBERT,
            accuracy=accuracy_score(y_true, y_pred),
            precision=precision_score(y_true, y_pred, zero_division=0),
            recall=recall_score(y_true, y_pred, zero_division=0),
            f1_score=f1_score(y_true, y_pred, zero_division=0),
            roc_auc=roc_auc_score(y_true, y_prob),
            test_samples=len(y_true),
            training_samples=0,
            training_time_seconds=getattr(self, "_training_time", 0.0),
            confusion_matrix=confusion_matrix(y_true, y_pred),
        )
        self._metrics = metrics
        model_logger.info(
            "DistilBERT evaluation — Acc: %.4f | F1: %.4f | AUC: %.4f",
            metrics.accuracy, metrics.f1_score, metrics.roc_auc,
        )
        return metrics

    def save(self, path: Path) -> Path:
        """Save DistilBERT model and tokeniser to disk."""
        self._assert_trained()
        save_path = Path(path)
        save_path.mkdir(parents=True, exist_ok=True)
        self.model_hf.save_pretrained(str(save_path))
        self.tokeniser.save_pretrained(str(save_path))
        logger.info("DistilBERT saved to: %s", save_path)
        return save_path

    def load(self, path: Path) -> "DistilBERTPhishingDetector":
        """Load DistilBERT model and tokeniser from disk."""
        load_path = Path(path)
        if not load_path.exists():
            raise ModelNotFoundError(str(load_path))
        self.model_hf = DistilBertForSequenceClassification.from_pretrained(
            str(load_path)
        ).to(self.device)
        self.tokeniser = DistilBertTokenizerFast.from_pretrained(str(load_path))
        self.is_trained = True
        logger.info("DistilBERT loaded from: %s", load_path)
        return self
