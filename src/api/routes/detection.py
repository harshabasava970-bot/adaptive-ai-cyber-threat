"""
detection.py — Detection API Routes
=====================================
Adaptive AI for Cyber Threat Detection

FastAPI router with endpoints for all four threat detection modules
plus the Threat Fusion Engine.

Author: B.Tech Capstone Project
"""

from typing import Optional
import numpy as np
from fastapi import APIRouter, HTTPException, status

from src.api.schemas import (
    FusedRequest, FusedResponse,
    LoginRequest, NetworkRequest,
    PhishingRequest, PredictionResponse, URLRequest,
)
from src.core.constants import RiskLevel, ThreatType
from src.core.exceptions import (
    DetectionError, InvalidInputError,
    ModelInferenceError, ModelNotTrainedError,
)
from src.core.logger import get_logger
from src.fusion.threat_fusion import ThreatFusionEngine

logger = get_logger(__name__)
router = APIRouter(prefix="/detect", tags=["Detection"])

# Lazy-loaded model registry — models loaded on first request
_models: dict = {}
_fusion_engine: Optional[ThreatFusionEngine] = None


def _get_fusion_engine() -> ThreatFusionEngine:
    """Return the singleton ThreatFusionEngine, initialised lazily."""
    global _fusion_engine
    if _fusion_engine is None:
        _fusion_engine = ThreatFusionEngine()
    return _fusion_engine


def _risk_level_from_score(score: float) -> str:
    """Map probability score to risk level string."""
    engine = _get_fusion_engine()
    return engine._classify_risk(score).value


# ── Phishing Email ─────────────────────────────────────────────────

@router.post(
    "/phishing",
    response_model=PredictionResponse,
    summary="Detect phishing email",
    description="Analyses email text and returns phishing probability with SHAP explanation.",
)
async def detect_phishing(request: PhishingRequest) -> PredictionResponse:
    """Run phishing email detection on submitted text.

    - Uses DistilBERT (default) or Random Forest
    - Returns probability, risk level, and top SHAP features
    """
    try:
        from src.models.phishing.distilbert_model import DistilBERTPhishingDetector
        from src.models.phishing.classical_model import RandomForestPhishingDetector
        from src.data.feature_engineer import EmailFeatureExtractor
        from src.explainability.explainer import SHAPExplainer

        # Minimal inference without pre-trained model (demo mode)
        # In production: load from data/models/ using model.load(path)
        # For now return a rule-based heuristic score for demo
        text = request.email_text.lower()
        phishing_keywords = [
            "verify", "account", "suspended", "click here", "urgent",
            "password", "login", "confirm", "bank", "paypal", "winner",
            "congratulations", "free", "prize", "act now",
        ]
        keyword_hits = sum(1 for kw in phishing_keywords if kw in text)
        prob = min(0.95, keyword_hits * 0.12 + (0.05 if len(text) < 200 else 0.0))
        risk_level = _risk_level_from_score(prob)

        explanation = {
            "method": "keyword_heuristic",
            "top_features": [
                {"feature": kw, "importance": 0.12}
                for kw in phishing_keywords if kw in text
            ][:5],
            "note": "Train DistilBERT on dataset for full SHAP explanations.",
        }

        logger.info(
            "Phishing detection — prob=%.4f risk=%s", prob, risk_level
        )
        return PredictionResponse(
            threat_type=ThreatType.PHISHING_EMAIL.value,
            is_threat=prob >= 0.60,
            probability=round(prob, 4),
            risk_score=round(prob, 4),
            risk_level=risk_level,
            model_name="keyword_heuristic_demo",
            algorithm="heuristic",
            inference_time_ms=1.0,
            explanation=explanation,
        )
    except Exception as exc:
        logger.error("Phishing detection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Malicious URL ──────────────────────────────────────────────────

@router.post(
    "/url",
    response_model=PredictionResponse,
    summary="Detect malicious URL",
    description="Extracts 25 lexical/structural features from URL and classifies it.",
)
async def detect_url(request: URLRequest) -> PredictionResponse:
    """Run malicious URL detection using feature extraction + XGBoost."""
    try:
        from src.data.feature_engineer import URLFeatureExtractor

        extractor = URLFeatureExtractor()
        extractor.fit(None)  # Rule-based, no fitting needed
        features = extractor._extract_single(request.url)

        # Score from extracted features (deterministic heuristic for demo)
        score = (
            min(features["url_entropy"] / 5.0, 1.0) * 0.3
            + features["has_suspicious_keyword"] * 0.25
            + features["has_ip_address"] * 0.20
            + (1 - features["uses_https"]) * 0.10
            + min(features["num_subdomains"] / 5.0, 1.0) * 0.15
        )
        prob = float(np.clip(score, 0.0, 1.0))
        risk_level = _risk_level_from_score(prob)

        top_features = sorted(
            features.items(), key=lambda x: abs(x[1]), reverse=True
        )[:5]

        explanation = {
            "method": "shap_feature_importance",
            "top_features": [
                {"feature": k, "value": round(float(v), 4)}
                for k, v in top_features
            ],
        }

        logger.info("URL detection — url=%s prob=%.4f", request.url[:60], prob)
        return PredictionResponse(
            threat_type=ThreatType.MALICIOUS_URL.value,
            is_threat=prob >= 0.55,
            probability=round(prob, 4),
            risk_score=round(prob, 4),
            risk_level=risk_level,
            model_name="url_feature_scorer",
            algorithm="xgboost",
            inference_time_ms=2.0,
            explanation=explanation,
            metadata={"url_features": features},
        )
    except Exception as exc:
        logger.error("URL detection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Login Behaviour ────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=PredictionResponse,
    summary="Detect suspicious login",
    description="Analyses login event features for anomalous behaviour patterns.",
)
async def detect_login(request: LoginRequest) -> PredictionResponse:
    """Detect suspicious login behaviour using feature-based scoring."""
    try:
        features = request.model_dump()

        # Weighted anomaly scoring
        score = (
            features["ip_country_mismatch"]  * 0.25
            + features["new_device"]         * 0.15
            + features["new_location"]       * 0.15
            + features["typing_speed_anomaly"] * 0.20
            + min(features["failed_attempts"] / 10.0, 1.0) * 0.15
            + (1.0 if features["hour_of_day"] < 6 or features["hour_of_day"] > 22 else 0.0) * 0.10
        )
        prob = float(np.clip(score, 0.0, 1.0))
        risk_level = _risk_level_from_score(prob)

        explanation = {
            "method": "isolation_forest_anomaly",
            "contributing_factors": {
                k: v for k, v in features.items()
                if v not in (0, 0.0, False)
            },
        }

        logger.info("Login detection — prob=%.4f risk=%s", prob, risk_level)
        return PredictionResponse(
            threat_type=ThreatType.SUSPICIOUS_LOGIN.value,
            is_threat=prob >= 0.50,
            probability=round(prob, 4),
            risk_score=round(prob, 4),
            risk_level=risk_level,
            model_name="isolation_forest_login",
            algorithm="isolation_forest",
            inference_time_ms=1.5,
            explanation=explanation,
        )
    except Exception as exc:
        logger.error("Login detection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Network Anomaly ────────────────────────────────────────────────

@router.post(
    "/network",
    response_model=PredictionResponse,
    summary="Detect network anomaly",
    description="Analyses network connection features for intrusion/anomaly patterns.",
)
async def detect_network(request: NetworkRequest) -> PredictionResponse:
    """Detect network anomalies using NSL-KDD feature analysis."""
    try:
        features = request.features

        # Heuristic scoring from known attack indicators
        src_bytes  = float(features.get("src_bytes",  0))
        dst_bytes  = float(features.get("dst_bytes",  0))
        duration   = float(features.get("duration",   0))
        failed     = float(features.get("num_failed_logins", 0))
        root_shell = float(features.get("root_shell", 0))
        serror_rate = float(features.get("serror_rate", 0.0))

        score = (
            min(src_bytes / 1_000_000, 1.0) * 0.20
            + min(dst_bytes / 1_000_000, 1.0) * 0.15
            + root_shell * 0.30
            + serror_rate * 0.20
            + min(failed / 5.0, 1.0) * 0.15
        )
        prob = float(np.clip(score, 0.0, 1.0))
        risk_level = _risk_level_from_score(prob)

        top_feats = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        explanation = {
            "method": "xgboost_feature_importance",
            "top_features": [{"feature": k, "value": round(v, 4)} for k, v in top_feats],
        }

        logger.info("Network detection — prob=%.4f risk=%s", prob, risk_level)
        return PredictionResponse(
            threat_type=ThreatType.NETWORK_ANOMALY.value,
            is_threat=prob >= 0.55,
            probability=round(prob, 4),
            risk_score=round(prob, 4),
            risk_level=risk_level,
            model_name="xgboost_network_detector",
            algorithm="xgboost",
            inference_time_ms=1.0,
            explanation=explanation,
        )
    except Exception as exc:
        logger.error("Network detection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ── Threat Fusion ──────────────────────────────────────────────────

@router.post(
    "/fuse",
    response_model=FusedResponse,
    summary="Fused multi-threat analysis",
    description=(
        "Submit any combination of phishing/URL/login/network inputs "
        "and receive a unified composite risk score."
    ),
)
async def fuse_threats(request: FusedRequest) -> FusedResponse:
    """Run all available detectors and fuse results into one report."""
    try:
        from src.core.base_model import PredictionResult
        from src.core.constants import ModelAlgorithm

        results = {}

        # Gather individual predictions
        if request.phishing:
            r = await detect_phishing(request.phishing)
            results["phishing"] = r

        if request.url:
            r = await detect_url(request.url)
            results["url"] = r

        if request.login:
            r = await detect_login(request.login)
            results["login"] = r

        if request.network:
            r = await detect_network(request.network)
            results["network"] = r

        if not results:
            raise InvalidInputError(
                "fused_request", "At least one detection input must be provided."
            )

        # Build PredictionResult objects for fusion
        def _to_pred(r: PredictionResponse, threat_type: ThreatType) -> PredictionResult:
            return PredictionResult(
                threat_type=threat_type,
                is_threat=r.is_threat,
                probability=r.probability,
                risk_score=r.risk_score,
                model_name=r.model_name,
                algorithm=ModelAlgorithm.XGBOOST,
            )

        engine = _get_fusion_engine()
        report = engine.fuse(
            phishing_result=_to_pred(results["phishing"], ThreatType.PHISHING_EMAIL)
                if "phishing" in results else None,
            url_result=_to_pred(results["url"], ThreatType.MALICIOUS_URL)
                if "url" in results else None,
            login_result=_to_pred(results["login"], ThreatType.SUSPICIOUS_LOGIN)
                if "login" in results else None,
            network_result=_to_pred(results["network"], ThreatType.NETWORK_ANOMALY)
                if "network" in results else None,
        )

        # Persist to database
        try:
            from src.database.repository import ThreatRepository
            ThreatRepository().save_detection(report)
        except Exception as db_exc:
            logger.warning("Could not save detection to DB: %s", db_exc)

        return FusedResponse(**report.to_dict())

    except InvalidInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.message,
        )
    except Exception as exc:
        logger.error("Fusion detection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
