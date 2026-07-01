"""
main.py — FastAPI Application Entry Point
==========================================
Adaptive AI for Cyber Threat Detection

Creates and configures the FastAPI application with:
  - All detection routers (phishing, URL, login, network, fusion)
  - Analytics and report routers
  - Global error handling middleware
  - CORS configuration
  - Health check endpoint
  - OpenAPI documentation at /docs

Run with:
    uvicorn src.api.main:app --reload --port 8000

Author: B.Tech Capstone Project
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.middleware.error_handler import ErrorHandlerMiddleware
from src.api.routes import analytics, detection, reports
from src.api.schemas import HealthResponse
from src.core.config import ConfigManager
from src.core.constants import API_V1_PREFIX, APP_NAME, APP_VERSION
from src.core.logger import get_logger, setup_logging
from src.database.models import init_db

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager.

    Startup: initialise database, load configuration.
    Shutdown: clean up resources.
    """
    logger.info("=" * 55)
    logger.info("Starting %s v%s", APP_NAME, APP_VERSION)
    logger.info("=" * 55)

    # Initialise database tables
    try:
        init_db()
        logger.info("Database initialised.")
    except Exception as exc:
        logger.warning("Database init failed (non-fatal): %s", exc)

    yield  # Application runs here

    logger.info("Application shutdown complete.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    config = ConfigManager.get_instance()

    app = FastAPI(
        title="Adaptive AI Cyber Threat Detection API",
        description=(
            "Production-grade REST API for AI-powered cybersecurity threat detection. "
            "Detects phishing emails, malicious URLs, suspicious logins, and network anomalies "
            "using Machine Learning, Deep Learning, and Explainable AI.\n\n"
            "**IEEE 29148 / 29119 / 1012 / 7000 Compliant** | B.Tech Capstone Project 2025-2026"
        ),
        version=APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── Middleware ──────────────────────────────────────────────────
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8501",
            "http://localhost:3000",
            "https://harshabasava970-bot.streamlit.app",
            "*",  # Relaxed for development; tighten in production
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ─────────────────────────────────────────────────────
    app.include_router(detection.router, prefix=API_V1_PREFIX)
    app.include_router(analytics.router, prefix=API_V1_PREFIX)
    app.include_router(reports.router,   prefix=API_V1_PREFIX)

    # ── Health Check ─────────────────────────────────────────────────
    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["System"],
        summary="Health check",
    )
    async def health_check() -> HealthResponse:
        """Returns API health status. Used by Docker/Render health probes."""
        cfg = ConfigManager.get_instance()
        return HealthResponse(
            status="healthy",
            version=APP_VERSION,
            env=cfg.environment,
        )

    @app.get("/", tags=["System"], summary="API root")
    async def root():
        """API root — redirect info."""
        return {
            "name": APP_NAME,
            "version": APP_VERSION,
            "docs": "/docs",
            "health": "/health",
            "api": API_V1_PREFIX,
        }

    logger.info("FastAPI application created. Routes registered.")
    return app


# Create the app instance (used by uvicorn)
app = create_app()


def run() -> None:
    """Programmatic entry point for 'cyber-threat-api' CLI command."""
    import uvicorn
    config = ConfigManager.get_instance()
    uvicorn.run(
        "src.api.main:app",
        host=config.get("api.host", "0.0.0.0"),
        port=config.get_int("api.port", 8000),
        reload=config.get_bool("api.reload", True),
        log_level=config.get("api.log_level", "info"),
    )


if __name__ == "__main__":
    run()
