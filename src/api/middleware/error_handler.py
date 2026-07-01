"""
error_handler.py — Global Exception Middleware
================================================
Adaptive AI for Cyber Threat Detection

Catches all unhandled exceptions and returns structured JSON error responses
conforming to RFC 7807 Problem Details format.

Author: B.Tech Capstone Project
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.exceptions import CyberThreatBaseError
from src.core.logger import get_logger

logger = get_logger(__name__)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Middleware that catches all exceptions and returns JSON error responses."""

    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except CyberThreatBaseError as exc:
            logger.error("Application error: %s — %s", exc.error_code, exc.message)
            return JSONResponse(
                status_code=422,
                content=exc.to_dict(),
            )
        except Exception as exc:
            logger.error("Unhandled error: %s", exc, exc_info=True)
            return JSONResponse(
                status_code=500,
                content={
                    "error_code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred.",
                    "details": {},
                },
            )
