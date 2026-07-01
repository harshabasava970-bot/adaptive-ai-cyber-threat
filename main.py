"""
main.py — Root-level entry point for Render.com deployment.

Render looks for the app at the project root.
This file simply re-exports the FastAPI app from src.api.main.
"""
import sys
import os

# Ensure project root is on the Python path
sys.path.insert(0, os.path.dirname(__file__))

from src.api.main import app  # noqa: F401 — re-exported for uvicorn

__all__ = ["app"]
