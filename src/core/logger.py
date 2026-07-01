"""
logger.py — Centralised Logging Setup
=======================================
Adaptive AI for Cyber Threat Detection

Provides a single initialisation function for the application-wide logging
system. Supports:
  - Rotating file handlers (app.log, error.log, security.log, model.log)
  - Coloured console output via Rich
  - JSON-structured log format (toggled by environment)
  - Per-module named loggers

Design Pattern: Factory Function (not a class — logging module manages state)

IEEE 29119: Logging is required for test traceability.
IEEE 29148 NFR-LOG-001: All security events must be logged with timestamps.

Usage:
    from src.core.logger import setup_logging, get_logger

    # Call once at application startup
    setup_logging()

    # In every module
    logger = get_logger(__name__)
    logger.info("Module initialised.")

Author: B.Tech Capstone Project
"""

import logging
import logging.config
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import yaml

from src.core.constants import CONFIG_DIR, LOGS_DIR

# Sentinel to prevent double-initialisation
_logging_configured: bool = False


def setup_logging(
    config_path: Optional[Path] = None,
    log_level: Optional[str] = None,
) -> None:
    """Initialise the application logging system.

    Loads logging configuration from logging_config.yaml. Creates all
    required log directories. Falls back to basic console logging if the
    config file is not found.

    This function is idempotent — calling it multiple times has no effect
    after the first successful call.

    Args:
        config_path: Override path to logging_config.yaml.
                     Defaults to config/logging_config.yaml.
        log_level: Override the root log level (e.g., "DEBUG", "INFO").
                   Useful for test environments.

    Side Effects:
        - Creates the logs/ directory if it does not exist.
        - Configures the Python logging system globally.

    Example:
        >>> setup_logging()
        >>> setup_logging(log_level="DEBUG")  # Override for debugging
    """
    global _logging_configured
    if _logging_configured:
        return

    # Ensure log directory exists
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Resolve config path
    resolved_config = config_path or (CONFIG_DIR / "logging_config.yaml")

    if resolved_config.exists():
        try:
            with open(resolved_config, "r", encoding="utf-8") as f:
                log_config = yaml.safe_load(f)

            # Override log level if explicitly provided (e.g., during testing)
            if log_level:
                log_config["root"]["level"] = log_level.upper()
                for logger_name in log_config.get("loggers", {}):
                    log_config["loggers"][logger_name]["level"] = log_level.upper()

            logging.config.dictConfig(log_config)

        except (yaml.YAMLError, KeyError, ValueError) as exc:
            # Config file exists but is malformed — fall back to basic config
            _configure_basic_logging(log_level or "DEBUG")
            logging.getLogger(__name__).warning(
                "Failed to load logging_config.yaml (%s). "
                "Using basic console logging.",
                exc,
            )
    else:
        _configure_basic_logging(log_level or "DEBUG")
        logging.getLogger(__name__).warning(
            "logging_config.yaml not found at %s. Using basic console logging.",
            resolved_config,
        )

    _logging_configured = True

    # Log startup confirmation
    startup_logger = logging.getLogger("src")
    startup_logger.info(
        "=" * 60,
    )
    startup_logger.info(
        "Adaptive AI for Cyber Threat Detection — Logging Initialised"
    )
    startup_logger.info(
        "Log directory: %s",
        LOGS_DIR,
    )
    startup_logger.info(
        "=" * 60,
    )


def _configure_basic_logging(level: str) -> None:
    """Configure a minimal console-only logging setup as fallback.

    Args:
        level: Logging level string (e.g., "DEBUG", "INFO").
    """
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.DEBUG),
        format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger for the given module.

    Convenience wrapper that ensures setup_logging() has been called
    before returning the logger.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        Configured Logger instance.

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Starting detection pipeline.")
    """
    if not _logging_configured:
        setup_logging()
    return logging.getLogger(name)


def get_security_logger() -> logging.Logger:
    """Return the dedicated security event logger.

    The security logger writes to logs/security.log with a longer
    retention period than the general application log.

    Returns:
        Logger configured for security audit events.

    Example:
        >>> sec_logger = get_security_logger()
        >>> sec_logger.warning("Phishing attempt detected from IP: %s", ip)
    """
    return logging.getLogger("src.security")


def get_model_logger() -> logging.Logger:
    """Return the dedicated model training/inference logger.

    Returns:
        Logger configured for ML model events.
    """
    return logging.getLogger("src.models")


def reset_logging() -> None:
    """Reset logging configuration.

    Used exclusively in unit tests to allow logging re-initialisation
    between test cases. Never call this in production.
    """
    global _logging_configured
    _logging_configured = False
    # Remove all handlers from all loggers
    for name in list(logging.Logger.manager.loggerDict.keys()):
        log = logging.getLogger(name)
        log.handlers.clear()
    logging.root.handlers.clear()
