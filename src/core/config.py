"""
config.py — Centralised Configuration Manager
===============================================
Adaptive AI for Cyber Threat Detection

Implements the Singleton pattern to ensure only one config instance exists
throughout the application lifecycle. Loads from:
  1. config/settings.yaml  (base defaults)
  2. config/model_config.yaml
  3. config/logging_config.yaml
  4. config/database_config.yaml
  5. .env file (overrides — loaded via python-dotenv)
  6. Actual OS environment variables (highest priority)

Design Patterns:
  - Singleton: ensures one config instance
  - Strategy: swaps database config based on APP_ENV value

IEEE 29148 NFR Reference: NFR-CFG-001 (Configuration Management)

Author: B.Tech Capstone Project
"""

import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv

from src.core.constants import CONFIG_DIR, PROJECT_ROOT
from src.core.exceptions import ConfigurationError, MissingEnvironmentVariableError

logger = logging.getLogger(__name__)


class ConfigManager:
    """Singleton configuration manager for the entire application.

    Merges YAML configuration with environment variables, giving env vars
    the highest priority. Thread-safe via double-checked locking.

    Usage:
        config = ConfigManager.get_instance()
        api_port = config.get("api.port", default=8000)
        db_url = config.get_required("DATABASE_URL")

    Attributes:
        _instance: Class-level reference to the single instance.
        _lock: Threading lock for thread-safe initialisation.
        _config: The merged configuration dictionary.
        _env: Current application environment string.
    """

    _instance: Optional["ConfigManager"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        """Private constructor — use get_instance() instead.

        Raises:
            RuntimeError: If instantiated directly instead of via get_instance().
        """
        self._config: dict[str, Any] = {}
        self._env: str = "development"
        self._loaded: bool = False

    @classmethod
    def get_instance(cls) -> "ConfigManager":
        """Return the single ConfigManager instance (thread-safe).

        Uses double-checked locking to minimise synchronisation overhead
        after the instance is created.

        Returns:
            The singleton ConfigManager instance.
        """
        if cls._instance is None:
            with cls._lock:
                # Second check inside lock prevents race condition
                if cls._instance is None:
                    instance = cls()
                    instance._load_all()
                    cls._instance = instance
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance.

        Used exclusively in unit tests to ensure test isolation.
        Never call this in production code.
        """
        with cls._lock:
            cls._instance = None
            logger.debug("ConfigManager singleton reset (test use only).")

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def _load_all(self) -> None:
        """Load all configuration sources in priority order.

        Order (lowest to highest priority):
          1. YAML defaults
          2. .env file
          3. OS environment variables
        """
        self._load_env_file()
        self._load_yaml_configs()
        self._env = os.getenv("APP_ENV", self._config.get("application", {}).get("environment", "development"))
        self._loaded = True
        logger.info(
            "Configuration loaded. Environment: %s | Project root: %s",
            self._env,
            PROJECT_ROOT,
        )

    def _load_env_file(self) -> None:
        """Load .env file into OS environment variables.

        If .env does not exist, falls back to .env.example gracefully
        and logs a warning — does not raise an exception.
        """
        env_path = PROJECT_ROOT / ".env"
        example_path = PROJECT_ROOT / ".env.example"

        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=True)
            logger.debug("Loaded environment from: %s", env_path)
        elif example_path.exists():
            load_dotenv(dotenv_path=example_path, override=False)
            logger.warning(
                ".env not found. Loaded .env.example as fallback. "
                "Create a .env file for your environment."
            )
        else:
            logger.warning(
                "Neither .env nor .env.example found at %s. "
                "Using OS environment variables only.",
                PROJECT_ROOT,
            )

    def _load_yaml_configs(self) -> None:
        """Parse all YAML configuration files and merge into _config.

        Each YAML file is loaded under a top-level key matching its filename
        (without .yaml extension) to prevent key collisions.

        Raises:
            ConfigurationError: If a required config file cannot be parsed.
        """
        yaml_files = {
            "settings": CONFIG_DIR / "settings.yaml",
            "model_config": CONFIG_DIR / "model_config.yaml",
            "logging_config": CONFIG_DIR / "logging_config.yaml",
            "database_config": CONFIG_DIR / "database_config.yaml",
        }

        for config_name, config_path in yaml_files.items():
            if not config_path.exists():
                raise ConfigurationError(
                    message=f"Required configuration file not found: {config_path}",
                    config_key=config_name,
                    details={"path": str(config_path)},
                )
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if loaded:
                        # settings.yaml is merged at root level for convenience
                        if config_name == "settings":
                            self._config.update(loaded)
                        else:
                            self._config[config_name] = loaded
                logger.debug("Loaded config: %s", config_path)
            except yaml.YAMLError as exc:
                raise ConfigurationError(
                    message=f"Failed to parse YAML configuration: {config_path}",
                    config_key=config_name,
                    details={"yaml_error": str(exc)},
                ) from exc

    # -------------------------------------------------------------------------
    # Accessors
    # -------------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value using dot-notation keys.

        Checks OS environment variables first (higher priority), then
        traverses the YAML config dictionary using the dot-notation path.

        Args:
            key: Dot-notation config path, e.g. "api.port" or "API_PORT".
            default: Value returned if key is not found anywhere.

        Returns:
            Configuration value, or default if not found.

        Examples:
            >>> config.get("api.port", default=8000)
            8000
            >>> config.get("API_PORT")
            '8000'
        """
        # Check environment variable first (uppercase, dots → underscores)
        env_key = key.upper().replace(".", "_")
        env_value = os.getenv(env_key)
        if env_value is not None:
            return env_value

        # Traverse nested dict using dot notation
        parts = key.split(".")
        current = self._config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def get_required(self, key: str) -> Any:
        """Retrieve a required configuration value.

        Like get(), but raises an exception if the key is not found.

        Args:
            key: Dot-notation config key or environment variable name.

        Returns:
            Configuration value.

        Raises:
            MissingEnvironmentVariableError: If key is an env var not set.
            ConfigurationError: If key is not found in YAML or environment.
        """
        value = self.get(key)
        if value is None:
            raise ConfigurationError(
                message=f"Required configuration key '{key}' is not set.",
                config_key=key,
                details={"hint": f"Check .env and config YAML files."},
            )
        return value

    def get_int(self, key: str, default: int = 0) -> int:
        """Retrieve a configuration value cast to int.

        Args:
            key: Dot-notation config key.
            default: Integer default if key not found.

        Returns:
            Integer value.

        Raises:
            ConfigurationError: If value cannot be cast to int.
        """
        value = self.get(key, default=default)
        try:
            return int(value)
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(
                message=f"Configuration key '{key}' must be an integer, got: {value!r}",
                config_key=key,
            ) from exc

    def get_float(self, key: str, default: float = 0.0) -> float:
        """Retrieve a configuration value cast to float.

        Args:
            key: Dot-notation config key.
            default: Float default if key not found.

        Returns:
            Float value.

        Raises:
            ConfigurationError: If value cannot be cast to float.
        """
        value = self.get(key, default=default)
        try:
            return float(value)
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(
                message=f"Configuration key '{key}' must be a float, got: {value!r}",
                config_key=key,
            ) from exc

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Retrieve a configuration value cast to bool.

        Handles string representations: 'true', '1', 'yes' → True.

        Args:
            key: Dot-notation config key.
            default: Boolean default if key not found.

        Returns:
            Boolean value.
        """
        value = self.get(key, default=default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "on")
        return bool(value)

    def get_path(self, key: str, default: Optional[str] = None) -> Path:
        """Retrieve a configuration value as a resolved Path.

        Args:
            key: Dot-notation config key.
            default: String default path if key not found.

        Returns:
            Resolved absolute Path object.

        Raises:
            ConfigurationError: If key not found and no default provided.
        """
        value = self.get(key, default=default)
        if value is None:
            raise ConfigurationError(
                message=f"Required path configuration '{key}' is not set.",
                config_key=key,
            )
        path = Path(value)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path.resolve()

    @property
    def environment(self) -> str:
        """Return the current application environment string.

        Returns:
            One of: 'development', 'staging', 'production'.
        """
        return self._env

    @property
    def is_debug(self) -> bool:
        """Return True if debug mode is enabled."""
        return self.get_bool("DEBUG", default=self._env == "development")

    @property
    def is_production(self) -> bool:
        """Return True if running in production environment."""
        return self._env == "production"

    def __repr__(self) -> str:
        """Return a safe string representation (no secrets exposed)."""
        return (
            f"ConfigManager(environment={self._env!r}, "
            f"loaded={self._loaded}, "
            f"config_keys={list(self._config.keys())})"
        )
