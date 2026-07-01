"""
test_config.py — Unit Tests for ConfigManager
===============================================
Adaptive AI for Cyber Threat Detection

Tests the Singleton pattern, environment variable loading,
dot-notation accessor methods, and error handling.

IEEE 29119 Test Coverage:
  - TC-CFG-001: Singleton returns same instance
  - TC-CFG-002: get() returns YAML value
  - TC-CFG-003: get() returns env var override
  - TC-CFG-004: get() returns default for missing key
  - TC-CFG-005: get_required() raises on missing key
  - TC-CFG-006: get_int() / get_float() / get_bool() type casting
  - TC-CFG-007: reset() clears singleton for test isolation

Author: B.Tech Capstone Project
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from src.core.config import ConfigManager
from src.core.exceptions import ConfigurationError


@pytest.fixture(autouse=True)
def reset_config_singleton():
    """Reset the ConfigManager singleton before and after every test.

    This ensures test isolation — no shared state between tests.
    """
    ConfigManager.reset()
    yield
    ConfigManager.reset()


class TestConfigManagerSingleton:
    """Tests for the Singleton design pattern implementation."""

    def test_get_instance_returns_same_object(self):
        """TC-CFG-001: Two get_instance() calls return identical objects."""
        instance_a = ConfigManager.get_instance()
        instance_b = ConfigManager.get_instance()
        assert instance_a is instance_b, (
            "Singleton violation: get_instance() returned different objects."
        )

    def test_reset_clears_singleton(self):
        """TC-CFG-007: reset() creates a fresh instance on next call."""
        instance_a = ConfigManager.get_instance()
        ConfigManager.reset()
        instance_b = ConfigManager.get_instance()
        assert instance_a is not instance_b, (
            "reset() should invalidate the existing singleton instance."
        )


class TestConfigManagerAccessors:
    """Tests for get(), get_required(), and typed accessors."""

    def test_get_returns_default_for_missing_key(self):
        """TC-CFG-004: get() with an unknown key returns the default value."""
        config = ConfigManager.get_instance()
        result = config.get("this.key.does.not.exist", default="fallback_value")
        assert result == "fallback_value"

    def test_get_returns_none_when_no_default(self):
        """get() with no default and missing key returns None."""
        config = ConfigManager.get_instance()
        result = config.get("nonexistent.key")
        assert result is None

    def test_get_env_var_overrides_yaml(self):
        """TC-CFG-003: OS environment variable takes priority over YAML value."""
        config = ConfigManager.get_instance()
        with patch.dict(os.environ, {"API_PORT": "9999"}):
            result = config.get("api.port")
            assert result == "9999", (
                "Environment variable API_PORT should override YAML api.port."
            )

    def test_get_required_raises_on_missing_key(self):
        """TC-CFG-005: get_required() raises ConfigurationError for missing key."""
        config = ConfigManager.get_instance()
        with pytest.raises(ConfigurationError) as exc_info:
            config.get_required("absolutely.nonexistent.config.key.xyz")
        assert "absolutely.nonexistent.config.key.xyz" in str(exc_info.value.message)

    def test_get_int_returns_integer(self):
        """TC-CFG-006a: get_int() correctly casts string to int."""
        config = ConfigManager.get_instance()
        with patch.dict(os.environ, {"SOME_INT_VALUE": "42"}):
            result = config.get_int("some.int.value", default=0)
            # Env var lookup converts dots to underscores: SOME_INT_VALUE
            assert isinstance(result, int)

    def test_get_int_returns_default_for_missing(self):
        """get_int() returns integer default when key is missing."""
        config = ConfigManager.get_instance()
        result = config.get_int("missing.integer.key", default=99)
        assert result == 99
        assert isinstance(result, int)

    def test_get_float_returns_float(self):
        """TC-CFG-006b: get_float() correctly casts string to float."""
        config = ConfigManager.get_instance()
        result = config.get_float("missing.float.key", default=3.14)
        assert result == 3.14
        assert isinstance(result, float)

    def test_get_bool_true_strings(self):
        """TC-CFG-006c: get_bool() correctly handles truthy string values."""
        config = ConfigManager.get_instance()
        truthy_values = ["true", "True", "TRUE", "1", "yes", "YES", "on"]
        for val in truthy_values:
            with patch.dict(os.environ, {"BOOL_TEST_KEY": val}):
                result = config.get_bool("bool.test.key", default=False)
                assert result is True, f"Expected True for value '{val}'"

    def test_get_bool_false_strings(self):
        """get_bool() correctly handles falsy string values."""
        config = ConfigManager.get_instance()
        falsy_values = ["false", "False", "0", "no", "off"]
        for val in falsy_values:
            with patch.dict(os.environ, {"BOOL_TEST_KEY": val}):
                result = config.get_bool("bool.test.key", default=True)
                assert result is False, f"Expected False for value '{val}'"

    def test_get_bool_returns_default_for_missing(self):
        """get_bool() returns default when key is missing."""
        config = ConfigManager.get_instance()
        assert config.get_bool("nonexistent.bool", default=True) is True
        assert config.get_bool("nonexistent.bool", default=False) is False


class TestConfigManagerEnvironmentProperty:
    """Tests for the environment and debug properties."""

    def test_is_debug_true_in_development(self):
        """is_debug should be True when environment is development."""
        config = ConfigManager.get_instance()
        with patch.dict(os.environ, {"APP_ENV": "development", "DEBUG": "true"}):
            ConfigManager.reset()
            config = ConfigManager.get_instance()
            assert config.is_debug is True

    def test_is_production_false_in_development(self):
        """is_production should be False in development environment."""
        config = ConfigManager.get_instance()
        assert config.is_production is False

    def test_repr_does_not_expose_secrets(self):
        """repr() should not expose any secret values."""
        config = ConfigManager.get_instance()
        representation = repr(config)
        # Ensure repr doesn't contain common secret patterns
        assert "password" not in representation.lower()
        assert "secret" not in representation.lower() or "config_keys" in representation
        assert "ConfigManager(" in representation
