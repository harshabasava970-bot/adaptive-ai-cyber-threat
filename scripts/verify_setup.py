"""
verify_setup.py — Project Setup Verification Script
=====================================================
Adaptive AI for Cyber Threat Detection

Run this script after cloning and configuring the project to verify:
  1. Python version is compatible
  2. All required packages are importable
  3. Configuration files exist and are parseable
  4. Required directories exist
  5. Environment variables are set (non-secret ones)
  6. Logging system initialises correctly

Usage:
    python scripts/verify_setup.py

Exit Codes:
    0 — All checks passed
    1 — One or more checks failed

Author: B.Tech Capstone Project
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path so we can import src
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _print_header(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _check(description: str, condition: bool, fix_hint: str = "") -> bool:
    """Print a check result and return whether it passed."""
    status = "✓ PASS" if condition else "✗ FAIL"
    print(f"  {status}  {description}")
    if not condition and fix_hint:
        print(f"         → {fix_hint}")
    return condition


def check_python_version() -> bool:
    """Verify Python 3.11 or higher is being used."""
    _print_header("Python Version Check")
    major, minor = sys.version_info.major, sys.version_info.minor
    passed = _check(
        f"Python {major}.{minor} (requires 3.11+)",
        major == 3 and minor >= 11,
        fix_hint="Install Python 3.11+ from https://python.org",
    )
    print(f"  Full version: {sys.version}")
    return passed


def check_required_packages() -> bool:
    """Attempt to import all critical production dependencies."""
    _print_header("Package Import Checks")

    packages = [
        ("fastapi", "FastAPI"),
        ("uvicorn", "Uvicorn"),
        ("pydantic", "Pydantic"),
        ("streamlit", "Streamlit"),
        ("sklearn", "Scikit-learn"),
        ("xgboost", "XGBoost"),
        ("torch", "PyTorch"),
        ("transformers", "HuggingFace Transformers"),
        ("shap", "SHAP"),
        ("lime", "LIME"),
        ("pandas", "Pandas"),
        ("numpy", "NumPy"),
        ("matplotlib", "Matplotlib"),
        ("plotly", "Plotly"),
        ("sqlalchemy", "SQLAlchemy"),
        ("dotenv", "python-dotenv"),
        ("yaml", "PyYAML"),
        ("tqdm", "tqdm"),
        ("loguru", "Loguru"),
        ("rich", "Rich"),
        ("reportlab", "ReportLab"),
        ("nltk", "NLTK"),
        ("tldextract", "tldextract"),
    ]

    all_passed = True
    for module_name, display_name in packages:
        try:
            __import__(module_name)
            passed = True
        except ImportError:
            passed = False
            all_passed = False
        _check(
            f"{display_name} ({module_name})",
            passed,
            fix_hint=f"Run: pip install -r requirements.txt",
        )

    return all_passed


def check_config_files() -> bool:
    """Verify all required YAML configuration files exist."""
    _print_header("Configuration File Checks")

    config_dir = PROJECT_ROOT / "config"
    required_files = [
        "settings.yaml",
        "model_config.yaml",
        "logging_config.yaml",
        "database_config.yaml",
    ]

    all_passed = True
    for filename in required_files:
        path = config_dir / filename
        passed = path.exists()
        if not passed:
            all_passed = False
        _check(
            f"config/{filename}",
            passed,
            fix_hint=f"File missing: {path}",
        )

    return all_passed


def check_env_file() -> bool:
    """Check for .env file existence."""
    _print_header("Environment File Check")

    env_path = PROJECT_ROOT / ".env"
    example_path = PROJECT_ROOT / ".env.example"

    env_exists = _check(
        ".env file present",
        env_path.exists(),
        fix_hint="Run: copy .env.example .env  (then edit it)",
    )
    _check(".env.example template present", example_path.exists())

    return env_exists


def check_directories() -> bool:
    """Verify required data and log directories exist or can be created."""
    _print_header("Directory Structure Check")

    required_dirs = [
        "src/core",
        "src/data",
        "src/models",
        "src/api",
        "src/dashboard",
        "src/explainability",
        "src/fusion",
        "src/reports",
        "src/database",
        "config",
        "data/raw",
        "data/processed",
        "data/models",
        "tests/unit",
        "tests/integration",
        "logs",
        "notebooks",
        "scripts",
        "docs",
    ]

    all_passed = True
    for rel_dir in required_dirs:
        path = PROJECT_ROOT / rel_dir
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        passed = path.exists() and path.is_dir()
        if not passed:
            all_passed = False
        _check(f"{rel_dir}/", passed)

    return all_passed


def check_core_imports() -> bool:
    """Verify the src.core package imports correctly."""
    _print_header("Core Package Import Check")

    checks = []

    try:
        from src.core.constants import ThreatType, RiskLevel, ModelAlgorithm
        checks.append(_check("src.core.constants", True))
    except Exception as e:
        checks.append(_check("src.core.constants", False, fix_hint=str(e)))

    try:
        from src.core.exceptions import CyberThreatBaseError, ModelNotTrainedError
        checks.append(_check("src.core.exceptions", True))
    except Exception as e:
        checks.append(_check("src.core.exceptions", False, fix_hint=str(e)))

    try:
        from src.core.config import ConfigManager
        _ = ConfigManager.get_instance()
        ConfigManager.reset()
        checks.append(_check("src.core.config (ConfigManager)", True))
    except Exception as e:
        checks.append(_check("src.core.config (ConfigManager)", False, fix_hint=str(e)))

    try:
        from src.core.logger import setup_logging, get_logger, reset_logging
        setup_logging()
        _ = get_logger("verify_setup")
        reset_logging()
        checks.append(_check("src.core.logger (setup_logging)", True))
    except Exception as e:
        checks.append(_check("src.core.logger (setup_logging)", False, fix_hint=str(e)))

    try:
        from src.core.base_model import BaseDetectionModel, PredictionResult, ModelMetrics
        checks.append(_check("src.core.base_model", True))
    except Exception as e:
        checks.append(_check("src.core.base_model", False, fix_hint=str(e)))

    return all(checks)


def main() -> int:
    """Run all verification checks and report results.

    Returns:
        Exit code: 0 for success, 1 for failure.
    """
    print("\n" + "=" * 60)
    print("  Adaptive AI for Cyber Threat Detection")
    print("  Project Setup Verification")
    print("=" * 60)

    results = [
        check_python_version(),
        check_directories(),
        check_config_files(),
        check_env_file(),
        check_required_packages(),
        check_core_imports(),
    ]

    total = len(results)
    passed = sum(results)
    failed = total - passed

    _print_header("Verification Summary")
    print(f"  Total checks : {total}")
    print(f"  Passed       : {passed}")
    print(f"  Failed       : {failed}")

    if failed == 0:
        print("\n  ✓ All checks passed. Your setup is ready.")
        print("  → Run: uvicorn src.api.main:app --reload")
        print("  → Run: streamlit run src/dashboard/app.py")
        return 0
    else:
        print(f"\n  ✗ {failed} check(s) failed. Please fix the issues above.")
        print("  → Common fix: pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
