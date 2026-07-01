"""
init_db.py — Database Initialisation Script
=============================================
Adaptive AI for Cyber Threat Detection

Creates the SQLite database file and all tables defined in the
database schema. Safe to run multiple times (idempotent).

Usage:
    python scripts/init_db.py

Author: B.Tech Capstone Project
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.logger import setup_logging, get_logger

setup_logging()
logger = get_logger(__name__)


def main() -> None:
    """Initialise the database schema."""
    logger.info("Database initialisation starting...")

    # Ensure data directory exists
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    db_path = data_dir / "threat_db.sqlite"
    logger.info("Database path: %s", db_path)

    # Database models will be imported from src.database once Module 2+
    # are implemented. For now, we confirm the data directory exists.
    logger.info(
        "Database directory ready. "
        "Full schema will be created in Module 2 (database models)."
    )
    print(f"\n✓ Data directory ready: {data_dir}")
    print(f"✓ Database will be created at: {db_path}")
    print("  Full schema initialisation will run in Module 2.")


if __name__ == "__main__":
    main()
