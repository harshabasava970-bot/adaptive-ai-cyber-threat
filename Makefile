# =============================================================================
# Makefile — Developer Workflow Automation
# Adaptive AI for Cyber Threat Detection
# =============================================================================
# Usage:
#   make setup      — create venv and install all deps
#   make verify     — run setup verification
#   make test       — run full test suite with coverage
#   make lint       — run all linters
#   make format     — auto-format code
#   make api        — start FastAPI development server
#   make dashboard  — start Streamlit dashboard
#   make clean      — clean build artifacts
# =============================================================================

PYTHON = python
PIP = pip
VENV = .venv
SRC = src
TESTS = tests

.PHONY: all setup verify install install-dev test test-unit test-integration \
        lint format type-check security-check api dashboard clean help

# Default target
all: verify

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV)\Scripts\pip install --upgrade pip
	$(VENV)\Scripts\pip install -r requirements-dev.txt
	copy .env.example .env
	$(PYTHON) scripts/verify_setup.py

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements-dev.txt

verify:
	$(PYTHON) scripts/verify_setup.py

init-db:
	$(PYTHON) scripts/init_db.py

# ---------------------------------------------------------------------------
# Testing (IEEE 29119)
# ---------------------------------------------------------------------------
test:
	pytest $(TESTS) -v --cov=$(SRC) --cov-report=html --cov-report=term-missing

test-unit:
	pytest $(TESTS)/unit -v -m "unit"

test-integration:
	pytest $(TESTS)/integration -v -m "integration"

test-fast:
	pytest $(TESTS) -v -m "not slow and not model" --no-cov

# ---------------------------------------------------------------------------
# Code Quality
# ---------------------------------------------------------------------------
lint:
	flake8 $(SRC) $(TESTS) --max-line-length=88 --extend-ignore=E203
	pylint $(SRC) --fail-under=8.0

format:
	black $(SRC) $(TESTS)
	isort $(SRC) $(TESTS)

type-check:
	mypy $(SRC) --ignore-missing-imports

security-check:
	bandit -r $(SRC) -ll

# ---------------------------------------------------------------------------
# Run Services
# ---------------------------------------------------------------------------
api:
	uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

dashboard:
	streamlit run src/dashboard/app.py --server.port 8501

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	if exist __pycache__ rmdir /s /q __pycache__
	if exist .pytest_cache rmdir /s /q .pytest_cache
	if exist htmlcov rmdir /s /q htmlcov
	if exist .coverage del .coverage
	for /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help:
	@echo Available targets:
	@echo   setup          - Create virtual env and install dependencies
	@echo   verify         - Run project setup verification
	@echo   install        - Install production dependencies only
	@echo   install-dev    - Install all dependencies including dev tools
	@echo   init-db        - Initialise the SQLite database
	@echo   test           - Run all tests with coverage report
	@echo   test-unit      - Run unit tests only
	@echo   test-fast      - Run tests excluding slow/model tests
	@echo   lint           - Run flake8 and pylint
	@echo   format         - Auto-format with black and isort
	@echo   type-check     - Run mypy static type analysis
	@echo   security-check - Run bandit security analysis
	@echo   api            - Start FastAPI development server
	@echo   dashboard      - Start Streamlit dashboard
	@echo   clean          - Remove build/cache artifacts
