# 🛡️ Adaptive AI for Cyber Threat Detection

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32-ff4b4b.svg)](https://streamlit.io/)
[![Tests](https://img.shields.io/badge/Tests-87%20Passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![IEEE](https://img.shields.io/badge/IEEE-29148%20%7C%2029119%20%7C%207000-blue.svg)](docs/)
[![Live API](https://img.shields.io/badge/API-Live%20on%20Render-success.svg)](https://cyber-threat-api-4gms.onrender.com/health)
[![Dashboard](https://img.shields.io/badge/Dashboard-Live%20on%20Streamlit-ff4b4b.svg)](https://cyber-threat-ai.streamlit.app)

---

## 🌐 Live Deployment

| Resource | URL |
|----------|-----|
| 🔗 **Source Code** | https://github.com/harshabasava970-bot/adaptive-ai-cyber-threat |
| ⚡ **Live API** | https://cyber-threat-api-4gms.onrender.com |
| 📖 **Interactive API Docs** | https://cyber-threat-api-4gms.onrender.com/docs |
| 🛡️ **Live Dashboard** | https://cyber-threat-ai.streamlit.app |

> **Note:** The free Render API may take 30 seconds to wake up on first visit. Subsequent requests are instant.

---

## 📋 Overview

**Adaptive AI for Cyber Threat Detection** is a production-grade, intelligent cybersecurity platform that uses Machine Learning, Deep Learning (Transformers), and Explainable AI to detect multiple categories of cyber threats in real time.

Built as a **Final Year B.Tech Capstone Project** in Computer Science Engineering. Structured for **IEEE/Springer publication** and compliant with IEEE 29148, IEEE 29119, IEEE 1012, and IEEE 7000 standards.

---

## 🎯 What It Detects

| # | Threat Type | Algorithm | Dataset |
|---|-------------|-----------|---------|
| 1 | **Phishing Emails** | DistilBERT + BERT + Random Forest | HuggingFace Phishing Dataset |
| 2 | **Malicious URLs** | XGBoost + Random Forest (25 features) | PhiUSIIL UCI Dataset |
| 3 | **Suspicious Login Behaviour** | Isolation Forest + XGBoost | Synthetic (50,000 samples) |
| 4 | **Network Anomalies** | XGBoost + Isolation Forest | NSL-KDD (125,973 samples) |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────┐
│                   PRESENTATION LAYER                        │
│     Streamlit Dashboard    │    FastAPI REST API            │
├────────────────────────────────────────────────────────────┤
│                   APPLICATION LAYER                         │
│   Threat Fusion Engine  │  Report Generator  │  Alerts      │
├────────────────────────────────────────────────────────────┤
│                    INFERENCE LAYER                          │
│  Phishing  │  Malicious URL  │  Login Behaviour │  Network  │
├────────────────────────────────────────────────────────────┤
│                      ML/DL LAYER                            │
│  DistilBERT │ BERT │ XGBoost │ Random Forest │ Iso Forest  │
├────────────────────────────────────────────────────────────┤
│                  EXPLAINABILITY LAYER                       │
│            SHAP TreeExplainer  │  LIME TabularExplainer     │
├────────────────────────────────────────────────────────────┤
│                      DATA LAYER                             │
│    Downloader │ Cleaner │ EDA │ Feature Engineer │ SQLite   │
└────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Local)

```bash
# 1. Clone
git clone https://github.com/harshabasava970-bot/adaptive-ai-cyber-threat.git
cd adaptive-ai-cyber-threat

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env

# 5. Verify setup
python scripts/verify_setup.py

# 6. Run API
uvicorn main:app --reload --port 8000

# 7. Run Dashboard (new terminal)
streamlit run src/dashboard/app.py
```

---

## 📁 Project Structure

```
adaptive-ai-cyber-threat/
├── config/                    # YAML configuration files
│   ├── settings.yaml          # App-wide settings & thresholds
│   ├── model_config.yaml      # ML/DL hyperparameters
│   ├── logging_config.yaml    # Rotating log handlers
│   └── database_config.yaml   # SQLite/PostgreSQL config
├── src/
│   ├── core/                  # Config, logging, exceptions, base model
│   ├── data/                  # Downloader, cleaner, EDA, feature engineering
│   ├── models/
│   │   ├── phishing/          # DistilBERT + BERT + RF + LR
│   │   ├── malicious_url/     # XGBoost + Random Forest
│   │   ├── login_behaviour/   # Isolation Forest + XGBoost
│   │   └── network_anomaly/   # XGBoost + Isolation Forest
│   ├── fusion/                # Threat Fusion Engine
│   ├── explainability/        # SHAP + LIME explainers
│   ├── api/                   # FastAPI routes, schemas, middleware
│   ├── dashboard/             # Streamlit dark-theme dashboard
│   ├── reports/               # PDF + CSV report generator
│   └── database/              # SQLAlchemy models + repository
├── tests/
│   ├── unit/                  # 75 unit tests
│   └── integration/           # 12 integration tests
├── docs/
│   ├── requirements/SRS.md    # IEEE 29148 SRS
│   └── deployment_guide.md    # Step-by-step deploy guide
├── scripts/
│   ├── verify_setup.py        # Setup verification
│   └── init_db.py             # Database initialisation
├── main.py                    # Root entry point (Render.com)
├── requirements.txt           # Production dependencies
├── Dockerfile                 # Container definition
├── docker-compose.yml         # Multi-service orchestration
├── render.yaml                # Render.com deployment config
└── .github/workflows/ci.yml   # GitHub Actions CI/CD
```

---

## 🔌 API Endpoints

```
GET  /health                          → Health check
GET  /docs                            → Swagger UI (interactive)
POST /api/v1/detect/phishing          → Phishing email detection
POST /api/v1/detect/url               → Malicious URL detection
POST /api/v1/detect/login             → Suspicious login detection
POST /api/v1/detect/network           → Network anomaly detection
POST /api/v1/detect/fuse              → Multi-threat fusion
GET  /api/v1/analytics/recent         → Recent detections
GET  /api/v1/analytics/metrics        → Model performance
GET  /api/v1/analytics/threat-counts  → Threat distribution
GET  /api/v1/reports/csv              → Download CSV report
GET  /api/v1/reports/pdf              → Download PDF report
```

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ --override-ini="addopts=" -v

# Unit tests only
python -m pytest tests/unit/ --override-ini="addopts=" -v

# Integration tests only
python -m pytest tests/integration/ --override-ini="addopts=" -v
```

**Results: 87/87 tests passing ✅**

---

## 📊 Risk Classification

| Level | Score | Action |
|-------|-------|--------|
| 🔴 CRITICAL | 0.85–1.00 | Immediate escalation |
| 🟠 HIGH | 0.65–0.84 | Security team alert |
| 🟡 MEDIUM | 0.45–0.64 | Investigate |
| 🟢 LOW | 0.25–0.44 | Monitor |
| 🔵 INFO | 0.00–0.24 | No action |

---

## 📜 IEEE Standards Compliance

| Standard | Coverage |
|----------|----------|
| **IEEE 29148** | Software Requirements Specification (`docs/requirements/SRS.md`) |
| **IEEE 29119** | Test plan, 87 test cases, coverage report |
| **IEEE 1012** | Model verification via accuracy, F1, ROC-AUC, 5-fold CV |
| **IEEE 7000** | AI transparency via SHAP + LIME for every prediction |

---

## 🛠️ Tech Stack

`Python 3.11` `FastAPI` `Streamlit` `PyTorch` `HuggingFace Transformers`
`Scikit-learn` `XGBoost` `Isolation Forest` `SHAP` `LIME`
`Pandas` `NumPy` `Plotly` `SQLAlchemy` `SQLite`
`ReportLab` `GitHub Actions` `Render.com` `Streamlit Cloud` `Docker`

---

## 👨‍💻 Author

**B.Tech Final Year Capstone Project**
Department of Computer Science Engineering
Academic Year 2025–2026

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
