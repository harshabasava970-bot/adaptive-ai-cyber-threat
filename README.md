# Adaptive AI for Cyber Threat Detection

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2+-red.svg)](https://pytorch.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-ff4b4b.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![IEEE](https://img.shields.io/badge/Standard-IEEE%2029148-blue.svg)](https://standards.ieee.org/)

---

## Overview

**Adaptive AI for Cyber Threat Detection** is an intelligent, production-grade cybersecurity
platform that leverages Machine Learning, Deep Learning (Transformer-based NLP), and Explainable
AI (XAI) to detect, classify, and explain multiple categories of cyber threats in real time.

This project is developed as a Final Year B.Tech Capstone Project in Computer Science Engineering
and is structured to meet IEEE publication standards (IEEE 29148, IEEE 29119, IEEE 1012, IEEE 7000).

---

## Threat Detection Capabilities

| Module | Threat Type              | Core Algorithm                    |
|--------|--------------------------|-----------------------------------|
| 6      | Phishing Email Detection | DistilBERT + BERT Fine-tuning     |
| 7      | Malicious URL Detection  | Random Forest + XGBoost           |
| 8      | Suspicious Login Behaviour | Isolation Forest + Logistic Reg. |
| 9      | Network Anomaly Detection | XGBoost + Isolation Forest       |
| 10     | Threat Fusion Engine     | Ensemble Scoring + Risk Aggregation |

---

## Key Features

- Multi-threat Detection across 4 cybersecurity domains
- Explainable AI (SHAP + LIME) for every prediction
- Real-time Streamlit dark-theme dashboard
- FastAPI REST backend with auto OpenAPI docs
- Composite risk scoring engine
- PDF/CSV report generation with audit trails
- SOLID architecture — fully modular and extensible
- IEEE 29148 / 29119 / 1012 / 7000 compliant

---

## Quick Start

```bash
# Clone
git clone https://github.com/<your-username>/adaptive-ai-cyber-threat.git
cd adaptive-ai-cyber-threat

# Virtual environment (Windows)
python -m venv .venv
.venv\Scripts\activate

# Install
pip install -r requirements.txt

# Configure
copy .env.example .env

# Verify setup
python scripts/verify_setup.py

# Run API
uvicorn src.api.main:app --reload --port 8000

# Run Dashboard (new terminal)
streamlit run src/dashboard/app.py
```

---

## Deployment (All Free)

| Component          | Platform            | URL                                      |
|--------------------|---------------------|------------------------------------------|
| FastAPI Backend    | Render.com          | https://your-app.onrender.com            |
| API Docs           | Render.com          | https://your-app.onrender.com/docs       |
| Streamlit Dashboard | Streamlit Cloud    | https://your-app.streamlit.app           |
| Model Storage      | Hugging Face Hub    | https://huggingface.co/your-username     |

See `docs/deployment_guide.md` for step-by-step beginner instructions.

---

## IEEE Standards Compliance

| Standard   | Coverage                                              |
|------------|-------------------------------------------------------|
| IEEE 29148 | Software Requirements Specification in docs/requirements/ |
| IEEE 29119 | Test plan, test cases, test reports in tests/         |
| IEEE 1012  | Verification and validation plan                      |
| IEEE 7000  | AI ethics, explainability via SHAP/LIME               |

---

## License

MIT License — See LICENSE file for details.

## Author

B.Tech Final Year Capstone Project
Department of Computer Science Engineering
Academic Year 2025-2026
