# Software Requirements Specification (SRS)
## Adaptive AI for Cyber Threat Detection
### Version 1.0 | IEEE 29148:2018 Compliant

---

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification defines the functional and non-functional
requirements for the Adaptive AI for Cyber Threat Detection platform. This document
follows the IEEE 29148:2018 standard for systems and software engineering requirements.

### 1.2 Scope
The system detects four classes of cyber threats:
1. Phishing emails
2. Malicious URLs
3. Suspicious login behaviour
4. Network anomalies

### 1.3 Definitions and Acronyms
| Acronym | Definition |
|---------|------------|
| AI | Artificial Intelligence |
| ML | Machine Learning |
| DL | Deep Learning |
| XAI | Explainable Artificial Intelligence |
| SHAP | SHapley Additive exPlanations |
| LIME | Local Interpretable Model-agnostic Explanations |
| API | Application Programming Interface |
| SRS | Software Requirements Specification |
| FR | Functional Requirement |
| NFR | Non-Functional Requirement |

---

## 2. Overall Description

### 2.1 System Context
The platform operates as a cybersecurity analysis tool accepting inputs via:
- REST API endpoints (for programmatic integration)
- Web dashboard (for human analysts)

### 2.2 User Classes
| User Class | Description |
|------------|-------------|
| Security Analyst | Investigates threat alerts via dashboard |
| System Administrator | Configures models and thresholds |
| Developer | Integrates via REST API |
| Researcher | Evaluates model performance metrics |

---

## 3. Functional Requirements

### 3.1 Phishing Email Detection
| ID | Requirement |
|----|-------------|
| FR-PHI-001 | System shall classify email text as phishing or legitimate |
| FR-PHI-002 | System shall provide a confidence probability in [0, 1] |
| FR-PHI-003 | System shall support DistilBERT and BERT model variants |
| FR-PHI-004 | System shall explain predictions using SHAP token attribution |

### 3.2 Malicious URL Detection
| ID | Requirement |
|----|-------------|
| FR-URL-001 | System shall classify URLs as malicious or benign |
| FR-URL-002 | System shall extract lexical, host-based, and content features from URLs |
| FR-URL-003 | System shall support Random Forest and XGBoost models |
| FR-URL-004 | System shall provide SHAP feature importance for URL predictions |

### 3.3 Suspicious Login Behaviour Detection
| ID | Requirement |
|----|-------------|
| FR-LOG-001 | System shall detect anomalous login patterns |
| FR-LOG-002 | System shall use Isolation Forest for unsupervised detection |
| FR-LOG-003 | System shall flag logins from unusual geolocations or times |

### 3.4 Network Anomaly Detection
| ID | Requirement |
|----|-------------|
| FR-NET-001 | System shall detect anomalous network traffic patterns |
| FR-NET-002 | System shall classify network connections as normal or attack |
| FR-NET-003 | System shall support multiple attack categories |

### 3.5 Threat Fusion Engine
| ID | Requirement |
|----|-------------|
| FR-FUS-001 | System shall aggregate threat scores from all detection modules |
| FR-FUS-002 | System shall produce a composite risk score in [0, 1] |
| FR-FUS-003 | System shall classify composite risk as: Critical / High / Medium / Low / Info |

### 3.6 Explainability
| ID | Requirement |
|----|-------------|
| FR-XAI-001 | System shall generate SHAP explanations for every prediction |
| FR-XAI-002 | System shall generate LIME explanations for every prediction |
| FR-XAI-003 | Explanations shall identify top N contributing features |

### 3.7 Dashboard
| ID | Requirement |
|----|-------------|
| FR-DSH-001 | System shall display real-time threat alerts |
| FR-DSH-002 | System shall display model performance metrics |
| FR-DSH-003 | System shall provide downloadable PDF/CSV reports |
| FR-DSH-004 | Dashboard shall use a dark theme |

---

## 4. Non-Functional Requirements

### 4.1 Performance
| ID | Requirement |
|----|-------------|
| NFR-PER-001 | API inference latency shall be < 2000ms for URL/login/network models |
| NFR-PER-002 | BERT/DistilBERT inference latency shall be < 5000ms |
| NFR-PER-003 | Dashboard shall refresh in < 3 seconds |

### 4.2 Reliability
| ID | Requirement |
|----|-------------|
| NFR-REL-001 | API shall return structured error responses for all failure cases |
| NFR-REL-002 | System shall log all errors with stack traces |

### 4.3 Security
| ID | Requirement |
|----|-------------|
| NFR-SEC-001 | API keys and secrets shall be loaded from environment variables only |
| NFR-SEC-002 | All security events shall be logged to a dedicated audit log |
| NFR-SEC-003 | Input validation shall be applied to all API endpoints |

### 4.4 Maintainability
| ID | Requirement |
|----|-------------|
| NFR-MAI-001 | Code coverage shall be >= 80% |
| NFR-MAI-002 | All public functions shall have docstrings |
| NFR-MAI-003 | All configuration shall be in YAML files or environment variables |

### 4.5 Explainability (IEEE 7000)
| ID | Requirement |
|----|-------------|
| NFR-XAI-001 | Every prediction shall be accompanied by a human-readable explanation |
| NFR-XAI-002 | Model bias analysis shall be documented in the evaluation report |
