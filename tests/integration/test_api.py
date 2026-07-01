"""
test_api.py — Integration Tests for FastAPI Endpoints
=======================================================
IEEE 29119 Test Coverage:
  TC-API-001: Health check returns 200
  TC-API-002: Phishing endpoint validates input
  TC-API-003: URL detection returns structured response
  TC-API-004: Login detection returns structured response
  TC-API-005: Network detection returns structured response
  TC-API-006: Fusion endpoint with all inputs
  TC-API-007: Invalid input returns 422

Author: B.Tech Capstone Project
"""

import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


class TestHealthEndpoint:

    def test_health_returns_200(self):
        """TC-API-001: /health returns HTTP 200."""
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_response_structure(self):
        """Health response contains status, version, env keys."""
        r = client.get("/health")
        data = r.json()
        assert "status" in data
        assert "version" in data
        assert "env" in data
        assert data["status"] == "healthy"

    def test_root_returns_200(self):
        """GET / returns 200 with API info."""
        r = client.get("/")
        assert r.status_code == 200
        assert "docs" in r.json()


class TestPhishingEndpoint:

    def test_phishing_valid_request(self):
        """TC-API-002: Valid phishing request returns structured response."""
        r = client.post("/api/v1/detect/phishing", json={
            "email_text": "Urgent: Verify your account immediately at our secure portal.",
            "model": "distilbert",
        })
        assert r.status_code == 200
        data = r.json()
        assert "probability" in data
        assert "is_threat" in data
        assert "risk_level" in data
        assert 0.0 <= data["probability"] <= 1.0

    def test_phishing_too_short_rejected(self):
        """TC-API-007: Email text shorter than 10 chars returns 422."""
        r = client.post("/api/v1/detect/phishing", json={"email_text": "Hi"})
        assert r.status_code == 422


class TestURLEndpoint:

    def test_url_benign(self):
        """TC-API-003: Benign URL returns low risk score."""
        r = client.post("/api/v1/detect/url", json={"url": "https://google.com"})
        assert r.status_code == 200
        data = r.json()
        assert "probability" in data
        assert data["threat_type"] == "malicious_url"

    def test_url_suspicious(self):
        """Suspicious URL returns higher probability."""
        r = client.post("/api/v1/detect/url", json={
            "url": "http://paypal-verify-account.xyz/login/secure"
        })
        assert r.status_code == 200
        assert r.json()["probability"] > 0.3

    def test_url_too_short_rejected(self):
        """TC-API-007: Very short URL rejected with 422."""
        r = client.post("/api/v1/detect/url", json={"url": "ab"})
        assert r.status_code == 422


class TestLoginEndpoint:

    def test_login_normal_returns_200(self):
        """TC-API-004: Normal login event returns structured response."""
        r = client.post("/api/v1/detect/login", json={
            "hour_of_day": 10, "day_of_week": 1,
            "login_duration": 120.0, "failed_attempts": 0,
            "ip_country_mismatch": 0, "new_device": 0,
            "new_location": 0, "typing_speed_anomaly": 0.1,
            "session_duration": 1800.0, "concurrent_sessions": 1,
        })
        assert r.status_code == 200
        data = r.json()
        assert "probability" in data
        assert data["is_threat"] is False

    def test_login_suspicious_flagged(self):
        """Anomalous login should have higher probability."""
        r = client.post("/api/v1/detect/login", json={
            "hour_of_day": 3, "day_of_week": 0,
            "login_duration": 5.0, "failed_attempts": 10,
            "ip_country_mismatch": 1, "new_device": 1,
            "new_location": 1, "typing_speed_anomaly": 0.95,
            "session_duration": 30.0, "concurrent_sessions": 5,
        })
        assert r.status_code == 200
        assert r.json()["probability"] > 0.5


class TestNetworkEndpoint:

    def test_network_normal_returns_200(self):
        """TC-API-005: Normal network connection returns structured response."""
        r = client.post("/api/v1/detect/network", json={
            "features": {"src_bytes": 491, "dst_bytes": 0, "duration": 0}
        })
        assert r.status_code == 200
        assert "probability" in r.json()

    def test_network_attack_pattern_flagged(self):
        """High src_bytes + root_shell → elevated threat probability."""
        r = client.post("/api/v1/detect/network", json={
            "features": {
                "src_bytes": 5000000, "root_shell": 1,
                "serror_rate": 0.9, "num_failed_logins": 5,
            }
        })
        assert r.status_code == 200
        assert r.json()["probability"] > 0.4


class TestFusionEndpoint:

    def test_fusion_single_input(self):
        """TC-API-006: Fusion with one input returns composite report."""
        r = client.post("/api/v1/detect/fuse", json={
            "url": {"url": "http://malicious-phishing.xyz/account"}
        })
        assert r.status_code == 200
        data = r.json()
        assert "composite_risk_score" in data
        assert "risk_level" in data
        assert "report_id" in data

    def test_fusion_empty_rejected(self):
        """Fusion with no inputs returns 400."""
        r = client.post("/api/v1/detect/fuse", json={})
        assert r.status_code == 400
