"""
test_feature_engineer.py — Unit Tests for Feature Engineering
===============================================================
IEEE 29119 Test Coverage:
  TC-FE-001: URL features return correct count
  TC-FE-002: Entropy computed for known strings
  TC-FE-003: HTTPS detection works
  TC-FE-004: IP address detection
  TC-FE-005: Suspicious keyword detection

Author: B.Tech Capstone Project
"""

import numpy as np
import pytest
from src.data.feature_engineer import URLFeatureExtractor


@pytest.fixture
def extractor():
    ext = URLFeatureExtractor()
    ext.fit(None)
    return ext


class TestURLFeatureExtractor:

    def test_returns_correct_feature_count(self, extractor):
        """TC-FE-001: extract_single returns 25 features."""
        feats = extractor._extract_single("http://example.com/path")
        assert len(feats) == 25

    def test_https_detection(self, extractor):
        """TC-FE-003: uses_https=1 for https:// URLs."""
        feats = extractor._extract_single("https://secure.example.com")
        assert feats["uses_https"] == 1

    def test_http_not_https(self, extractor):
        """TC-FE-003: uses_https=0 for http:// URLs."""
        feats = extractor._extract_single("http://insecure.example.com")
        assert feats["uses_https"] == 0

    def test_ip_address_detection(self, extractor):
        """TC-FE-004: has_ip_address=1 when URL contains raw IP."""
        feats = extractor._extract_single("http://192.168.1.1/admin")
        assert feats["has_ip_address"] == 1

    def test_no_ip_in_domain(self, extractor):
        """TC-FE-004: has_ip_address=0 for normal domain."""
        feats = extractor._extract_single("https://google.com")
        assert feats["has_ip_address"] == 0

    def test_suspicious_keyword_detected(self, extractor):
        """TC-FE-005: has_suspicious_keyword=1 for phishing-like URL."""
        feats = extractor._extract_single("http://paypal-verify.xyz/account/login")
        assert feats["has_suspicious_keyword"] == 1

    def test_entropy_positive(self, extractor):
        """TC-FE-002: Shannon entropy is positive for non-empty string."""
        entropy = extractor._shannon_entropy("randomstring123")
        assert entropy > 0.0

    def test_entropy_zero_empty(self, extractor):
        """TC-FE-002: Entropy is 0 for empty string."""
        entropy = extractor._shannon_entropy("")
        assert entropy == 0.0

    def test_url_length_correct(self, extractor):
        """url_length feature matches actual URL length."""
        url = "https://example.com/test"
        feats = extractor._extract_single(url)
        assert feats["url_length"] == len(url)

    def test_transform_single_returns_2d_array(self, extractor):
        """transform_single() returns shape (1, 25) numpy array."""
        arr = extractor.transform_single("https://example.com")
        assert arr.shape == (1, 25)

    def test_unparseable_url_returns_zeros(self, extractor):
        """Invalid URL should return zero features without exception."""
        feats = extractor._extract_single("")
        assert all(v == 0 or v == 0.0 for v in feats.values())
