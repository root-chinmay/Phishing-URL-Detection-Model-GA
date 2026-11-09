import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))
from src.security.redirect_analysis import analyze_redirect_risk_offline, KNOWN_SHORTENERS
from src.security.qr_scanner import QRQuishingDetector

def test_detect_known_shorteners():
    assert "bit.ly" in KNOWN_SHORTENERS
    assert "t.co" in KNOWN_SHORTENERS
    res = analyze_redirect_risk_offline("https://bit.ly/3x8AbCd")
    assert res["is_known_shortener"] is True

def test_detect_redirect_parameters():
    url_redirect = "https://legit-portal.com/login?redirect=http%3A%2F%2Fmalicious-site.ru%2Fsteal"
    info = analyze_redirect_risk_offline(url_redirect)
    assert info["has_redirect_param"] is True
    assert len(info["embedded_urls"]) > 0

def test_qr_quishing_detector():
    detector = QRQuishingDetector()
    verdict = detector.inspect_qr_payload("http://192.168.1.50/credentials.php")
    assert verdict["is_valid_url"] is True
    assert verdict["quarantine_status"] == "isolated_for_inspection"
    assert verdict["hostname"] == "192.168.1.50"
