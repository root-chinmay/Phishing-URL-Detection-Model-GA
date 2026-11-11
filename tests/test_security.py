import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))
from src.security.redirect_analysis import (
    analyze_redirect_risk_offline,
    canonicalize_url_for_comparison,
    KNOWN_SHORTENERS,
    _is_public_ip_for_host
)
from src.security.qr_scanner import QRQuishingDetector

def test_detect_known_shorteners():
    assert "bit.ly" in KNOWN_SHORTENERS
    assert "t.co" in KNOWN_SHORTENERS
    assert "rb.gy" in KNOWN_SHORTENERS
    assert "tinyurl.com" in KNOWN_SHORTENERS
    res = analyze_redirect_risk_offline("https://bit.ly/3x8AbCd")
    assert res["is_known_shortener"] is True

def test_detect_redirect_parameters():
    url_redirect = "https://legit-portal.com/login?redirect=http%3A%2F%2Fmalicious-site.ru%2Fsteal"
    info = analyze_redirect_risk_offline(url_redirect)
    assert info["has_redirect_param"] is True
    assert len(info["embedded_urls"]) > 0
    assert info["potential_embedded_target"] == "http://malicious-site.ru/steal"

def test_canonicalize_url_strips_tracking():
    long_clean = "https://www.google.com/search?q=cybersecurity"
    long_tracked = "HTTPS://WWW.GOOGLE.COM:443/search?q=cybersecurity&utm_source=bitly&fbclid=12345"
    assert canonicalize_url_for_comparison(long_clean) == canonicalize_url_for_comparison(long_tracked)

def test_ssrf_guard_blocks_private_ips():
    assert _is_public_ip_for_host("127.0.0.1") is False
    assert _is_public_ip_for_host("192.168.1.10") is False
    assert _is_public_ip_for_host("10.0.0.1") is False
    assert _is_public_ip_for_host("169.254.169.254") is False
    assert _is_public_ip_for_host("8.8.8.8") is True

def test_qr_quishing_detector():
    detector = QRQuishingDetector()
    verdict = detector.inspect_qr_payload("http://192.168.1.50/credentials.php")
    assert verdict["is_valid_url"] is True
    assert verdict["quarantine_status"] == "isolated_for_inspection"
    assert verdict["hostname"] == "192.168.1.50"
