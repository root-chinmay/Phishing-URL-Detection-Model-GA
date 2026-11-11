import pytest
import os
import sys
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.models.inference_engine import URLThreatDetectionInferenceEngine, MobiURLGuardInferenceEngine
from src.features.url_features import extract_advanced_url_features
from src.uncertainty.conformal import ConformalPredictor
from src.calibration.probability_calibration import calculate_ece
from src.security.adversarial import AdversarialURLPerturber

def test_inference_engine_contract():
    engine = MobiURLGuardInferenceEngine()
    
    # Test safe URL
    safe_res = engine.analyze_url("https://www.google.com")
    assert "classification" in safe_res
    assert "risk_percentage" in safe_res
    assert "benign_percentage" in safe_res
    assert "conformal_prediction_set" in safe_res
    assert safe_res["risk_percentage"] < 35.0
    assert safe_res["classification"] == "legitimate"

    # Test phishing URL
    phish_res = engine.analyze_url("http://paypa1-account-verification-alert.com/login.php?cmd=verify")
    assert phish_res["risk_percentage"] > 60.0
    assert "malicious" in phish_res["conformal_prediction_set"]

def test_conformal_prediction_set():
    cp = ConformalPredictor(alpha=0.05)
    cp.q_hat = 0.60
    cp.calibrated = True

    # Ambiguous probability (e.g. 0.45) should trigger {Legitimate, Malicious}
    pred_set_ambiguous = cp.predict_set(0.45)
    assert "Legitimate" in pred_set_ambiguous
    assert "Malicious" in pred_set_ambiguous

    # High malicious probability (0.95) should be singleton {Malicious}
    pred_set_mal = cp.predict_set(0.95)
    assert "Malicious" in pred_set_mal
    assert "Legitimate" not in pred_set_mal

def test_ece_calculation():
    # Perfectly calibrated predictions
    y_true = np.array([1, 1, 0, 0])
    y_prob = np.array([0.9, 0.9, 0.1, 0.1])
    ece = calculate_ece(y_true, y_prob)
    assert ece < 0.2

def test_adversarial_suite():
    perturber = AdversarialURLPerturber()
    url = "https://paypal-login.com"
    suite = perturber.generate_adversarial_suite(url)
    assert "homoglyph_attack" in suite
    assert "subdomain_injection" in suite
    assert "percent_obfuscation" in suite
    assert "nested_redirect" in suite

def test_shortener_and_long_url_consistency():
    engine = URLThreatDetectionInferenceEngine()

    long_benign = "https://www.google.com/search?q=cybersecurity"
    res_long_benign = engine.analyze_url(long_benign, resolve_shorteners=False)

    mock_redirect_benign = {
        "original_url": "https://bit.ly/safe_google_test",
        "final_url": f"{long_benign}&utm_source=bitly",
        "resolved_successfully": True,
        "hop_count": 1,
        "cross_domain_redirects": 1,
        "protocol_downgrade": False,
        "redirect_chain": [
            {"hop": 0, "url": "https://bit.ly/safe_google_test", "hostname": "bit.ly", "protocol": "https", "status_code": 301},
            {"hop": 1, "url": f"{long_benign}&utm_source=bitly", "hostname": "www.google.com", "protocol": "https", "status_code": 200},
        ],
        "resolution_error": None
    }
    res_short_benign = engine.analyze_url("https://bit.ly/safe_google_test", redirect_info=mock_redirect_benign)
    assert res_short_benign["classification"] == res_long_benign["classification"] == "legitimate"
    assert abs(res_short_benign["risk_percentage"] - res_long_benign["risk_percentage"]) <= 5.0

    long_phish = "http://paypa1-account-verification-alert.com/login.php?cmd=verify"
    res_long_phish = engine.analyze_url(long_phish, resolve_shorteners=False)
    mock_redirect_phish = {
        "original_url": "https://tinyurl.com/phish_test",
        "final_url": long_phish,
        "resolved_successfully": True,
        "hop_count": 2,
        "cross_domain_redirects": 1,
        "protocol_downgrade": True,
        "redirect_chain": [
            {"hop": 0, "url": "https://tinyurl.com/phish_test", "hostname": "tinyurl.com", "protocol": "https", "status_code": 302},
            {"hop": 1, "url": long_phish, "hostname": "paypa1-account-verification-alert.com", "protocol": "http", "status_code": 200},
        ],
        "resolution_error": None
    }
    res_short_phish = engine.analyze_url("https://tinyurl.com/phish_test", redirect_info=mock_redirect_phish)
    assert res_short_phish["classification"] == "malicious"
    assert res_short_phish["risk_percentage"] >= res_long_phish["risk_percentage"]
    assert res_short_phish["advanced_features"]["protocol_downgrade_flag"] == 1

def test_advanced_url_features_detection():
    obfuscated = "https://user@xkzqwrptv.xyz:8443/verify.php?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    adv = extract_advanced_url_features(obfuscated)
    assert adv["has_userinfo_at_obfuscation"] == 1
    assert adv["has_port_obfuscation"] == 1
    assert adv["has_encoded_payload"] == 1
    assert adv["consonant_cluster_anomaly"] == 1
    assert adv["has_double_extension_or_script"] == 1

