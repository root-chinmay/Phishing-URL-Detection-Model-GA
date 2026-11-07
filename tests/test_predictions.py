import pytest
import os
import sys
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.models.inference_engine import MobiURLGuardInferenceEngine
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
