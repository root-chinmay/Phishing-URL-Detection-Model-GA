"""
MobiURL-Guard Android / Mobile Entry Point
Built with Python & Kivy for 100% offline edge inference on mobile devices.
"""
import sys
import os

# Ensure package imports resolve cleanly
sys.path.insert(0, os.path.abspath("."))
from src.models.inference_engine import MobiURLGuardInferenceEngine

def create_mobile_cli_demo():
    """Interactive command-line test runner of the mobile detection engine."""
    print("=" * 60)
    print("MOBIURL-GUARD MOBILE ENGINE (OFFLINE ANDROID RUNTIME)")
    print("=" * 60)
    engine = MobiURLGuardInferenceEngine()

    test_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "http://paypa1-account-verification-alert.com/login.php?cmd=verify",
        "https://xn--pypal-4ve.com/signin",
        "http://bit.ly/3x8AbCd",
        "https://unknown-domain-test-2026.xyz/portal"
    ]

    for u in test_urls:
        res = engine.analyze_url(u)
        print(f"\n[URL]: {res['url']}")
        print(f" -> Decision: {res['classification'].upper()}")
        print(f" -> Malicious Risk: {res['risk_percentage']}% | Benign Prob: {res['benign_percentage']}%")
        print(f" -> Conformal Set: {res['conformal_prediction_set']} (Confidence: {res['prediction_confidence']})")
        print(f" -> Top Reasons: {res['top_reasons'][:2]}")

if __name__ == "__main__":
    create_mobile_cli_demo()
