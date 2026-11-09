"""
MobiURL-Guard Android Application Entry Point
Built with Python & Kivy for 100% offline edge inference on Android mobile devices.
"""
import sys
import os

os.environ["KIVY_NO_ARGS"] = "1"

sys.path.insert(0, os.path.abspath("."))
from src.models.inference_engine import MobiURLGuardInferenceEngine
from src.mobile.screens import MobiURLMobileController, HAS_KIVY

if HAS_KIVY:
    from kivy.app import App
    from src.mobile.screens import build_kivy_screen_manager

    class MobiURLGuardApp(App):
        def build(self):
            self.title = "URL Threat Detection"
            self.controller = MobiURLMobileController()
            return build_kivy_screen_manager(self.controller)

def run_mobile_app():
    """Launch mobile application or run demo suite if headless."""
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli_demo()
    elif HAS_KIVY and os.environ.get("HEADLESS") != "1":
        try:
            MobiURLGuardApp().run()
        except Exception as e:
            print(f"[Mobile] GUI initialization fallback: {e}")
            run_cli_demo()
    else:
        run_cli_demo()

def run_cli_demo():
    print("=" * 65)
    print("URL THREAT DETECTION MOBILE ANDROID INTERFACE DEMO (OFFLINE RUNTIME)")
    print("=" * 65)
    controller = MobiURLMobileController()

    sample_urls = [
        "https://www.google.com/search?q=cybersecurity+defense",
        "https://secure-login.paypa1.com.account-update.xyz/auth?dest=wallet",
        "http://192.168.1.100:8080/admin/secure_login.php",
        "https://s3.dualstack.us-west-2.amazonaws.com/payhoa-prod/login.html",
        "https://bit.ly/3xY9zqW"
    ]

    for url in sample_urls:
        res = controller.scan_url(url)
        print(f"\n[SCAN URL]: {res['url']}")
        print(f" -> Classification: {res['classification'].upper()}")
        print(f" -> Malicious Risk: {res['risk_percentage']}% | Legitimate Prob: {res['benign_percentage']}%")
        print(f" -> Conformal Prediction Set: {res['conformal_prediction_set']}")
        print(f" -> Uncertainty Status: {res['uncertainty_status'].title()} | Confidence: {res['prediction_confidence'].title()}")
        print(f" -> Latency: {res['processing_time_ms']} ms")
        print(f" -> Top Explanations:")
        for r in res['top_reasons'][:2]:
            print(f"    • {r}")

    print("\n[History Log]:")
    for h in controller.get_history():
        print(f"  [{h['timestamp']}] {h['classification'].upper()} ({h['risk_percentage']}%) - {h['url'][:40]}...")

if __name__ == "__main__":
    run_mobile_app()
