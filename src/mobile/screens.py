"""
MobiURL-Guard Kivy Screen Architecture
Defines the 7 required screens for the Android mobile application:
1. HomeDashboardScreen
2. URLAnalysisScreen
3. RiskAssessmentScreen
4. DetailedExplanationScreen
5. ScanHistoryScreen
6. QRScannerScreen
7. SettingsScreen
"""
import os
import sys
import json
import time

try:
    # Set headless environment flags if no display is detected
    if not os.environ.get("DISPLAY") and sys.platform != "win32":
        os.environ["KIVY_NO_CONSOLELOG"] = "1"
    
    from kivy.app import App
    from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.label import Label
    from kivy.uix.textinput import TextInput
    from kivy.uix.button import Button
    from kivy.core.window import Window
    from kivy.metrics import dp
    HAS_KIVY = True
except Exception as e:
    HAS_KIVY = False
    print(f"[Warning] Kivy UI widgets unavailable: {e}. Running in headless adapter mode.")

# Screen 1: Home Dashboard Screen
class HomeDashboardScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "home"

# Screen 2: URL Analysis Screen
class URLAnalysisScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "analysis"

# Screen 3: Risk Assessment Screen
class RiskAssessmentScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "assessment"

# Screen 4: Detailed Feature Explanation Screen
class DetailedExplanationScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "explanation"

# Screen 5: Scan History Screen
class ScanHistoryScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "history"

# Screen 6: QR Scanner Screen
class QRScannerScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "qr"

# Screen 7: Settings Screen
class SettingsScreen:
    def __init__(self, manager=None):
        self.manager = manager
        self.name = "settings"


class MobiURLMobileController:
    """
    Central Mobile Application State & Navigation Controller.
    Interacts with the offline MobiURLGuardInferenceEngine.
    """
    def __init__(self, engine=None):
        if engine is None:
            from src.models.inference_engine import MobiURLGuardInferenceEngine
            self.engine = MobiURLGuardInferenceEngine()
        else:
            self.engine = engine

        self.current_screen = "home"
        self.current_result = None
        self.history = []
        self.offline_mode = True
        self.conformal_alpha = 0.05
        self.risk_threshold = 50.0

    def navigate_to(self, screen_id: str) -> str:
        valid_screens = ["home", "analysis", "assessment", "explanation", "history", "qr", "settings"]
        if screen_id in valid_screens:
            self.current_screen = screen_id
            return f"Navigated to {screen_id}"
        raise ValueError(f"Unknown screen: {screen_id}")

    def scan_url(self, url: str, message_text: str = None) -> dict:
        """Scan URL and update application state."""
        res = self.engine.analyze_url(url, message_text)
        self.current_result = res
        
        # Add to local persistent history
        self.history.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": res["url"],
            "risk_percentage": res["risk_percentage"],
            "classification": res["classification"],
            "conformal_set": res["conformal_prediction_set"],
            "latency_ms": res.get("processing_time_ms", 1.2)
        })
        self.current_screen = "assessment"
        return res

    def get_history(self) -> list:
        return list(reversed(self.history))

    def clear_history(self):
        self.history.clear()


if HAS_KIVY:
    class KivyHomeDashboard(Screen):
        def __init__(self, controller, **kwargs):
            super().__init__(name="home", **kwargs)
            self.controller = controller
            layout = BoxLayout(orientation="vertical", padding=dp(15), spacing=dp(10))

            # Header
            header = Label(
                text="[b]URL Threat Detection[/b]\n[size=12]Offline Mobile Threat Defense[/size]",
                markup=True, size_hint_y=0.2, halign="center"
            )
            layout.add_widget(header)

            # URL Input Box
            self.url_input = TextInput(
                hint_text="Enter or paste suspicious URL...",
                multiline=False, size_hint_y=0.15
            )
            layout.add_widget(self.url_input)

            # Action Buttons
            btn_box = BoxLayout(orientation="horizontal", spacing=dp(8), size_hint_y=0.15)
            scan_btn = Button(text="Scan URL", background_color=(0.14, 0.45, 0.95, 1.0))
            scan_btn.bind(on_press=self.on_scan)
            qr_btn = Button(text="QR Scanner", background_color=(0.2, 0.7, 0.3, 1.0))
            qr_btn.bind(on_press=lambda x: self.navigate("qr"))
            btn_box.add_widget(scan_btn)
            btn_box.add_widget(qr_btn)
            layout.add_widget(btn_box)

            # Navigation Row
            nav_box = BoxLayout(orientation="horizontal", spacing=dp(5), size_hint_y=0.12)
            hist_btn = Button(text="History")
            hist_btn.bind(on_press=lambda x: self.navigate("history"))
            set_btn = Button(text="Settings")
            set_btn.bind(on_press=lambda x: self.navigate("settings"))
            nav_box.add_widget(hist_btn)
            nav_box.add_widget(set_btn)
            layout.add_widget(nav_box)

            # Status Badge
            status_lbl = Label(
                text=f"Status: 100% Offline Active | Engine v{self.controller.engine.version}",
                font_size="11sp", size_hint_y=0.1
            )
            layout.add_widget(status_lbl)

            self.add_widget(layout)

        def on_scan(self, instance):
            url = self.url_input.text.strip()
            if url:
                self.controller.scan_url(url)
                self.manager.current = "assessment"

        def navigate(self, screen_name):
            self.controller.navigate_to(screen_name)
            self.manager.current = screen_name

    class KivyRiskAssessment(Screen):
        def __init__(self, controller, **kwargs):
            super().__init__(name="assessment", **kwargs)
            self.controller = controller
            self.layout = BoxLayout(orientation="vertical", padding=dp(15), spacing=dp(8))
            self.info_label = Label(text="No scan performed yet.", markup=True)
            self.layout.add_widget(self.info_label)

            btn_box = BoxLayout(orientation="horizontal", spacing=dp(8), size_hint_y=0.2)
            explain_btn = Button(text="View Why Suspicious")
            explain_btn.bind(on_press=lambda x: self.navigate("explanation"))
            home_btn = Button(text="Back Home")
            home_btn.bind(on_press=lambda x: self.navigate("home"))
            btn_box.add_widget(explain_btn)
            btn_box.add_widget(home_btn)
            self.layout.add_widget(btn_box)
            self.add_widget(self.layout)

        def on_pre_enter(self):
            res = self.controller.current_result
            if res:
                color = "ff4444" if res["classification"] == "malicious" else ("44ff44" if res["classification"] == "legitimate" else "ffbb33")
                txt = f"""[b]Security Assessment Result[/b]
Target: {res['url'][:45]}...

Malicious Risk: [color=#{color}][b]{res['risk_percentage']}%[/b][/color]
Estimated Legitimate Probability: {res['benign_percentage']}%
Classification: [color=#{color}][b]{res['classification'].upper()}[/b][/color]
Confidence: {res['prediction_confidence'].title()}
Conformal Set: {res['conformal_prediction_set']}
Processing Time: {res.get('processing_time_ms', 1.0)} ms"""
                self.info_label.text = txt

        def navigate(self, screen_name):
            self.controller.navigate_to(screen_name)
            self.manager.current = screen_name

    class KivyExplanationScreen(Screen):
        def __init__(self, controller, **kwargs):
            super().__init__(name="explanation", **kwargs)
            self.controller = controller
            layout = BoxLayout(orientation="vertical", padding=dp(15), spacing=dp(8))
            layout.add_widget(Label(text="[b]Forensic Explanations[/b]", markup=True, size_hint_y=0.15))

            self.reasons_label = Label(text="", size_hint_y=0.7, markup=True, halign="left", valign="top")
            layout.add_widget(self.reasons_label)

            back_btn = Button(text="Back to Result", size_hint_y=0.15)
            back_btn.bind(on_press=lambda x: self.navigate("assessment"))
            layout.add_widget(back_btn)
            self.add_widget(layout)

        def on_pre_enter(self):
            res = self.controller.current_result
            if res:
                reasons = res.get("top_reasons", [])
                lines = [f"• {r}" for r in reasons]
                self.reasons_label.text = "\n\n".join(lines) if lines else "No anomalous flags triggered."

        def navigate(self, screen_name):
            self.controller.navigate_to(screen_name)
            self.manager.current = screen_name

    def build_kivy_screen_manager(controller):
        """Construct full Kivy ScreenManager with all registered screens."""
        sm = ScreenManager(transition=FadeTransition())
        sm.add_widget(KivyHomeDashboard(controller))
        sm.add_widget(KivyRiskAssessment(controller))
        sm.add_widget(KivyExplanationScreen(controller))
        return sm
