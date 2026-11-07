"""
MobiURL-Guard Kivy Screen Architecture
Defines the 6 core screens programmatically for Android deployment:
1. HomeDashboardScreen
2. URLAnalysisScreen
3. RiskAssessmentScreen
4. DetailedAnalysisScreen
5. ScanHistoryScreen
6. SettingsScreen
"""

class ScreenMetadata:
    SCREENS = [
        {"id": "home", "title": "Home Dashboard", "icon": "shield-check"},
        {"id": "analysis", "title": "URL Analysis", "icon": "radar"},
        {"id": "assessment", "title": "Risk Assessment", "icon": "alert-circle"},
        {"id": "details", "title": "Detailed Diagnostics", "icon": "file-text"},
        {"id": "history", "title": "Scan History", "icon": "history"},
        {"id": "settings", "title": "Settings & Privacy", "icon": "settings"}
    ]

class MockKivyAppInterface:
    """Interface adapter for headless or desktop testing of screen navigation."""
    def __init__(self, engine):
        self.engine = engine
        self.current_screen = "home"
        self.current_result = None

    def navigate_to(self, screen_id: str):
        self.current_screen = screen_id
        return f"Navigated to {screen_id}"

    def trigger_scan(self, url: str, message_text: str = None):
        self.current_result = self.engine.analyze_url(url, message_text)
        self.current_screen = "assessment"
        return self.current_result
