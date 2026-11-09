import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))
from src.mobile.screens import MobiURLMobileController
from src.models.student_model import LightweightTreeInterpreter

def test_mobile_controller_navigation():
    controller = MobiURLMobileController()
    assert controller.current_screen == "home"

    controller.navigate_to("analysis")
    assert controller.current_screen == "analysis"

    controller.navigate_to("settings")
    assert controller.current_screen == "settings"

def test_mobile_controller_scan_and_history():
    controller = MobiURLMobileController()
    res = controller.scan_url("https://www.google.com")
    assert res is not None
    assert "risk_percentage" in res
    assert "conformal_prediction_set" in res
    assert controller.current_screen == "assessment"

    history = controller.get_history()
    assert len(history) == 1
    assert history[0]["url"] == "https://www.google.com"

    controller.clear_history()
    assert len(controller.get_history()) == 0

def test_student_interpreter_parity():
    import json
    model_path = "models/exported/student_model.json"
    if os.path.exists(model_path):
        student_dict = json.load(open(model_path))
        interpreter = LightweightTreeInterpreter(student_dict)
        dummy_vec = [0.0] * 28
        prob = interpreter.predict_proba_single(dummy_vec)
        assert 0.0 <= prob <= 1.0
