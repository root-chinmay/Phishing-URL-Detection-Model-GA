import os
import sys
import pytest
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.uncertainty.conformal import ConformalPredictor

def test_split_conformal_calibration():
    cp = ConformalPredictor(alpha=0.10)
    
    # 100 calibration predictions [P(benign), P(malicious)]
    np.random.seed(42)
    y_calib = np.random.randint(0, 2, 100)
    probs_calib = np.zeros((100, 2))
    for i in range(100):
        p1 = 0.85 if y_calib[i] == 1 else 0.15
        probs_calib[i] = [1.0 - p1, p1]

    q_hat = cp.calibrate(probs_calib, y_calib)
    assert 0.0 < q_hat <= 1.0
    assert cp.calibrated is True

def test_conformal_coverage_evaluation():
    cp = ConformalPredictor(alpha=0.05)
    cp.q_hat = 0.65
    cp.calibrated = True

    y_test = np.array([1, 0, 1, 0])
    probs_test = np.array([
        [0.05, 0.95],
        [0.90, 0.10],
        [0.45, 0.55],
        [0.92, 0.08]
    ])

    eval_res = cp.evaluate_coverage(probs_test, y_test)
    assert "nominal_coverage" in eval_res
    assert "empirical_coverage" in eval_res
    assert "average_set_size" in eval_res
    assert eval_res["empirical_coverage"] >= 0.75
