import os
import sys
import pytest
import numpy as np
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.abspath("."))
from src.calibration.probability_calibration import calculate_ece, compute_reliability_curve, calibrate_model

def test_calculate_ece_bounds():
    y_true = np.array([1, 1, 0, 0, 1, 0])
    y_prob = np.array([0.95, 0.85, 0.05, 0.15, 0.80, 0.10])
    ece = calculate_ece(y_true, y_prob, n_bins=5)
    assert 0.0 <= ece <= 1.0

def test_reliability_curve():
    y_true = np.array([1, 0, 1, 0])
    y_prob = np.array([0.8, 0.2, 0.7, 0.3])
    curve = compute_reliability_curve(y_true, y_prob, n_bins=4)
    assert len(curve) == 4
    for b in curve:
        assert "mean_confidence" in b
        assert "empirical_accuracy" in b

def test_calibrate_model_isotonic():
    np.random.seed(42)
    X = np.random.randn(150, 4)
    y = (X[:, 0] > 0).astype(int)

    base = DecisionTreeClassifier(max_depth=3, random_state=42).fit(X[:100], y[:100])
    calibrated = calibrate_model(base, X[100:], y[100:], method="isotonic")

    probs = calibrated.predict_proba(X[:10])
    assert probs.shape == (10, 2)
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
