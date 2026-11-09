import os
import sys
import pytest
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.ensemble.stacking import HybridStackingClassifier

def test_stacking_classifier_fit_predict():
    np.random.seed(42)
    X = np.random.randn(200, 10)
    y = (X[:, 0] + X[:, 1] > 0).astype(int)

    clf = HybridStackingClassifier(cv_splits=3, random_state=42)
    clf.fit(X, y)

    # Verify OOF prediction matrix was constructed
    assert clf.oof_predictions_ is not None
    assert clf.oof_predictions_.shape == (200, len(clf.base_models))

    # Test predict_proba contract
    probs = clf.predict_proba(X[:10])
    assert probs.shape == (10, 2)
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
    assert np.allclose(np.sum(probs, axis=1), 1.0)

    # Test evaluation metrics
    eval_res = clf.evaluate(X[:50], y[:50])
    assert "stacking" in eval_res
    assert "soft_voting" in eval_res
    assert "f1_score" in eval_res["stacking"]
