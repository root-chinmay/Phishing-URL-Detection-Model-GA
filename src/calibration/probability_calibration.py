import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss

def calculate_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """
    Calculate Expected Calibration Error (ECE).
    Measures the weighted average difference between predicted confidence and observed accuracy.
    """
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    total_samples = len(y_true)

    for i in range(n_bins):
        bin_mask = (y_prob >= bin_edges[i]) & (y_prob < bin_edges[i + 1])
        if i == n_bins - 1: # Include upper bound
            bin_mask = (y_prob >= bin_edges[i]) & (y_prob <= bin_edges[i + 1])

        bin_samples = np.sum(bin_mask)
        if bin_samples > 0:
            bin_acc = np.mean(y_true[bin_mask])
            bin_conf = np.mean(y_prob[bin_mask])
            ece += (bin_samples / total_samples) * abs(bin_acc - bin_conf)

    return round(float(ece), 4)

def compute_reliability_curve(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> list:
    """Compute bin points for reliability diagram plotting."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    curve = []

    for i in range(n_bins):
        bin_mask = (y_prob >= bin_edges[i]) & (y_prob < bin_edges[i + 1])
        if i == n_bins - 1:
            bin_mask = (y_prob >= bin_edges[i]) & (y_prob <= bin_edges[i + 1])

        bin_samples = int(np.sum(bin_mask))
        if bin_samples > 0:
            bin_acc = float(np.mean(y_true[bin_mask]))
            bin_conf = float(np.mean(y_prob[bin_mask]))
        else:
            bin_acc = float((bin_edges[i] + bin_edges[i + 1]) / 2)
            bin_conf = bin_acc

        curve.append({
            "bin": i,
            "min_prob": round(float(bin_edges[i]), 2),
            "max_prob": round(float(bin_edges[i + 1]), 2),
            "mean_confidence": round(bin_conf, 4),
            "empirical_accuracy": round(bin_acc, 4),
            "sample_count": bin_samples
        })

    return curve

def calibrate_model(base_model, X_calib: np.ndarray, y_calib: np.ndarray, method: str = "isotonic"):
    """
    Fit post-hoc calibration on separate calibration partition.
    method: 'isotonic' (non-parametric) or 'sigmoid' (Platt scaling).
    Compatible with scikit-learn >= 1.5 (FrozenEstimator) and legacy (<1.5 cv='prefit').
    """
    try:
        from sklearn.frozen import FrozenEstimator
        calibrated = CalibratedClassifierCV(estimator=FrozenEstimator(base_model), method=method)
    except ImportError:
        try:
            calibrated = CalibratedClassifierCV(estimator=base_model, method=method, cv="prefit")
        except Exception:
            calibrated = CalibratedClassifierCV(estimator=base_model, method=method, cv=2)

    calibrated.fit(X_calib, y_calib)
    return calibrated
