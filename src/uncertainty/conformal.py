import numpy as np

class ConformalPredictor:
    """
    Split Conformal Classification Predictor.
    Computes conformity scores on a dedicated calibration dataset and constructs
    rigorous prediction sets with finite-sample coverage guarantee (1 - alpha).
    Possible sets:
      - {0}: Legitimate only
      - {1}: Malicious only
      - {0, 1}: Uncertain / Insufficient evidence (both classes possible at target confidence)
    """
    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha
        self.q_hat = 0.5
        self.calibrated = False

    def calibrate(self, probs_calib: np.ndarray, y_calib: np.ndarray):
        """
        Calibrate quantile using non-conformity scores s_i = 1 - P(Y = y_i | X_i).
        Finite sample correction: quantile level = ceil((n + 1) * (1 - alpha)) / n.
        """
        n = len(y_calib)
        if n == 0:
            raise ValueError("Calibration set cannot be empty.")

        # Non-conformity score for true class
        scores = []
        for i in range(n):
            true_label = int(y_calib[i])
            prob_true = probs_calib[i, true_label]
            scores.append(1.0 - prob_true)

        scores = np.sort(scores)
        # Quantile index with finite sample correction
        k = int(np.ceil((n + 1) * (1.0 - self.alpha)))
        k = min(max(k, 1), n) # Clamp to valid range
        self.q_hat = float(scores[k - 1])
        self.calibrated = True
        return self.q_hat

    def predict_set(self, prob_malicious: float) -> list:
        """
        Generate prediction set given predicted probability of malicious class.
        P(Y=1) = prob_malicious, P(Y=0) = 1 - prob_malicious.
        An outcome label y is included if (1 - P(Y = y)) <= q_hat.
        """
        if not self.calibrated:
            self.q_hat = 0.65 # Safe fallback threshold

        prob_benign = 1.0 - prob_malicious
        pred_set = []

        # Check inclusion of Benign (0)
        score_0 = 1.0 - prob_benign
        if score_0 <= self.q_hat:
            pred_set.append("Legitimate")

        # Check inclusion of Malicious (1)
        score_1 = 1.0 - prob_malicious
        if score_1 <= self.q_hat:
            pred_set.append("Malicious")

        # Guarantee at least the argmax if empty due to edge case
        if not pred_set:
            pred_set = ["Malicious"] if prob_malicious >= 0.5 else ["Legitimate"]

        return pred_set

    def evaluate_coverage(self, probs_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate empirical coverage and average set size on test data."""
        n = len(y_test)
        covered = 0
        set_sizes = []
        uncertain_count = 0

        for i in range(n):
            p_mal = float(probs_test[i, 1])
            pset = self.predict_set(p_mal)
            true_name = "Malicious" if y_test[i] == 1 else "Legitimate"

            if true_name in pset:
                covered += 1
            set_sizes.append(len(pset))
            if len(pset) > 1:
                uncertain_count += 1

        return {
            "nominal_coverage": round(1.0 - self.alpha, 4),
            "empirical_coverage": round(covered / n, 4),
            "average_set_size": round(float(np.mean(set_sizes)), 3),
            "uncertainty_rate": round(uncertain_count / n, 4),
            "q_hat_threshold": round(self.q_hat, 4)
        }
