import numpy as np

class OODDetector:
    """Out-of-Distribution detector using feature standard score distance from training centroid."""
    def __init__(self, threshold: float = 3.5):
        self.centroid = None
        self.std = None
        self.threshold = threshold

    def fit(self, X_train: np.ndarray):
        """Fit baseline mean and standard deviation across numerical features."""
        self.centroid = np.mean(X_train, axis=0)
        self.std = np.std(X_train, axis=0)
        # Prevent division by zero
        self.std = np.where(self.std == 0, 1e-6, self.std)

    def score(self, x: np.ndarray) -> float:
        """Compute maximum standardized z-distance from training distribution."""
        if self.centroid is None or self.std is None:
            return 0.0
        z_scores = np.abs((x - self.centroid) / self.std)
        return float(np.max(z_scores))

    def is_ood(self, x: np.ndarray) -> bool:
        """Return True if feature vector exceeds OOD threshold."""
        return self.score(x) > self.threshold
