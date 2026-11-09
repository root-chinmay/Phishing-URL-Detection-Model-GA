import os
import time
import pickle
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    matthews_corrcoef
)

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

class HybridStackingClassifier:
    """
    Multilayer Hybrid Stacking Ensemble Architecture (Research Gap 2).
    
    Layer 1: Complementary diverse base learners (Tree ensembles, Gradient boosting, Linear).
    Layer 2: Meta-classifier trained exclusively on Out-of-Fold (OOF) cross-validated probability predictions.
    Layer 3: Calibrated final malicious probability and threat risk decision.
    """
    def __init__(self, base_models: dict = None, meta_classifier = None, cv_splits: int = 5, random_state: int = 42):
        self.cv_splits = cv_splits
        self.random_state = random_state

        if base_models is None:
            self.base_models = {
                "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=random_state, n_jobs=-1),
                "Extra Trees": ExtraTreesClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=random_state, n_jobs=-1),
                "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state))
            }
            if HAS_XGB:
                self.base_models["XGBoost"] = xgb.XGBClassifier(
                    n_estimators=100, max_depth=6, learning_rate=0.1,
                    eval_metric="logloss", random_state=random_state, n_jobs=-1
                )
            if HAS_LGB:
                self.base_models["LightGBM"] = lgb.LGBMClassifier(
                    n_estimators=100, max_depth=6, learning_rate=0.1,
                    class_weight="balanced", random_state=random_state, n_jobs=-1, verbose=-1
                )
        else:
            self.base_models = base_models

        if meta_classifier is None:
            self.meta_classifier = LogisticRegression(max_iter=1000, random_state=random_state)
        else:
            self.meta_classifier = meta_classifier

        self.fitted_base_models_ = {}
        self.oof_predictions_ = None
        self.meta_feature_names_ = list(self.base_models.keys())

    def fit(self, X: np.ndarray, y: np.ndarray):
        """
        Fit Layer 1 base models using K-Fold Out-of-Fold CV to build meta-features,
        then train Layer 2 meta-classifier on clean, un-leaked OOF probabilities.
        """
        n_samples = len(X)
        n_models = len(self.base_models)
        self.oof_predictions_ = np.zeros((n_samples, n_models), dtype=np.float32)

        skf = StratifiedKFold(n_splits=self.cv_splits, shuffle=True, random_state=self.random_state)

        print(f"[Stacking] Generating Out-of-Fold (OOF) meta-features across {self.cv_splits} folds for {n_models} base models...")
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            X_fold_train, y_fold_train = X[train_idx], y[train_idx]
            X_fold_val = X[val_idx]

            for m_idx, (name, model) in enumerate(self.base_models.items()):
                # Clone/instantiate fresh estimator for this fold
                from sklearn.base import clone
                fold_model = clone(model)
                fold_model.fit(X_fold_train, y_fold_train)

                if hasattr(fold_model, "predict_proba"):
                    val_probs = fold_model.predict_proba(X_fold_val)[:, 1]
                else:
                    val_probs = fold_model.predict(X_fold_val)

                self.oof_predictions_[val_idx, m_idx] = val_probs

        print("[Stacking] Fitting Layer 2 Meta-Classifier on un-leaked OOF predictions...")
        self.meta_classifier.fit(self.oof_predictions_, y)

        print("[Stacking] Re-fitting all Layer 1 base models on complete training partition...")
        for name, model in self.base_models.items():
            from sklearn.base import clone
            full_model = clone(model)
            full_model.fit(X, y)
            self.fitted_base_models_[name] = full_model

        return self

    def _transform_meta_features(self, X: np.ndarray) -> np.ndarray:
        """Extract prediction probability meta-features from fitted Layer 1 models."""
        meta_features = np.zeros((len(X), len(self.fitted_base_models_)), dtype=np.float32)
        for m_idx, (name, model) in enumerate(self.fitted_base_models_.items()):
            if hasattr(model, "predict_proba"):
                meta_features[:, m_idx] = model.predict_proba(X)[:, 1]
            else:
                meta_features[:, m_idx] = model.predict(X)
        return meta_features

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Generate final calibrated 2-class probability matrix [P(benign), P(malicious)]."""
        S_test = self._transform_meta_features(X)
        if hasattr(self.meta_classifier, "predict_proba"):
            return self.meta_classifier.predict_proba(S_test)
        else:
            preds = self.meta_classifier.predict(S_test)
            return np.vstack([1.0 - preds, preds]).T

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Binary threat classification against threshold."""
        probs = self.predict_proba(X)[:, 1]
        return (probs >= threshold).astype(int)

    def predict_soft_voting(self, X: np.ndarray) -> np.ndarray:
        """Compute conventional soft voting average across base models for comparison."""
        S_test = self._transform_meta_features(X)
        return np.mean(S_test, axis=1)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate complete cybersecurity benchmark metrics for Stacking vs Soft Voting."""
        t0 = time.perf_counter()
        y_prob = self.predict_proba(X_test)[:, 1]
        infer_time_ms = round(((time.perf_counter() - t0) / max(len(X_test), 1)) * 1000, 4)
        y_pred = (y_prob >= 0.5).astype(int)

        # Soft voting comparison
        soft_vote_probs = self.predict_soft_voting(X_test)
        soft_vote_preds = (soft_vote_probs >= 0.5).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        tn_sv, fp_sv, fn_sv, tp_sv = confusion_matrix(y_test, soft_vote_preds).ravel()

        return {
            "stacking": {
                "accuracy": round(accuracy_score(y_test, y_pred), 4),
                "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
                "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
                "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
                "mcc": round(matthews_corrcoef(y_test, y_pred), 4),
                "specificity": round(tn / (tn + fp) if (tn + fp) > 0 else 0.0, 4),
                "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
                "pr_auc": round(average_precision_score(y_test, y_prob), 4),
                "fpr": round(fp / (fp + tn) if (fp + tn) > 0 else 0.0, 4),
                "fnr": round(fn / (fn + tp) if (fn + tp) > 0 else 0.0, 4),
                "inference_time_per_sample_ms": infer_time_ms
            },
            "soft_voting": {
                "accuracy": round(accuracy_score(y_test, soft_vote_preds), 4),
                "precision": round(precision_score(y_test, soft_vote_preds, zero_division=0), 4),
                "recall": round(recall_score(y_test, soft_vote_preds, zero_division=0), 4),
                "f1_score": round(f1_score(y_test, soft_vote_preds, zero_division=0), 4),
                "mcc": round(matthews_corrcoef(y_test, soft_vote_preds), 4),
                "specificity": round(tn_sv / (tn_sv + fp_sv) if (tn_sv + fp_sv) > 0 else 0.0, 4),
                "roc_auc": round(roc_auc_score(y_test, soft_vote_probs), 4),
                "pr_auc": round(average_precision_score(y_test, soft_vote_probs), 4),
                "fpr": round(fp_sv / (fp_sv + tn_sv) if (fp_sv + tn_sv) > 0 else 0.0, 4),
                "fnr": round(fn_sv / (fn_sv + tp_sv) if (fn_sv + tp_sv) > 0 else 0.0, 4)
            }
        }

    def save(self, filepath: str = "models/checkpoints/stacking_model.pkl"):
        """Save serialized stacking ensemble."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(self, f)
        print(f"[Stacking] Model saved to {filepath}")

    @classmethod
    def load(cls, filepath: str = "models/checkpoints/stacking_model.pkl"):
        """Load serialized stacking ensemble."""
        with open(filepath, "rb") as f:
            return pickle.load(f)
