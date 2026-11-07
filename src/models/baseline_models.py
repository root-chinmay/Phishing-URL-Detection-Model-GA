import time
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

BASELINE_MODELS = {
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Decision Tree": DecisionTreeClassifier(max_depth=8, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42),
    "Extra Trees": ExtraTreesClassifier(n_estimators=100, max_depth=10, random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=80, learning_rate=0.1, random_state=42),
    "Naive Bayes": GaussianNB()
}

def train_and_evaluate_baselines(X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Train multiple baseline classifiers and evaluate comprehensive cybersecurity metrics."""
    results = {}

    for name, model in BASELINE_MODELS.items():
        # Measure training latency
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Measure inference latency per sample
        t1 = time.perf_counter()
        y_pred = model.predict(X_test)
        infer_time_ms = round(((time.perf_counter() - t1) / len(X_test)) * 1000, 3)

        # Get probabilities
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test)[:, 1]
        else:
            y_prob = y_pred

        # Classification metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        try:
            roc_auc = roc_auc_score(y_test, y_prob)
            pr_auc = average_precision_score(y_test, y_prob)
        except Exception:
            roc_auc = 0.5
            pr_auc = 0.5

        # Confusion matrix for FPR & FNR
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Estimated model size in KB
        import pickle
        size_kb = round(len(pickle.dumps(model)) / 1024, 2)

        results[name] = {
            "model": model,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "training_time_ms": train_time_ms,
            "inference_time_per_sample_ms": infer_time_ms,
            "model_size_kb": size_kb
        }

    return results
