import time
import pickle
import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
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

def get_baseline_models():
    """Instantiate candidate base classifiers."""
    models = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Decision Tree": DecisionTreeClassifier(max_depth=8, class_weight="balanced", random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1),
        "Extra Trees": ExtraTreesClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42),
        "Naive Bayes": GaussianNB()
    }
    if HAS_XGB:
        models["XGBoost"] = xgb.XGBClassifier(
            n_estimators=100, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1
        )
    if HAS_LGB:
        models["LightGBM"] = lgb.LGBMClassifier(
            n_estimators=100, max_depth=6, learning_rate=0.1,
            class_weight="balanced", random_state=42, n_jobs=-1, verbose=-1
        )
    return models

BASELINE_MODELS = get_baseline_models()

def train_and_evaluate_baselines(X_train: np.ndarray, y_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray, models_dict: dict = None) -> dict:
    """Train multiple baseline classifiers and evaluate comprehensive cybersecurity metrics."""
    if models_dict is None:
        models_dict = get_baseline_models()
    results = {}

    for name, model in models_dict.items():
        # Measure training latency
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        train_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Measure inference latency per sample
        t1 = time.perf_counter()
        y_pred = model.predict(X_test)
        infer_time_ms = round(((time.perf_counter() - t1) / max(len(X_test), 1)) * 1000, 4)

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
        mcc = matthews_corrcoef(y_test, y_pred)
        
        try:
            roc_auc = roc_auc_score(y_test, y_prob)
            pr_auc = average_precision_score(y_test, y_prob)
        except Exception:
            roc_auc = 0.5
            pr_auc = 0.5

        # Confusion matrix for FPR, FNR, Specificity
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # Estimated model size in KB
        size_kb = round(len(pickle.dumps(model)) / 1024, 2)

        results[name] = {
            "model": model,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "mcc": round(mcc, 4),
            "specificity": round(specificity, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "training_time_ms": train_time_ms,
            "inference_time_per_sample_ms": infer_time_ms,
            "model_size_kb": size_kb
        }

    return results
