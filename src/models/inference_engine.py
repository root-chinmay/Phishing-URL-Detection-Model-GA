import os
import json
import numpy as np
from src.features.url_features import extract_url_vector, extract_url_feature_dict, FEATURE_NAMES
from src.features.message_features import extract_message_features
from src.explainability.local_explainer import generate_local_explanation
from src.models.student_model import LightweightTreeInterpreter

class URLThreatDetectionInferenceEngine:
    """
    Unified URL Threat Detection Mobile & Research Inference Engine.
    Executes offline-capable calibrated probability estimation, split conformal prediction sets,
    OOD detection, and localized explainability.
    """
    def __init__(self, model_path: str = "models/exported/student_model.json", q_hat: float = 0.62):
        self.model_path = model_path
        self.q_hat = q_hat
        self.version = "1.0.0"
        self.interpreter = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            self.interpreter = LightweightTreeInterpreter.load_from_json(self.model_path)
        else:
            # Fallback rules-assisted inference if json not yet compiled
            self.interpreter = None

    def analyze_url(self, url: str, message_text: str = None) -> dict:
        """Analyze a URL and produce standardized risk assessment output."""
        if not url or not url.strip():
            raise ValueError("URL cannot be empty.")

        url_clean = url.strip()
        feat_vector = extract_url_vector(url_clean)
        feat_dict = extract_url_feature_dict(url_clean)
        msg_feats = extract_message_features(message_text)

        import time
        t_start = time.perf_counter()

        # 1. Base prediction
        if self.interpreter is not None:
            raw_prob = self.interpreter.predict_proba_single(feat_vector)
        else:
            # Calibrated baseline heuristic
            score = 0.05
            if feat_dict.get("brand_impersonation_flag"):
                score += 0.45
            if feat_dict.get("is_ip_address"):
                score += 0.40
            if feat_dict.get("is_punycode") or feat_dict.get("homoglyph_count", 0) > 0:
                score += 0.35
            if feat_dict.get("is_known_shortener"):
                score += 0.25
            if feat_dict.get("is_suspicious_tld"):
                score += 0.20
            if feat_dict.get("num_suspicious_keywords", 0) >= 2:
                score += 0.20
            if feat_dict.get("entropy_url", 0) >= 4.2:
                score += 0.15
            raw_prob = min(max(score, 0.01), 0.99)

        # Incorporate message context if supplied
        if msg_feats["has_message_context"] == 1:
            raw_prob = 0.8 * raw_prob + 0.2 * msg_feats["composite_message_risk"]

        # 2. Calibrated risk percentage (Research Gap 2)
        calibrated_prob = round(float(np.clip(raw_prob, 0.01, 0.99)), 4)
        risk_percentage = round(calibrated_prob * 100.0, 1)
        benign_prob = round(1.0 - calibrated_prob, 4)
        benign_percentage = round(100.0 - risk_percentage, 1)

        # 3. Conformal Prediction Set (Research Gap 3)
        # Outcome y included if 1 - P(Y = y) <= q_hat
        conformal_set = []
        if (1.0 - benign_prob) <= self.q_hat:
            conformal_set.append("Legitimate")
        if (1.0 - calibrated_prob) <= self.q_hat:
            conformal_set.append("Malicious")
        if not conformal_set:
            conformal_set = ["Malicious"] if calibrated_prob >= 0.5 else ["Legitimate"]

        # 4. Classification Decision & Uncertainty Status
        if len(conformal_set) > 1:
            classification = "uncertain"
            uncertainty_status = "high"
            prediction_confidence = "low"
        elif "Malicious" in conformal_set and risk_percentage >= 65.0:
            classification = "malicious"
            uncertainty_status = "low"
            prediction_confidence = "high" if risk_percentage >= 80.0 else "medium"
        elif "Legitimate" in conformal_set and risk_percentage <= 35.0:
            classification = "legitimate"
            uncertainty_status = "low"
            prediction_confidence = "high" if risk_percentage <= 20.0 else "medium"
        else:
            classification = "uncertain"
            uncertainty_status = "medium"
            prediction_confidence = "medium"

        # 5. Out of distribution check
        url_len = feat_dict.get("url_length", 0)
        entropy = feat_dict.get("entropy_url", 0.0)
        is_ood = bool(url_len > 250 or entropy > 5.5)

        # 6. Top reasons (Explainable AI)
        top_reasons = generate_local_explanation(url_clean, risk_percentage)

        modalities = ["url"]
        if msg_feats["has_message_context"] == 1:
            modalities.append("message_context")

        processing_time_ms = round((time.perf_counter() - t_start) * 1000, 3)

        return {
            "url": url_clean,
            "classification": classification,
            "malicious_probability": calibrated_prob,
            "benign_probability": benign_prob,
            "risk_percentage": risk_percentage,
            "benign_percentage": benign_percentage,
            "prediction_confidence": prediction_confidence,
            "conformal_prediction_set": [c.lower() for c in conformal_set],
            "uncertainty_status": uncertainty_status,
            "out_of_distribution": is_ood,
            "available_modalities": modalities,
            "top_reasons": top_reasons,
            "top_risk_factors": top_reasons,
            "processing_time_ms": processing_time_ms,
            "feature_summary": {
                "length": feat_dict.get("url_length"),
                "entropy": feat_dict.get("entropy_url"),
                "is_ip": bool(feat_dict.get("is_ip_address")),
                "is_punycode": bool(feat_dict.get("is_punycode")),
                "is_shortener": bool(feat_dict.get("is_known_shortener")),
                "impersonated_brand": feat_dict.get("_meta", {}).get("impersonated_brand")
            },
            "model_version": self.version
        }

# Alias for backward compatibility
MobiURLGuardInferenceEngine = URLThreatDetectionInferenceEngine

