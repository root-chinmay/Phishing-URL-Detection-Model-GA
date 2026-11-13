import os
import json
import time
import numpy as np
from src.features.url_features import (
    extract_url_vector,
    extract_url_feature_dict,
    extract_advanced_url_features,
    FEATURE_NAMES
)
from src.features.message_features import extract_message_features
from src.explainability.local_explainer import generate_local_explanation
from src.models.student_model import LightweightTreeInterpreter
from src.security.redirect_analysis import (
    analyze_redirect_risk_offline,
    resolve_redirect_chain,
    canonicalize_url_for_comparison
)


OFFICIAL_MAJOR_DOMAINS = (
    "google.com", "github.com", "wikipedia.org", "python.org", "mozilla.org",
    "amazon.com", "amazon.in", "apple.com", "microsoft.com", "paypal.com",
    "youtube.com", "linkedin.com", "stackoverflow.com", "cloudflare.com",
    "vercel.com", "npmjs.com", "adobe.com", "dropbox.com", "zoom.us",
    "slack.com", "stripe.com", "shopify.com", "openai.com", "bbc.com",
    "nytimes.com", "arxiv.org", "ieee.org", "acm.org"
)


class URLThreatDetectionInferenceEngine:
    """
    Unified URL Threat Detection Mobile & Research Inference Engine.
    Executes calibrated probability estimation, split conformal prediction sets,
    OOD detection, safe shortener destination resolution, advanced obfuscation analysis,
    and localized explainability.
    """
    def __init__(self, model_path: str = "models/exported/student_model.json", q_hat: float = 0.62):
        self.model_path = model_path
        self.q_hat = q_hat
        self.version = "1.1.0"
        self.interpreter = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            self.interpreter = LightweightTreeInterpreter.load_from_json(self.model_path)
        else:
            # Fallback rules-assisted inference if json not yet compiled
            self.interpreter = None

    def _score_single_url(self, target_url: str) -> tuple[float, dict]:
        """Compute base ML probability + feature dictionary for a canonical target URL."""
        feat_vector = extract_url_vector(target_url)
        feat_dict = extract_url_feature_dict(target_url)

        if self.interpreter is not None:
            raw_prob = self.interpreter.predict_proba_single(feat_vector)
        else:
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

        return float(raw_prob), feat_dict

    def analyze_url(
        self,
        url: str,
        message_text: str = None,
        resolve_shorteners: bool = True,
        redirect_info: dict = None
    ) -> dict:
        """Analyze a URL (automatically unshortening/normalizing if needed) and produce standardized risk output."""
        if not url or not url.strip():
            raise ValueError("URL cannot be empty.")

        url_clean = url.strip()
        t_start = time.perf_counter()

        # 0. Pre-scan for shorteners & embedded open-redirect parameters
        offline_redirect = analyze_redirect_risk_offline(url_clean)
        is_input_shortener = bool(offline_redirect.get("is_known_shortener"))

        resolved_redirect = redirect_info
        if resolved_redirect is None and resolve_shorteners and is_input_shortener:
            resolved_redirect = resolve_redirect_chain(url_clean, max_hops=8, timeout=3.5)

        # Determine effective target URL for consistent evaluation
        effective_url = url_clean
        used_resolved_target = False

        if resolved_redirect and resolved_redirect.get("resolved_successfully") and resolved_redirect.get("final_url"):
            effective_url = resolved_redirect["final_url"]
            used_resolved_target = True
        elif offline_redirect.get("has_redirect_param") and offline_redirect.get("potential_embedded_target"):
            embedded = offline_redirect["potential_embedded_target"]
            if isinstance(embedded, str) and embedded.lower().startswith(("http://", "https://")):
                # Evaluate embedded target alongside host if host isn't already known malicious
                effective_url = embedded
                used_resolved_target = True

        canonical_target = canonicalize_url_for_comparison(effective_url) or effective_url

        # 1. Base prediction on canonical target URL so shortener + long URL align closely
        raw_prob, feat_dict = self._score_single_url(canonical_target)

        # Extract advanced structural, DGA, obfuscation, and redirect features
        adv_feats = extract_advanced_url_features(canonical_target, resolved_redirect)
        if is_input_shortener and not used_resolved_target:
            adv_feats["shortener_unresolved_flag"] = 1
            adv_feats["shortener_resolved_flag"] = 0
        elif is_input_shortener and used_resolved_target:
            adv_feats["shortener_resolved_flag"] = 1
            adv_feats["shortener_unresolved_flag"] = 0

        # 2. Advanced probabilistic log-odds calibration
        p_base = float(np.clip(raw_prob, 0.035, 0.94))
        log_odds = float(np.log(p_base / (1.0 - p_base)))

        if adv_feats.get("is_executable_drop"):
            log_odds += 3.6
            if adv_feats.get("is_upload_drop_dir"):
                log_odds += 1.1
            if adv_feats.get("has_random_hash_filename"):
                log_odds += 0.7
        if adv_feats.get("protocol_downgrade_flag"):
            log_odds += 1.5
        if adv_feats.get("has_userinfo_at_obfuscation"):
            log_odds += 2.2
        if adv_feats.get("has_encoded_payload"):
            log_odds += 1.2
        if adv_feats.get("has_port_obfuscation"):
            log_odds += 1.0
        if adv_feats.get("has_double_extension_or_script"):
            log_odds += 1.1
        if adv_feats.get("consonant_cluster_anomaly"):
            log_odds += 0.9
        if adv_feats.get("char_ngram_phishing_score", 0) >= 0.25:
            log_odds += 1.3 * adv_feats["char_ngram_phishing_score"]
        if adv_feats.get("cross_domain_redirect_count", 0) >= 3:
            log_odds += 0.8
        elif adv_feats.get("redirect_hop_count", 0) >= 4:
            log_odds += 0.6

        # Nuanced micro-calibration from exact URL structural entropy and length
        entropy_val = float(feat_dict.get("entropy_url", 3.8))
        url_len = float(feat_dict.get("url_length", 45))
        log_odds += (entropy_val - 3.8) * 0.22
        log_odds += max(0.0, url_len - 45.0) * 0.006

        if adv_feats.get("is_http_non_ssl") and log_odds > -2.0:
            log_odds += 0.45

        # If input was an open-redirect wrapper with an embedded risky target, also ensure base host risk isn't lost
        if offline_redirect.get("has_redirect_param") and effective_url != url_clean:
            orig_prob, _ = self._score_single_url(canonicalize_url_for_comparison(url_clean) or url_clean)
            if orig_prob > 0.4:
                log_odds += 0.5

        # If a known shortener could NOT be resolved (offline / dead / blocked), retain mild caution
        if is_input_shortener and not used_resolved_target:
            log_odds = max(log_odds + 1.1, -0.32)
        elif is_input_shortener and used_resolved_target:
            if log_odds > -0.85:
                log_odds += 0.15

        msg_feats = extract_message_features(message_text)
        if msg_feats["has_message_context"] == 1:
            log_odds += float(msg_feats.get("composite_message_risk", 0.0)) * 1.5

        # Sigmoid probability
        calibrated_raw = 1.0 / (1.0 + np.exp(-log_odds))

        # Verified authority domain guard on canonical target host (only when free of obfuscation and executable drops)
        target_host = feat_dict.get("_meta", {}).get("hostname", "")
        is_official_target = any(target_host == d or target_host.endswith(f".{d}") for d in OFFICIAL_MAJOR_DOMAINS)
        if (
            is_official_target
            and feat_dict.get("is_punycode", 0) == 0
            and feat_dict.get("homoglyph_count", 0) == 0
            and adv_feats.get("has_userinfo_at_obfuscation", 0) == 0
            and adv_feats.get("protocol_downgrade_flag", 0) == 0
            and adv_feats.get("is_executable_drop", 0) == 0
            and not offline_redirect.get("has_redirect_param")
        ):
            calibrated_raw = 0.01

        # 3. Calibrated risk percentage (bounded 1.0% to 97.2% - eliminates the flat 99% ceiling)
        calibrated_prob = round(float(np.clip(calibrated_raw, 0.01, 0.972)), 4)
        risk_percentage = round(calibrated_prob * 100.0, 1)
        benign_prob = round(1.0 - calibrated_prob, 4)
        benign_percentage = round(100.0 - risk_percentage, 1)

        # 4. Conformal Prediction Set
        conformal_set = []
        if (1.0 - benign_prob) <= self.q_hat:
            conformal_set.append("Legitimate")
        if (1.0 - calibrated_prob) <= self.q_hat:
            conformal_set.append("Malicious")
        if not conformal_set:
            conformal_set = ["Malicious"] if calibrated_prob >= 0.5 else ["Legitimate"]

        # 5. Classification Decision & Uncertainty Status
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

        # 6. Out of distribution check
        url_len = feat_dict.get("url_length", 0)
        entropy = feat_dict.get("entropy_url", 0.0)
        is_ood = bool(url_len > 250 or entropy > 5.5 or (is_input_shortener and not used_resolved_target))

        # 7. Top reasons (Explainable AI)
        top_reasons = generate_local_explanation(
            canonical_target,
            risk_percentage,
            advanced_feats=adv_feats,
            redirect_info=resolved_redirect
        )

        modalities = ["url"]
        if used_resolved_target:
            modalities.append("redirect_resolution")
        if msg_feats["has_message_context"] == 1:
            modalities.append("message_context")

        processing_time_ms = round((time.perf_counter() - t_start) * 1000, 3)

        return {
            "url": url_clean,
            "effective_url": canonical_target,
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
            "redirect_info": resolved_redirect,
            "advanced_features": adv_feats,
            "feature_summary": {
                "length": feat_dict.get("url_length"),
                "entropy": feat_dict.get("entropy_url"),
                "is_ip": bool(feat_dict.get("is_ip_address")),
                "is_punycode": bool(feat_dict.get("is_punycode")),
                "is_shortener": bool(is_input_shortener or feat_dict.get("is_known_shortener")),
                "shortener_resolved": used_resolved_target,
                "impersonated_brand": feat_dict.get("_meta", {}).get("impersonated_brand")
            },
            "model_version": self.version
        }


# Alias for backward compatibility
MobiURLGuardInferenceEngine = URLThreatDetectionInferenceEngine
