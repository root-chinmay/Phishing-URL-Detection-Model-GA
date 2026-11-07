# Comprehensive Research Gap Mapping & Contributions

**Project**: MobiURL-Guard: An Explainable, Calibrated, Adversarially Robust and Privacy-Aware Mobile Malicious URL Detection Framework  
**Author**: Cybersecurity Research & Development Team  
**Date**: 2026-11-07  

---

## Executive Overview

This document explicitly maps the 12 core cybersecurity research gaps addressed in MobiURL-Guard, linking prior literature limitations to our experimental methodology, code implementation, and evaluation results.

---

### Gap 1: Cross-Domain and Zero-Day Generalization
- **Prior Work Limitation**: Existing phishing classifiers rely on random train-test splitting where subdomains of the same host leak between sets, reporting artificially high accuracy (~99%) that plummets when encountering unfamiliar zero-day domains.
- **Our Contribution**: Implemented `create_domain_disjoint_split` in `src/data/splitting.py` enforcing strict zero domain overlap. Extracted generalized lexical, entropy, and punycode structural features that do not memorize specific domain names.
- **Evaluated In**: `scripts/evaluate_generalisation.py` -> `reports/generalisation_report.md`.

### Gap 2: Calibrated Malicious-Risk Percentages
- **Prior Work Limitation**: Raw neural network and tree classifier scores (e.g. sigmoid outputs) are notoriously uncalibrated and overconfident, misleading mobile users with false certainty.
- **Our Contribution**: Applied non-parametric Isotonic Regression and Platt scaling on a strictly held-out calibration partition (15% split). Evaluated Expected Calibration Error (ECE) and Brier score loss.
- **Evaluated In**: `src/calibration/probability_calibration.py` -> `reports/calibration_report.md`.

### Gap 3: Conformal Prediction & Set-Valued Uncertainty
- **Prior Work Limitation**: Conventional detectors force a binary point decision (Safe vs Malicious), failing to convey statistical uncertainty when evidence is ambiguous.
- **Our Contribution**: Implemented Split Conformal Prediction (`src/uncertainty/conformal.py`) with finite-sample quantile correction providing rigorous 90%, 95%, and 99% coverage guarantees. Prediction sets allow returning `{Legitimate, Malicious}` for uncertain samples.
- **Evaluated In**: `reports/conformal_report.md`.

### Gap 4: Adversarial URL Perturbations & Evasion Attacks
- **Prior Work Limitation**: Phishing actors evade token-based and regex detectors via Cyrillic homoglyphs, brand subdomain injection, and percent-encoding obfuscation.
- **Our Contribution**: Developed `AdversarialURLPerturber` (`src/security/adversarial.py`) evaluating clean vs perturbed recall across 5 attack strategies.
- **Evaluated In**: `scripts/evaluate_adversarial.py` -> `reports/adversarial_report.md`.

### Gap 5: Brand Impersonation Detection
- **Prior Work Limitation**: Blacklists and simple keyword matching either miss typosquatted brands (e.g. `paypa1`) or falsely flag legitimate discussions.
- **Our Contribution**: Built `src/features/brand_detection.py` integrating SequenceMatcher character n-gram similarity, registered domain boundary checks, and `config/brand_domains.json`.
- **Evaluated In**: Verified against known financial, cloud, and social media targets.

### Gap 6: Message-Context-Aware Detection (Smishing / Phishing)
- **Prior Work Limitation**: Links received on mobile via SMS or WhatsApp carry psychological urgency that isolated URL analysis ignores.
- **Our Contribution**: Developed optional `src/features/message_features.py` detecting urgency tokens, credential demands, and financial lure keywords without reading private messages without consent.
- **Evaluated In**: Composite scoring in `MobiURLGuardInferenceEngine`.

### Gap 7: QR-Code & Quishing Quarantine Detection
- **Prior Work Limitation**: Mobile users scanning malicious physical QR codes are instantly redirected to landing pages before inspection can occur.
- **Our Contribution**: Implemented `src/security/qr_scanner.py` with strict pre-flight quarantine isolation; URL is parsed, decoded, and audited before user is prompted to open.

### Gap 8: URL Shorteners & Safe Redirect Analysis
- **Prior Work Limitation**: Shortened links hide malicious destinations; resolving them carelessly exposes the client to server-side tracking, drive-by downloads, or SSRF.
- **Our Contribution**: Implemented safe offline shortener identification and open-redirect parameter detection (`src/security/redirect_analysis.py`).

### Gap 9: Knowledge Distillation for Mobile Edge
- **Prior Work Limitation**: Heavy ensemble models (XGBoost, deep Transformers) cannot run efficiently on mid-range Android devices due to RAM, battery, and package size constraints.
- **Our Contribution**: Distilled ensemble knowledge into an 11-node compact Decision Tree exported as JSON (`models/exported/student_model.json`) and created `LightweightTreeInterpreter` running with 0.000000 desktop-mobile delta in 12 microseconds.
- **Evaluated In**: `reports/mobile_performance_report.md`.

### Gap 10: Adversarially Robust Explainable AI
- **Prior Work Limitation**: Black-box ML predictions fail to explain *why* a link is dangerous, leaving users unable to learn threat indicators.
- **Our Contribution**: Designed `src/explainability/local_explainer.py` generating localized, human-understandable security rationales for the top 3-5 risk factors.

### Gap 11: Concept Drift & Continuous Learning
- **Prior Work Limitation**: Cyber threat infrastructure mutates over time, causing silent performance decay.
- **Our Contribution**: Implemented Out-of-Distribution scoring (`src/uncertainty/out_of_distribution.py`) flagging anomalous feature shifts without treating unverified user inputs as ground truth.

### Gap 12: Privacy-Preserving Mobile Architecture
- **Prior Work Limitation**: Cloud-based URL reputation scanners upload user browsing history and chat messages to external corporate servers.
- **Our Contribution**: MobiURL-Guard executes 100% locally on-device. No URLs, browsing histories, or message text are ever transmitted to any external server.
