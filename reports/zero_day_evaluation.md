# Zero-Day & Domain-Disjoint Generalisation Report (Research Gap 3)

**Objective**: Measure whether detection capability relies on memorizing specific domain names or truly generalises to unfamiliar / zero-day malicious domains without fixed-brand lists.  
**Dataset Evaluated**: `data/raw/dataset.csv` (12,000 balanced partition)  

---

## 1. Generalisation Protocol Comparison

| Splitting Protocol | Domain Overlap Across Train/Test | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Generalisation Degradation |
|---|---|---|---|---|---|---|---|
| **Random Stratified Split** | **319 Shared Domains** (Intra-domain leakage present) | **0.8933** | 0.8960 | 0.8900 | **0.8930** | 0.9456 | Baseline (Optimistic) |
| **Domain-Disjoint Split (Zero-Day)** | **0 Shared Domains (100% Disjoint Domains)** | **0.8677** | 0.8803 | 0.8640 | **0.8721** | 0.8988 | Delta: 0.0209 (2.34%) |

---

## 2. Out-of-Distribution (OOD) Quantification

- **OOD Detection Mechanism**: Standardized Mahalanobis z-distance across numerical lexical/entropy feature space.
- **Empirical OOD Rate on Unseen Domains**: **30.62%** of test URLs flagged as out-of-distribution relative to the training centroid.
- **Operational Principle**: An unfamiliar domain is **NOT** automatically classified as malicious; instead, high OOD distance triggers elevated uncertainty and wide conformal prediction sets `{Legitimate, Malicious}`.

---

## 3. Research Insights & Defenses Against Domain Evasion

1. **Elimination of Intra-Domain Artifacts**: Standard phishing papers report 98-99% accuracy because identical domains leak across train and test sets. By enforcing complete domain disjointness, MobiURL-Guard demonstrates an authentic zero-day F1-score of **0.8721**.
2. **Inductive Lexical & Entropy Features**: The model accurately detects phishing hosted on never-before-seen domains by relying on domain hierarchy depth, Shannon entropy, brand-similarity tokens, and path-based credential harvesting indicators rather than static domain whitelists.
