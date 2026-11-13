# Conformal Prediction & Uncertainty Quantification Report (Research Gap 6)

**Objective**: Provide mathematically guaranteed prediction sets with finite-sample coverage (1 - alpha).  
**Method**: Split Conformal Prediction with quantile correction on held-out calibration partition.  

---

## 1. Conformal Coverage & Prediction Set Metrics

| Nominal Confidence (1 - alpha) | Empirical Coverage on Test | Average Set Size | Uncertainty Rate ({Legitimate, Malicious}) | Quantile Threshold q_hat |
|---|---|---|---|---|
| **90.0%** (alpha=0.10) | **92.1%** | 1.07 | 7.3% | 0.6492 |
| **95.0%** (alpha=0.05) | **96.1%** | 1.21 | 20.5% | 0.7107 |
| **99.0%** (alpha=0.01) | **99.0%** | 1.50 | 49.8% | 0.9390 |

---

## 2. Operational Semantics in MobiURL-Guard

- **`{Legitimate}`**: Confidently benign URL. Safe to proceed with normal navigation.
- **`{Malicious}`**: Confidently malicious phishing/threat URL. Immediate warning and navigation block.
- **`{Legitimate, Malicious}`**: **Uncertain / Insufficient Evidence**. Conformal theory dictates that evidence is ambiguous under the selected confidence level. The mobile application alerts the user: *"Unable to classify this URL with high confidence. Proceed with caution."*
