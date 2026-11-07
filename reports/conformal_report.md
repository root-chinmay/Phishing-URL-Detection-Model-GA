# Conformal Prediction & Uncertainty Quantification Report

**Objective**: Provide mathematically grounded prediction sets under finite-sample guarantee (1 - alpha).  
**Calibration Scheme**: Split Conformal Prediction with finite-sample quantile correction.  

| Target Coverage (1 - alpha) | Empirical Coverage on Test | Avg Prediction Set Size | Uncertainty Rate ({Legit, Phish}) | Calibrated Quantile q_hat |
|---|---|---|---|---|
| **90.0%** (alpha=0.10) | **97.9%** | 1.00 | 0.0% | 0.0476 |
| **95.0%** (alpha=0.05) | **97.9%** | 1.00 | 0.0% | 0.0476 |
| **99.0%** (alpha=0.01) | **100.0%** | 1.60 | 59.6% | 0.9524 |

## Interpretation of Prediction Sets

- **`{Legitimate}`**: Confidently safe URL with non-conformity exceeding bounds for maliciousness.
- **`{Malicious}`**: Confidently malicious URL with verified threat indicators.
- **`{Legitimate, Malicious}`**: **Uncertain / Insufficient Evidence**. Conformal coverage requires including both hypotheses at target confidence level. The mobile UI displays 'Unable to determine this URL reliably. Exercise caution.'
