# Adversarial Robustness & Evasion Evaluation Report

**Framework**: MobiURL-Guard Security Engine  
**Clean Malicious Recall**: **96.7%** (29/30)  

| Adversarial Mutation Strategy | Samples Tested | Detected Malicious | Flagged Uncertain | Evasion Rate | Robustness Assessment |
|---|---|---|---|---|---|
| **Homoglyph Attack** | 30 | 29 (96.7%) | 1 (3.3%) | **0.0%** | Resilient |
| **Subdomain Injection** | 30 | 30 (100.0%) | 0 (0.0%) | **0.0%** | Resilient |
| **Percent Obfuscation** | 30 | 21 (70.0%) | 1 (3.3%) | **26.7%** | Moderate Evasion |
| **Typosquatting** | 30 | 29 (96.7%) | 1 (3.3%) | **0.0%** | Resilient |
| **Nested Redirect** | 30 | 28 (93.3%) | 2 (6.7%) | **0.0%** | Resilient |

## Defense Mechanism Analysis

1. **Homoglyph & Confusable Resilience**: The integrated `unicode_features` module inspects character script changes and confusable Cyrillic codepoints, ensuring mutated letters do not lower risk score.
2. **Subdomain Injection Defense**: Naive detectors that look for `google.com` as a substring are fooled by `login.google.com.attacker.xyz`. MobiURL-Guard extracts the registered domain and cross-references against `brand_domains.json`, triggering the brand impersonation flag when a brand appears in subdomains of an unrelated host.
3. **Conformal Uncertainty Cushion**: When complex hex padding weakens individual features, the conformal prediction module expands the prediction set to `{Legitimate, Malicious}` rather than defaulting to benign.
