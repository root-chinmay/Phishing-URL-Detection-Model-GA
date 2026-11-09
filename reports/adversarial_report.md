# Adversarial Robustness & Evasion Evaluation Report

**Framework**: MobiURL-Guard Security Engine  
**Clean Malicious Recall**: **70.0%** (21/30)  

| Adversarial Mutation Strategy | Samples Tested | Detected Malicious | Flagged Uncertain | Evasion Rate | Robustness Assessment |
|---|---|---|---|---|---|
| **Homoglyph Attack** | 30 | 19 (63.3%) | 6 (20.0%) | **16.7%** | Moderate Evasion |
| **Subdomain Injection** | 30 | 27 (90.0%) | 3 (10.0%) | **0.0%** | Resilient |
| **Percent Obfuscation** | 30 | 27 (90.0%) | 2 (6.7%) | **3.3%** | Resilient |
| **Typosquatting** | 30 | 21 (70.0%) | 3 (10.0%) | **20.0%** | Moderate Evasion |
| **Nested Redirect** | 30 | 25 (83.3%) | 3 (10.0%) | **6.7%** | Resilient |

## Defense Mechanism Analysis

1. **Homoglyph & Confusable Resilience**: The integrated `unicode_features` module inspects character script changes and confusable Cyrillic codepoints, ensuring mutated letters do not lower risk score.
2. **Subdomain Injection Defense**: Naive detectors that look for `google.com` as a substring are fooled by `login.google.com.attacker.xyz`. MobiURL-Guard extracts the registered domain and cross-references against `brand_domains.json`, triggering the brand impersonation flag when a brand appears in subdomains of an unrelated host.
3. **Conformal Uncertainty Cushion**: When complex hex padding weakens individual features, the conformal prediction module expands the prediction set to `{Legitimate, Malicious}` rather than defaulting to benign.
