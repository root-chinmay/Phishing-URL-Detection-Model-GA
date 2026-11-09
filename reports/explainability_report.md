# Explainable Artificial Intelligence (XAI) Report (Research Gap 8)

**Objective**: Provide human-interpretable forensic rationale for every automated threat prediction, distinguishing observed empirical indicators from model inference.  
**Framework**: MobiURL-Guard Local Feature Contribution & Hierarchical Explainer  

---

## 1. Qualitative Forensic Case Studies

### Case: Brand Impersonation / Homoglyph
- **Input URL**: `https://secure-login.paypa1.com.account-update.xyz/auth?dest=wallet`
- **Ground Truth**: Phishing
- **Predicted Malicious Risk**: **99.0%** | **Classification**: `MALICIOUS`
- **Conformal Prediction Set**: `['malicious']`
- **Inference Latency**: `3.066 ms`
- **Forensic Risk Drivers**:
  - Brand Impersonation Detected: Domain mimics 'PayPal' while registered on an unrelated host.
  - Deep Nested Subdomains: Contains 3 subdomains masking actual registrant.
  - High-Risk TLD (.xyz): Commonly utilized in disposable phishing kits.
  - Multiple Credential Harvesting Keywords: Found 6 security-sensitive keywords in URL string.

---
### Case: Direct IP Host Credential Harvester
- **Input URL**: `http://192.168.1.100:8080/admin/secure_login.php?dest=dashboard`
- **Ground Truth**: Malicious
- **Predicted Malicious Risk**: **1.0%** | **Classification**: `LEGITIMATE`
- **Conformal Prediction Set**: `['legitimate']`
- **Inference Latency**: `0.944 ms`
- **Forensic Risk Drivers**:
  - Direct IP Hostname: URL accesses a raw IP address directly instead of a legitimate registered domain name.
  - Standard Domain Structure: Registered with normal depth and recognized Top-Level Domain.
  - No Obfuscation Detected: Free of homoglyphs, punycode prefixes, and nested open-redirects.

---
### Case: High-Entropy Cloud Storage Phish
- **Input URL**: `https://s3.dualstack.us-west-2.amazonaws.com/payhoa-prod/089e5f07d037dbc45680caad6f062a1b9f9b35afd2e1a88f09d82e0d449fb0c7/login.html`
- **Ground Truth**: Phishing
- **Predicted Malicious Risk**: **99.0%** | **Classification**: `MALICIOUS`
- **Conformal Prediction Set**: `['malicious']`
- **Inference Latency**: `2.383 ms`
- **Forensic Risk Drivers**:
  - Brand Impersonation Detected: Domain mimics 'Amazon' while registered on an unrelated host.
  - Deep Nested Subdomains: Contains 3 subdomains masking actual registrant.
  - Elevated Shannon Entropy (4.9015): High random character distribution in URL structure.
  - Abnormally Long URL (132 characters): Often indicates obfuscation or embedded data.

---
### Case: Known Link Shortener with Masked Query
- **Input URL**: `https://bit.ly/3xY9zqW?redirect=http%3A%2F%2Fmalicious-site.ru%2Fpayload`
- **Ground Truth**: Suspicious Redirect
- **Predicted Malicious Risk**: **99.0%** | **Classification**: `MALICIOUS`
- **Conformal Prediction Set**: `['malicious']`
- **Inference Latency**: `1.461 ms`
- **Forensic Risk Drivers**:
  - Masked Link Shortener: Destination domain is a known URL shortener that conceals the true landing page.
  - Elevated Shannon Entropy (4.808): High random character distribution in URL structure.

---
### Case: Legitimate Academic Institution
- **Input URL**: `https://www.rmit.edu.au/study-with-us/international-students`
- **Ground Truth**: Legitimate
- **Predicted Malicious Risk**: **6.7%** | **Classification**: `LEGITIMATE`
- **Conformal Prediction Set**: `['legitimate']`
- **Inference Latency**: `1.657 ms`
- **Forensic Risk Drivers**:
  - Standard Domain Structure: Registered with normal depth and recognized Top-Level Domain.
  - No Obfuscation Detected: Free of homoglyphs, punycode prefixes, and nested open-redirects.
  - Normal Character Distribution: Shannon entropy matches standard web application routing.

---

## 2. Global Feature Importance Hierarchy (Distilled Student Tree)

The student model allocates split priority to features that provide maximal information gain against deceptive URLs:

| Rank | Feature Identifier | Split Frequency in Distilled Model | Semantic Cyber Role |
|---|---|---|---|
| 1 | `entropy_url` | **23 nodes** | Detects obfuscated random tokens and long hex payloads |
| 2 | `entropy_hostname` | **23 nodes** | Lexical and structural threat differentiator |
| 3 | `hostname_length` | **14 nodes** | Captures long deceptive subdomains and IP hosts |
| 4 | `num_subdomains` | **12 nodes** | Lexical and structural threat differentiator |
| 5 | `url_length` | **11 nodes** | Flags excessive URL padding and nested redirection paths |
| 6 | `num_hyphens` | **10 nodes** | Lexical and structural threat differentiator |
| 7 | `num_digits` | **6 nodes** | Lexical and structural threat differentiator |
| 8 | `path_length` | **6 nodes** | Lexical and structural threat differentiator |
| 9 | `entropy_path` | **6 nodes** | Lexical and structural threat differentiator |
| 10 | `num_slashes` | **6 nodes** | Detects deep nested routing structures |

---

## 3. Explanation Consistency & Lightweight Mobile Architecture

1. **Observed Evidence vs. Inferred Risk**: The explainer clearly separates concrete lexical facts (e.g. `num_subdomains >= 3`, `entropy_url = 4.66`) from the model's calibrated risk interpretation.
2. **Offline Edge Feasibility**: Unlike heavy Shapley-value recalculation (which requires running hundreds of model passes per URL taking >500ms), MobiURL-Guard's hierarchical rule-path explainer operates in **< 0.05ms**, making it practical for real-time mobile notifications.
