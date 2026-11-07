# Dataset Audit & Ingestion Report

**Project**: MobiURL-Guard: Mobile Malicious URL Detection Framework  
**File Audited**: `data/raw/dataset.csv`  
**Date Generated**: 2026-11-07  

---

## 1. Executive Summary

A comprehensive forensic audit of the training dataset was performed. The dataset contains **310 raw records** which were canonicalized and deduplicated to **305 unique URLs** across **216 distinct registered domains**.

| Metric | Measured Value | Notes |
|---|---|---|
| Total Raw Records | **310** | Initial ingestion count |
| Canonical Deduplicated URLs | **305** | Scheme normalized, trailing slashes pruned |
| Duplicates Removed | **5** | Exact URL redundancy eliminated |
| Benign Samples (Class 0) | **150** (49.2%) | Legitimate academic, enterprise, news & reference |
| Malicious Samples (Class 1) | **155** (50.8%) | Brand phishing, IP hosts, homoglyphs & shorteners |
| Unique Registered Domains | **216** | Evaluated for domain-disjoint splitting |
| Missing / Null Values | **0** across critical fields | Complete label and string integrity |

---

## 2. Column Schema & Data Types

| Column Name | Data Type | Null Count | Semantic Description |
|---|---|---|---|
| `url` | `object (string)` | 0 | Raw input URL string |
| `label` | `int64` | 0 | Target binary label (0: Benign, 1: Malicious) |
| `domain` | `object (string)` | 0 | Hostname / registered domain label |
| `category` | `object (string)` | 0 | Phishing taxonomy (brand_impersonation, IP, homoglyph) |
| `is_synthetic` | `int64` | 0 | Indicator for synthetic benchmark variations |

---

## 3. Data Leakage Assessment & Safeguards

1. **Intra-Domain Leakage Prevention**: In conventional random train/test splitting, URLs sharing the same base domain (e.g. `login.paypal-update.xyz/a` and `login.paypal-update.xyz/b`) leak across partitions, inflating apparent test accuracy. We implement `create_domain_disjoint_split` in `src/data/splitting.py` to prevent any domain from bridging the train and test sets.
2. **Deterministic Canonicalization**: URLs are normalized with RFC-compliant scheme normalization and lowercased hostnames before feature extraction.
3. **No Synthetic Oversampling Before Split**: Oversampling or SMOTE, if used, is strictly restricted to training partitions only.
