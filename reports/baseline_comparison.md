# Multi-Model Baseline Evaluation Report (Layer 1)

**Framework**: MobiURL-Guard Cyber Defense Engine  
**Dataset**: `data/raw/dataset.csv` (Stratified 30,000 URLs)  
**Partitioning**: 70% Train (21,000) / 15% Held-out Calibration (4,500) / 15% Test (4,500)  
**Features**: 28 Lexical, Domain, Entropy, Unicode & Brand Indicators  

---

## 1. Comprehensive Performance Benchmark

| Model Architecture | Accuracy | Precision | Recall | F1-Score | MCC | Specificity | ROC-AUC | PR-AUC | FPR | FNR | Train (ms) | Infer (ms/sample) | Size (KB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 0.8831 | 0.9072 | 0.8531 | **0.8794** | 0.7676 | 0.9130 | 0.9549 | 0.9574 | 0.0870 | 0.1469 | 645.08 | 0.0002 | 1.8 |
| **Decision Tree** | 0.8938 | 0.9127 | 0.8705 | **0.8911** | 0.7884 | 0.9170 | 0.9500 | 0.9405 | 0.0830 | 0.1295 | 50.92 | 0.0002 | 25.09 |
| **Random Forest** | 0.9129 | 0.9292 | 0.8936 | **0.9111** | 0.8264 | 0.9321 | 0.9730 | 0.9763 | 0.0679 | 0.1064 | 347.94 | 0.0059 | 7676.81 |
| **Extra Trees** | 0.8942 | 0.9175 | 0.8660 | **0.8910** | 0.7897 | 0.9223 | 0.9603 | 0.9655 | 0.0777 | 0.1340 | 199.85 | 0.0057 | 4370.28 |
| **Gradient Boosting** | 0.9218 | 0.9336 | 0.9079 | **0.9206** | 0.8439 | 0.9356 | 0.9752 | 0.9774 | 0.0644 | 0.0921 | 3680.27 | 0.0023 | 812.79 |
| **XGBoost** | 0.9184 | 0.9352 | 0.8990 | **0.9167** | 0.8375 | 0.9379 | 0.9733 | 0.9757 | 0.0621 | 0.1010 | 2311.77 | 0.0007 | 319.66 |
| **LightGBM** | 0.9156 | 0.9316 | 0.8968 | **0.9138** | 0.8317 | 0.9343 | 0.9735 | 0.9760 | 0.0657 | 0.1032 | 122.62 | 0.0014 | 330.95 |

---

## 2. Key Observations
1. **Tree Ensembles**: Random Forest, Extra Trees, and LightGBM capture high-order non-linear feature interactions (such as brand impersonation flags combined with high entropy and punycode prefixes).
2. **Inference Latency Trade-Off**: Single decision trees and linear models achieve microsecond-level latency (<0.02ms), whereas deep gradient boosting trees require ~0.05-0.12ms per sample.
