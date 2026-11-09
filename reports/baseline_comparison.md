# Multi-Model Baseline Evaluation Report (Layer 1)

**Framework**: MobiURL-Guard Cyber Defense Engine  
**Dataset**: `data/raw/dataset.csv` (Stratified 30,000 URLs)  
**Partitioning**: 70% Train (21,000) / 15% Held-out Calibration (4,500) / 15% Test (4,500)  
**Features**: 28 Lexical, Domain, Entropy, Unicode & Brand Indicators  

---

## 1. Comprehensive Performance Benchmark

| Model Architecture | Accuracy | Precision | Recall | F1-Score | MCC | Specificity | ROC-AUC | PR-AUC | FPR | FNR | Train (ms) | Infer (ms/sample) | Size (KB) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 0.8784 | 0.9063 | 0.8438 | **0.8739** | 0.7587 | 0.9130 | 0.9533 | 0.9552 | 0.0870 | 0.1562 | 112.99 | 0.0002 | 1.8 |
| **Decision Tree** | 0.8940 | 0.9143 | 0.8692 | **0.8912** | 0.7889 | 0.9188 | 0.9531 | 0.9502 | 0.0812 | 0.1308 | 42.22 | 0.0001 | 24.78 |
| **Random Forest** | 0.9153 | 0.9288 | 0.8994 | **0.9139** | 0.8311 | 0.9312 | 0.9739 | 0.9770 | 0.0688 | 0.1006 | 309.37 | 0.0059 | 7569.44 |
| **Extra Trees** | 0.8947 | 0.9195 | 0.8647 | **0.8913** | 0.7907 | 0.9245 | 0.9612 | 0.9660 | 0.0755 | 0.1353 | 187.33 | 0.0058 | 4214.03 |
| **Gradient Boosting** | 0.9222 | 0.9317 | 0.9110 | **0.9212** | 0.8446 | 0.9334 | 0.9756 | 0.9776 | 0.0666 | 0.0890 | 3780.41 | 0.0018 | 812.23 |
| **XGBoost** | 0.9218 | 0.9376 | 0.9034 | **0.9202** | 0.8441 | 0.9401 | 0.9751 | 0.9775 | 0.0599 | 0.0966 | 2160.03 | 0.0005 | 315.88 |
| **LightGBM** | 0.9209 | 0.9363 | 0.9030 | **0.9193** | 0.8423 | 0.9387 | 0.9758 | 0.9782 | 0.0613 | 0.0970 | 108.61 | 0.0015 | 327.87 |

---

## 2. Key Observations
1. **Tree Ensembles**: Random Forest, Extra Trees, and LightGBM capture high-order non-linear feature interactions (such as brand impersonation flags combined with high entropy and punycode prefixes).
2. **Inference Latency Trade-Off**: Single decision trees and linear models achieve microsecond-level latency (<0.02ms), whereas deep gradient boosting trees require ~0.05-0.12ms per sample.
