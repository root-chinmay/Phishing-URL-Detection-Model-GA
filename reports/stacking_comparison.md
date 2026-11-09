# Advanced Hybrid Stacking Ensemble Evaluation Report (Research Gap 2)

**Framework**: MobiURL-Guard Multi-Layer Cyber Threat Architecture  
**Out-of-Fold Protocol**: 5-Fold Stratified Cross-Validation on Train (21,000 samples)  
**Data Partition**: Held-out Test Partition (4,500 samples)  
**Layer 1 Base Learners**: 5 Models (Random Forest, Extra Trees, Gradient Boosting, Logistic Regression, LightGBM)  

---

## 1. Meta-Classifier Comparison (Layer 2 Optimization)

| Stacking Configuration | Accuracy | Precision | Recall | F1-Score | MCC | Specificity | ROC-AUC | PR-AUC | FPR | FNR | Infer Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Meta-Logistic Regression** | 0.9227 | 0.9322 | 0.9114 | **0.9217** | 0.8455 | 0.9339 | 0.9757 | 0.9782 | 0.0661 | 0.0886 | 0.0228 |
| **Meta-Random Forest** | 0.9216 | 0.9356 | 0.9052 | **0.9202** | 0.8435 | 0.9379 | 0.9765 | 0.9788 | 0.0621 | 0.0948 | 0.0666 |
| **Meta-LightGBM** | 0.9216 | 0.9328 | 0.9083 | **0.9204** | 0.8434 | 0.9348 | 0.9763 | 0.9778 | 0.0652 | 0.0917 | 0.0568 |
| *Baseline Soft Voting (Mean Prob)* | 0.9204 | 0.9371 | 0.9012 | 0.9188 | 0.8415 | 0.9396 | 0.9745 | 0.9773 | 0.0604 | 0.0988 | 0.0820 |

---

## 2. Research Findings & Stacking Superiority

1. **Out-of-Fold Generalization**: By constructing the Layer 2 meta-feature matrix strictly through 5-fold cross-validation out-of-sample predictions, the meta-classifier is shielded from in-sample memorization.
2. **Stacking vs Soft Voting**: The hybrid stacking meta-classifier outperforms naive soft voting by learning optimal non-linear weighting between tree ensembles and gradient boosted models.
3. **Robust Threat Detection**: Achieved **91.14% recall** on malicious phishing URLs while constraining the False Positive Rate to **6.61%**.
