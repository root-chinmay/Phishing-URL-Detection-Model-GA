# Advanced Hybrid Stacking Ensemble Evaluation Report (Research Gap 2)

**Framework**: MobiURL-Guard Multi-Layer Cyber Threat Architecture  
**Out-of-Fold Protocol**: 5-Fold Stratified Cross-Validation on Train (21,000 samples)  
**Data Partition**: Held-out Test Partition (4,500 samples)  
**Layer 1 Base Learners**: 5 Models (Random Forest, Extra Trees, Gradient Boosting, Logistic Regression, LightGBM)  

---

## 1. Meta-Classifier Comparison (Layer 2 Optimization)

| Stacking Configuration | Accuracy | Precision | Recall | F1-Score | MCC | Specificity | ROC-AUC | PR-AUC | FPR | FNR | Infer Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Meta-Logistic Regression** | 0.9184 | 0.9312 | 0.9034 | **0.9171** | 0.8373 | 0.9334 | 0.9744 | 0.9773 | 0.0666 | 0.0966 | 0.0158 |
| **Meta-Random Forest** | 0.9218 | 0.9356 | 0.9057 | **0.9204** | 0.8440 | 0.9379 | 0.9753 | 0.9778 | 0.0621 | 0.0943 | 0.0267 |
| **Meta-LightGBM** | 0.9196 | 0.9240 | 0.9141 | **0.9190** | 0.8392 | 0.9250 | 0.9755 | 0.9774 | 0.0750 | 0.0859 | 0.0192 |
| *Baseline Soft Voting (Mean Prob)* | 0.9158 | 0.9352 | 0.8932 | 0.9137 | 0.8324 | 0.9383 | 0.9730 | 0.9761 | 0.0617 | 0.1068 | 0.0820 |

---

## 2. Research Findings & Stacking Superiority

1. **Out-of-Fold Generalization**: By constructing the Layer 2 meta-feature matrix strictly through 5-fold cross-validation out-of-sample predictions, the meta-classifier is shielded from in-sample memorization.
2. **Stacking vs Soft Voting**: The hybrid stacking meta-classifier outperforms naive soft voting by learning optimal non-linear weighting between tree ensembles and gradient boosted models.
3. **Robust Threat Detection**: Achieved **90.57% recall** on malicious phishing URLs while constraining the False Positive Rate to **6.21%**.
