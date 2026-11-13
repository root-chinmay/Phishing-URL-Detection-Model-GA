# Probability Calibration & Reliability Report (Research Gap 5)

**Objective**: Convert decision tree scores into mathematically grounded, trustworthy risk probabilities (0% - 100%).  
**Protocol**: Non-parametric Isotonic Regression on dedicated held-out calibration partition (4,500 URLs).  

---

## 1. Calibration Metrics Comparison

| Calibration Metric | Uncalibrated Raw Model | Post-Hoc Isotonic Calibrated | Relative Improvement |
|---|---|---|---|
| **Expected Calibration Error (ECE)** | **0.0098** | **0.0049** | **50.0% reduction** |
| **Brier Score Loss** | **0.0796** | **0.0794** | **0.3% improvement** |

---

## 2. Reliability Diagram Binned Distribution (10 Bins)

| Bin Range | Mean Confidence | Empirical Accuracy | Samples Count | Reliability Gap |
|---|---|---|---|---|
| [0.0 - 0.1] | 0.0464 | 0.0431 | 1,602 | 0.0033 |
| [0.1 - 0.2] | 0.1000 | 0.1250 | 8 | 0.0250 |
| [0.2 - 0.3] | 0.2786 | 0.2784 | 643 | 0.0002 |
| [0.3 - 0.4] | 0.3418 | 0.3293 | 82 | 0.0125 |
| [0.4 - 0.5] | 0.4500 | 0.4500 | 0 | 0.0000 |
| [0.5 - 0.6] | 0.5500 | 0.5500 | 0 | 0.0000 |
| [0.6 - 0.7] | 0.6492 | 0.6485 | 330 | 0.0007 |
| [0.7 - 0.8] | 0.7297 | 0.6562 | 32 | 0.0735 |
| [0.8 - 0.9] | 0.8791 | 0.8914 | 267 | 0.0123 |
| [0.9 - 1.0] | 0.9814 | 0.9753 | 1,536 | 0.0061 |
