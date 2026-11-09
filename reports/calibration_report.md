# Probability Calibration & Reliability Report (Research Gap 5)

**Objective**: Convert decision tree scores into mathematically grounded, trustworthy risk probabilities (0% - 100%).  
**Protocol**: Non-parametric Isotonic Regression on dedicated held-out calibration partition (4,500 URLs).  

---

## 1. Calibration Metrics Comparison

| Calibration Metric | Uncalibrated Raw Model | Post-Hoc Isotonic Calibrated | Relative Improvement |
|---|---|---|---|
| **Expected Calibration Error (ECE)** | **0.0174** | **0.0107** | **38.5% reduction** |
| **Brier Score Loss** | **0.0803** | **0.0802** | **0.1% improvement** |

---

## 2. Reliability Diagram Binned Distribution (10 Bins)

| Bin Range | Mean Confidence | Empirical Accuracy | Samples Count | Reliability Gap |
|---|---|---|---|---|
| [0.0 - 0.1] | 0.0491 | 0.0440 | 1,478 | 0.0051 |
| [0.1 - 0.2] | 0.1101 | 0.1126 | 231 | 0.0025 |
| [0.2 - 0.3] | 0.2340 | 0.2119 | 151 | 0.0221 |
| [0.3 - 0.4] | 0.3350 | 0.3228 | 443 | 0.0122 |
| [0.4 - 0.5] | 0.4355 | 0.4667 | 75 | 0.0312 |
| [0.5 - 0.6] | 0.5500 | 0.5500 | 0 | 0.0000 |
| [0.6 - 0.7] | 0.6200 | 0.6747 | 292 | 0.0547 |
| [0.7 - 0.8] | 0.7548 | 0.6667 | 45 | 0.0881 |
| [0.8 - 0.9] | 0.8439 | 0.8619 | 181 | 0.0180 |
| [0.9 - 1.0] | 0.9779 | 0.9744 | 1,604 | 0.0035 |
