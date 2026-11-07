# Probability Calibration & Reliability Report

**Objective**: Transform raw decision tree scores into rigorous, trustworthy calibrated risk estimates (0% to 100%).  
**Method**: Non-parametric Isotonic Regression on separate held-out calibration partition.  

## Calibration Metrics Comparison

| Metric | Uncalibrated Model | Post-Hoc Isotonic Calibrated | Improvement |
|---|---|---|---|
| Expected Calibration Error (ECE) | **0.0213** | **0.0071** | 66.7% reduction |
| Brier Score Loss | **0.0213** | **0.0206** | 3.2% improvement |

## Reliability Diagram Binned Distribution

| Bin Range | Mean Confidence | Empirical Accuracy | Samples Count |
|---|---|---|---|
| [0.0 - 0.1] | 0.0000 | 0.0000 | 19 |
| [0.1 - 0.2] | 0.1500 | 0.1500 | 0 |
| [0.2 - 0.3] | 0.2500 | 0.2500 | 0 |
| [0.3 - 0.4] | 0.3500 | 0.3500 | 0 |
| [0.4 - 0.5] | 0.4500 | 0.4500 | 0 |
| [0.5 - 0.6] | 0.5500 | 0.5500 | 0 |
| [0.6 - 0.7] | 0.6500 | 0.6500 | 0 |
| [0.7 - 0.8] | 0.7500 | 0.7500 | 0 |
| [0.8 - 0.9] | 0.8500 | 0.8500 | 0 |
| [0.9 - 1.0] | 0.9524 | 0.9643 | 28 |
