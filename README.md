# MobiURL-Guard: Mobile Malicious URL & Phishing Detection Framework

> **An Explainable, Calibrated, Adversarially Robust and Privacy-Aware Mobile Malicious URL Detection Framework**

[![GitHub Repository](https://img.shields.io/badge/GitHub-root--chinmay%2FPhishing--URL--Detection--Model--GA-blue?logo=github)](https://github.com/root-chinmay/Phishing-URL-Detection-Model-GA)
[![Vercel Deployment](https://img.shields.io/badge/Deploy-Vercel-black?logo=vercel)](https://vercel.com/new)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. System Architecture Overview

MobiURL-Guard is an edge-first cybersecurity framework engineered specifically for mobile devices and modern web applications. It accepts an arbitrary URL (plus optional SMS/chat message context) and outputs:
1. **Calibrated Malicious Risk Percentage (0% to 100%)**
2. **Estimated Benign Probability (100% - Risk)**
3. **Set-Valued Conformal Prediction Bounds (`{Legitimate}`, `{Malicious}`, or `{Legitimate, Malicious}` for uncertain evidence)**
4. **Explainable AI Attributions** identifying the top structural threat drivers
5. **Pre-flight Quishing Quarantine** for safe QR code decoding

```
[ Incoming URL / QR Code / SMS Message ]
                   │
                   ▼
       [ RFC Canonicalization ]
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│             28-Dimensional Edge Feature Engine         │
├────────────────────────────────────────────────────────┤
│ • Lexical: Length, digits, delimiters, keyword tokens  │
│ • Domain: IP host, subdomain depth, suspicious TLDs    │
│ • Entropy: Shannon entropy (URL, host, path, query)   │
│ • Unicode: Punycode (xn--), Cyrillic/Greek homoglyphs  │
│ • Brand: N-gram similarity & registered domain check   │
│ • Context: Psychological urgency & credential lures    │
└────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│          Distilled Student Tree Engine (1.95 KB)        │
│          Inference Latency: 0.012 ms (Pure Python/JS)  │
└────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│             Isotonic Probability Calibration           │
│             ECE: 0.0213 (82.4% Error Reduction)        │
└────────────────────────────────────────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│       Split Conformal Prediction (1 - alpha = 95%)     │
│   Outputs: {Legit}, {Malicious}, or {Legit, Malicious} │
└────────────────────────────────────────────────────────┘
                   │
                   ▼
[ Standardized JSON Assessment & Explainable Visual Dashboard ]
```

---

## 2. Key Research Contributions (12 Addressed Research Gaps)

| Research Gap | Prior Literature Limitation | MobiURL-Guard Solution | Implementation File |
|---|---|---|---|
| **Gap 1: Zero-Day Generalization** | Random splitting leaks domains, inflating accuracy (~99%). | Implemented **domain-disjoint splitting**; tested against unseen domain infrastructure. | `src/data/splitting.py` |
| **Gap 2: Calibrated Probabilities** | Raw neural network and tree logits are overconfident. | Non-parametric **Isotonic Regression**; evaluated with Expected Calibration Error (ECE). | `src/calibration/` |
| **Gap 3: Conformal Prediction** | Forced binary classifications hide ambiguity. | Set-valued conformal predictions guarantee **finite-sample coverage** (95%). | `src/uncertainty/conformal.py` |
| **Gap 4: Adversarial Robustness** | Attackers evade tokens via Cyrillic homoglyphs and padding. | Built **adversarial mutation suite**; validated defense against 5 attack types. | `src/security/adversarial.py` |
| **Gap 5: Brand Impersonation** | Static blacklists miss typosquatted brands. | SequenceMatcher n-gram similarity + subdomain registrant isolation. | `src/features/brand_detection.py` |
| **Gap 6: Message-Context Scoring** | Isolated URLs miss SMS/WhatsApp psychological urgency. | Linguistic scoring for urgency, credential demands, and prize lures. | `src/features/message_features.py` |
| **Gap 7: Quishing Quarantine** | Mobile scanners open physical QR codes automatically. | Pre-flight security quarantine isolates decoded URLs before user navigation. | `src/security/qr_scanner.py` |
| **Gap 8: Safe Redirect Analysis** | Link shorteners mask final landing destinations. | Safe offline shortener detection and open-redirect parameter parsing. | `src/security/redirect_analysis.py` |
| **Gap 9: Edge Distillation** | Heavy models (XGBoost/Transformers) drain phone battery. | Distilled into **11-node JSON tree**; executed by pure Python interpreter in 12 microseconds. | `src/models/student_model.py` |
| **Gap 10: Explainable AI** | Black-box scores fail to educate users. | Local directional attribution identifies top 3–5 threat reasons. | `src/explainability/` |
| **Gap 11: Concept Drift Monitoring** | Threat infrastructure shifts over time. | Centroid z-distance flagging Out-of-Distribution queries. | `src/uncertainty/out_of_distribution.py` |
| **Gap 12: Privacy Architecture** | Cloud scanners transmit browsing history to remote servers. | **100% On-Device Local Inference**. Zero URLs or message logs ever leave the phone. | Edge Architecture |

---

## 3. Machine Learning Experimental Results

Evaluated on canonicalized benchmark dataset (305 unique URLs, 28 extracted features):

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference / URL | Size (KB) |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 0.9787 | 1.0000 | 0.9630 | **0.9811** | 0.9907 | 0.005 ms | 0.91 KB |
| **Decision Tree (Student)** | 0.9787 | 0.9643 | 1.0000 | **0.9818** | 0.9750 | **0.004 ms** | **1.95 KB** |
| **Random Forest (100 Trees)** | 0.9787 | 0.9643 | 1.0000 | **0.9818** | 1.0000 | 0.170 ms | 149.6 KB |
| **Gradient Boosting** | 0.9787 | 0.9643 | 1.0000 | **0.9818** | 0.9750 | 0.023 ms | 87.8 KB |
| **Naive Bayes** | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 0.005 ms | 1.44 KB |

*Exact Equivalence Guarantee*: Desktop scikit-learn vs Mobile pure Python tree interpreter maximum delta: **`0.000000`**.

---

## 4. Running the Python Research Pipeline

### Setup Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run Dataset Audit
```bash
python3 scripts/audit_dataset.py
# Outputs: reports/dataset_statistics.json & reports/dataset_audit_report.md
```

### Train Baselines, Distill Student & Calibrate
```bash
python3 scripts/train_baselines.py
# Outputs: models/exported/student_model.json, reports/model_comparison.md, reports/calibration_report.md, reports/conformal_report.md
```

### Run Adversarial Robustness Evaluation
```bash
python3 scripts/evaluate_adversarial.py
# Outputs: reports/adversarial_report.md
```

### Run Unit Tests
```bash
pytest -v tests/
```

---

## 5. Web Application & Vercel Deployment

The repository includes a modern React + Vite + Tailwind CSS web dashboard ready for instant deployment on Vercel.

### Local Development
```bash
npm install
npm run dev
# Running on http://localhost:3000
```

### Push to GitHub Repository
The Git remote origin is configured for:
`https://github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git`

To push your code:
```bash
./push_to_github.sh <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>
```
Or manually:
```bash
git remote set-url origin https://<TOKEN>@github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git
git branch -M main
git push -u origin main
```

### Deploy to Vercel
1. Import the repository at [vercel.com/new](https://vercel.com/new).
2. Vercel automatically detects the Vite configuration in `vercel.json`.
3. Click **Deploy**.

---

## 6. Android APK Packaging (Buildozer)

To package the offline Android application using Buildozer and python-for-android:

```bash
# On Ubuntu / WSL2:
sudo apt update && sudo apt install -y git zip unzip openjdk-17-jdk autoconf libtool pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev libssl-dev
pip install buildozer cython

# Build Android APK in debug mode:
buildozer android debug
```
The resulting `.apk` will be output in `bin/` and functions completely offline without internet connectivity.

---

## 7. License
Distributed under the MIT License. Developed for advanced cybersecurity research and mobile threat defense.
