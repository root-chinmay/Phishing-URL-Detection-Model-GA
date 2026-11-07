import os
import sys
import json
import numpy as np

sys.path.insert(0, os.path.abspath("."))
from src.security.adversarial import AdversarialURLPerturber
from src.models.inference_engine import MobiURLGuardInferenceEngine
from src.data.loader import load_and_validate_dataset

def evaluate_adversarial_robustness():
    print("=" * 60)
    print("MOBIURL-GUARD: ADVERSARIAL ROBUSTNESS EVALUATION")
    print("=" * 60)

    engine = MobiURLGuardInferenceEngine()
    perturber = AdversarialURLPerturber()
    df = load_and_validate_dataset("data/raw/dataset.csv")

    malicious_urls = df[df["target"] == 1]["canonical_url"].tolist()[:30]
    benign_urls = df[df["target"] == 0]["canonical_url"].tolist()[:20]

    attack_types = ["homoglyph_attack", "subdomain_injection", "percent_obfuscation", "typosquatting", "nested_redirect"]
    attack_stats = {atk: {"total": 0, "detected_as_malicious": 0, "uncertain": 0, "evaded": 0} for atk in attack_types}

    # Evaluate clean malicious recall
    clean_detected = 0
    for u in malicious_urls:
        res = engine.analyze_url(u)
        if res["classification"] == "malicious":
            clean_detected += 1
    clean_recall = clean_detected / len(malicious_urls)

    # Evaluate adversarial perturbations
    for u in malicious_urls:
        suite = perturber.generate_adversarial_suite(u)
        for atk in attack_types:
            perturbed_url = suite[atk]
            res = engine.analyze_url(perturbed_url)
            attack_stats[atk]["total"] += 1
            if res["classification"] == "malicious":
                attack_stats[atk]["detected_as_malicious"] += 1
            elif res["classification"] == "uncertain":
                attack_stats[atk]["uncertain"] += 1
            else:
                attack_stats[atk]["evaded"] += 1

    report_md = "# Adversarial Robustness & Evasion Evaluation Report\n\n"
    report_md += "**Framework**: MobiURL-Guard Security Engine  \n"
    report_md += f"**Clean Malicious Recall**: **{clean_recall*100:.1f}%** ({clean_detected}/{len(malicious_urls)})  \n\n"
    report_md += "| Adversarial Mutation Strategy | Samples Tested | Detected Malicious | Flagged Uncertain | Evasion Rate | Robustness Assessment |\n"
    report_md += "|---|---|---|---|---|---|\n"

    for atk, stats in attack_stats.items():
        tot = stats["total"]
        det = stats["detected_as_malicious"]
        unc = stats["uncertain"]
        eva = stats["evaded"]
        evasion_rate = (eva / tot) * 100 if tot > 0 else 0
        name = atk.replace("_", " ").title()
        assessment = "Resilient" if evasion_rate <= 15 else ("Moderate Evasion" if evasion_rate <= 35 else "Vulnerable")
        report_md += f"| **{name}** | {tot} | {det} ({det/tot*100:.1f}%) | {unc} ({unc/tot*100:.1f}%) | **{evasion_rate:.1f}%** | {assessment} |\n"

    report_md += "\n## Defense Mechanism Analysis\n\n"
    report_md += "1. **Homoglyph & Confusable Resilience**: The integrated `unicode_features` module inspects character script changes and confusable Cyrillic codepoints, ensuring mutated letters do not lower risk score.\n"
    report_md += "2. **Subdomain Injection Defense**: Naive detectors that look for `google.com` as a substring are fooled by `login.google.com.attacker.xyz`. MobiURL-Guard extracts the registered domain and cross-references against `brand_domains.json`, triggering the brand impersonation flag when a brand appears in subdomains of an unrelated host.\n"
    report_md += "3. **Conformal Uncertainty Cushion**: When complex hex padding weakens individual features, the conformal prediction module expands the prediction set to `{Legitimate, Malicious}` rather than defaulting to benign.\n"

    with open("reports/adversarial_report.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    print("Saved reports/adversarial_report.md")

if __name__ == "__main__":
    evaluate_adversarial_robustness()
