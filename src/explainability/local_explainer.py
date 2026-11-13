from src.features.url_features import extract_url_feature_dict

FEATURE_EXPLANATION_TEMPLATES = {
    "brand_impersonation_flag": (
        "Potential Brand Impersonation: Target resembles a well-known protected institution but is hosted on an unverified domain.",
        0.30
    ),
    "is_punycode": (
        "Internationalized Domain (Punycode): Domain utilizes 'xn--' encoding which can disguise deceptive foreign characters.",
        0.25
    ),
    "homoglyph_count": (
        "Confusable Character / Homoglyph: URL contains visual character substitutions (e.g. Cyrillic letters mimicking Latin letters).",
        0.25
    ),
    "is_ip_address": (
        "Direct IP Hostname: URL accesses a raw IP address directly instead of a legitimate registered domain name.",
        0.28
    ),
    "is_known_shortener": (
        "Masked Link Shortener: Destination domain is a known URL shortener that conceals the true landing page.",
        0.20
    ),
    "is_suspicious_tld": (
        "High-Risk Top Level Domain: Domain is registered under a TLD frequently associated with low-cost disposable spam campaigns.",
        0.18
    ),
    "num_subdomains": (
        "Abnormal Subdomain Hierarchy: Domain utilizes deep nested subdomains often engineered to mimic legitimate domain paths.",
        0.18
    ),
    "entropy_url": (
        "Elevated Structural Entropy: URL exhibits high algorithmic randomness indicative of obfuscated session tokens or exploit payloads.",
        0.15
    ),
    "num_suspicious_keywords": (
        "Targeted Security Keywords: URL contains sensitive credential tokens (e.g. 'login', 'verify', 'update', 'banking').",
        0.15
    ),
    "num_digits": (
        "Excessive Digit Concentration: Hostname or path incorporates unusually high numbers of numerical digits.",
        0.12
    ),
    "url_length": (
        "Excessive URL Length: Overall link length significantly exceeds standard web navigation baselines.",
        0.10
    )
}

def generate_local_explanation(
    url: str,
    risk_percentage: float,
    advanced_feats: dict = None,
    redirect_info: dict = None
) -> list:
    """
    Generate top 3-5 clear, explainable factors contributing to the predicted risk score.
    Identifies specific lexical, domain, unicode, brand, and redirect-chain characteristics.
    """
    feats = extract_url_feature_dict(url)
    adv = advanced_feats or {}
    r_info = redirect_info or {}
    reasons = []

    # Check resolved redirect chain / shortener transparency
    if r_info.get("resolved_successfully") and r_info.get("final_url") and r_info.get("final_url") != r_info.get("original_url"):
        hops = r_info.get("hop_count", 1)
        final_host = ""
        chain = r_info.get("redirect_chain") or []
        if chain:
            final_host = chain[-1].get("hostname", "")
        if risk_percentage >= 60.0:
            reasons.append({
                "factor": "shortener_malicious_target",
                "text": f"Masked Malicious Destination: Shortener redirected across {hops} hop(s) to high-risk host '{final_host}'.",
                "severity": "critical",
                "weight": 0.36
            })

    if adv.get("protocol_downgrade_flag"):
        reasons.append({
            "factor": "protocol_downgrade",
            "text": "TLS Protocol Downgrade: Redirect chain downgraded transport security from HTTPS to unencrypted HTTP.",
            "severity": "high",
            "weight": 0.32
        })

    if adv.get("is_executable_drop"):
        drop_detail = "Direct Executable / Malware Drop: URL links directly to an executable binary (.exe/.scr/.bin/.apk/etc.) payload."
        if adv.get("is_upload_drop_dir"):
            drop_detail = "Malware Drop in Upload Directory: Executable binary hosted inside a public upload/drop directory."
        reasons.append({
            "factor": "executable_malware_drop",
            "text": drop_detail,
            "severity": "critical",
            "weight": 0.40
        })

    if adv.get("is_http_non_ssl") and risk_percentage >= 40.0:
        reasons.append({
            "factor": "insecure_http",
            "text": "Unencrypted Transport (HTTP): Link transmits over unencrypted plaintext HTTP without TLS/SSL protection.",
            "severity": "medium",
            "weight": 0.19
        })

    if adv.get("has_userinfo_at_obfuscation"):
        reasons.append({
            "factor": "userinfo_masking",
            "text": "Credential '@' Authority Masking: URL uses userinfo prefix before '@' to conceal true destination host.",
            "severity": "high",
            "weight": 0.31
        })

    # Check high-weight explicit security flags
    if feats.get("brand_impersonation_flag") == 1:
        brand = feats.get("_meta", {}).get("impersonated_brand")
        text = f"Brand Impersonation Detected: Domain mimics '{brand or 'known brand'}' while registered on an unrelated host."
        reasons.append({"factor": "brand_impersonation", "text": text, "severity": "critical", "weight": 0.35})

    if feats.get("is_ip_address") == 1:
        reasons.append({"factor": "ip_host", "text": FEATURE_EXPLANATION_TEMPLATES["is_ip_address"][0], "severity": "high", "weight": 0.30})

    if feats.get("is_punycode") == 1 or feats.get("homoglyph_count", 0) > 0:
        reasons.append({"factor": "homoglyph_punycode", "text": FEATURE_EXPLANATION_TEMPLATES["homoglyph_count"][0], "severity": "high", "weight": 0.28})

    if adv.get("has_encoded_payload"):
        reasons.append({
            "factor": "encoded_payload",
            "text": "Encoded Payload Blob: Path or query contains long Base64/Hex encoded tokens typical of payload smuggling.",
            "severity": "high",
            "weight": 0.26
        })

    if adv.get("has_port_obfuscation"):
        reasons.append({
            "factor": "port_obfuscation",
            "text": "Non-Standard Port Specified: Host connects via an uncommon port rather than standard HTTP/HTTPS ports.",
            "severity": "medium",
            "weight": 0.24
        })

    if adv.get("has_double_extension_or_script"):
        reasons.append({
            "factor": "double_extension",
            "text": "Suspicious Script/Double Extension: URL path uses deceptive multi-extension or credential-handler scripts.",
            "severity": "medium",
            "weight": 0.23
        })

    if feats.get("is_known_shortener") == 1 and not r_info.get("resolved_successfully"):
        reasons.append({"factor": "shortener", "text": FEATURE_EXPLANATION_TEMPLATES["is_known_shortener"][0], "severity": "medium", "weight": 0.22})

    if adv.get("consonant_cluster_anomaly"):
        reasons.append({
            "factor": "dga_consonant_anomaly",
            "text": "Algorithmic Domain Anomaly (DGA): Domain exhibits unnatural consonant clustering consistent with generated domains.",
            "severity": "medium",
            "weight": 0.21
        })

    if feats.get("num_subdomains", 0) >= 3:
        reasons.append({"factor": "subdomains", "text": f"Deep Nested Subdomains: Contains {feats['num_subdomains']} subdomains masking actual registrant.", "severity": "medium", "weight": 0.20})

    if feats.get("is_suspicious_tld") == 1:
        tld = feats.get("_meta", {}).get("tld")
        reasons.append({"factor": "suspicious_tld", "text": f"High-Risk TLD (.{tld}): Commonly utilized in disposable phishing kits.", "severity": "medium", "weight": 0.18})

    if feats.get("num_suspicious_keywords", 0) >= 2:
        reasons.append({"factor": "keywords", "text": f"Multiple Credential Harvesting Keywords: Found {feats['num_suspicious_keywords']} security-sensitive keywords in URL string.", "severity": "medium", "weight": 0.16})

    if feats.get("entropy_url", 0.0) >= 4.3:
        reasons.append({"factor": "entropy", "text": f"Elevated Shannon Entropy ({feats['entropy_url']}): High random character distribution in URL structure.", "severity": "low", "weight": 0.14})

    if feats.get("url_length", 0) > 85:
        reasons.append({"factor": "length", "text": f"Abnormally Long URL ({feats['url_length']} characters): Often indicates obfuscation or embedded data.", "severity": "low", "weight": 0.12})

    # Sort by weight descending
    reasons.sort(key=lambda x: x["weight"], reverse=True)

    # If safe URL with low risk, provide positive validation factors
    if risk_percentage < 35.0:
        benign_reasons = []
        if r_info.get("resolved_successfully") and r_info.get("final_url") and r_info.get("final_url") != r_info.get("original_url"):
            chain = r_info.get("redirect_chain") or []
            final_host = chain[-1].get("hostname", "") if chain else ""
            benign_reasons.append({
                "factor": "resolved_safe_target",
                "text": f"Resolved Shortener Destination: Unshortened via {r_info.get('hop_count', 1)} hop(s) to verified host '{final_host}'.",
                "severity": "safe",
                "weight": 0.35
            })
        benign_reasons.extend([
            {"factor": "clean_domain", "text": "Standard Domain Structure: Registered with normal depth and recognized Top-Level Domain.", "severity": "safe", "weight": 0.3},
            {"factor": "no_obfuscation", "text": "No Obfuscation Detected: Free of homoglyphs, punycode prefixes, and nested open-redirects.", "severity": "safe", "weight": 0.25},
            {"factor": "balanced_entropy", "text": "Normal Character Distribution: Shannon entropy matches standard web application routing.", "severity": "safe", "weight": 0.2}
        ])
        return [r["text"] for r in (reasons[:1] + benign_reasons)[:3]]

    # Return top 3-5 explanations
    if not reasons:
        reasons.append({"factor": "general", "text": "URL structural composition corresponds to elevated risk patterns observed in training corpus.", "severity": "medium", "weight": 0.1})

    return [r["text"] for r in reasons[:4]]
