import json
import os
import re
from difflib import SequenceMatcher

def load_brand_reference(config_path: str = "config/brand_domains.json") -> list:
    """Load configurable brand domains dictionary."""
    if not os.path.exists(config_path):
        # Fallback defaults if path differs
        return [
            {"name": "PayPal", "domains": ["paypal.com"], "aliases": ["paypal", "pay-pal", "paypa1"]},
            {"name": "Google", "domains": ["google.com"], "aliases": ["google", "gmail"]},
            {"name": "Apple", "domains": ["apple.com", "icloud.com"], "aliases": ["apple", "icloud"]},
            {"name": "Microsoft", "domains": ["microsoft.com", "live.com"], "aliases": ["microsoft", "office365"]},
            {"name": "Amazon", "domains": ["amazon.com"], "aliases": ["amazon", "amazn"]},
            {"name": "Netflix", "domains": ["netflix.com"], "aliases": ["netflix"]},
            {"name": "Chase", "domains": ["chase.com"], "aliases": ["chase"]}
        ]
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("brands", [])
    except Exception:
        return []

def calculate_similarity(s1: str, s2: str) -> float:
    """Calculate character-level normalized sequence similarity (0.0 to 1.0)."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

def extract_brand_impersonation_features(domain: str, full_url: str, brands: list = None) -> dict:
    """
    Examine whether a target brand name is suspiciously present in the domain, subdomains,
    or path without belonging to that brand's official registered domains.
    """
    if brands is None:
        brands = load_brand_reference()

    domain_lower = domain.lower()
    full_url_lower = full_url.lower()

    if not domain_lower:
        return {
            "brand_max_similarity": 0.0,
            "brand_impersonation_flag": 0,
            "brand_in_subdomain": 0,
            "brand_in_path": 0,
            "impersonated_brand": None
        }

    max_similarity = 0.0
    detected_brand = None
    is_impersonating = 0
    brand_in_subdomain = 0
    brand_in_path = 0

    # Clean domain to extract labels
    domain_clean = re.sub(r"^www\.", "", domain_lower)
    domain_labels = [lbl for lbl in domain_clean.split(".") if lbl]
    registered_domain = ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else domain_clean

    for brand in brands:
        brand_name = brand["name"]
        official_domains = [d.lower() for d in brand.get("domains", [])]
        aliases = [a.lower() for a in brand.get("aliases", [])]

        # Is this officially owned by the brand?
        is_official = any(domain_lower == d or domain_lower.endswith(f".{d}") for d in official_domains)
        if is_official:
            continue

        # Check alias similarity against registered domain core and tokens
        core_domain = domain_labels[-2] if len(domain_labels) >= 2 else (domain_labels[0] if domain_labels else "")
        core_tokens = ([core_domain] + core_domain.split("-") + core_domain.split("_")) if core_domain else []
        for alias in aliases:
            # Substring exact check (e.g. paypal in paypal-login)
            if core_domain and alias in core_domain:
                max_similarity = 1.0
                detected_brand = brand_name
                is_impersonating = 1
                break

            # Token similarity check
            for tok in core_tokens:
                if not tok:
                    continue
                sim = calculate_similarity(alias, tok)
                if sim > max_similarity:
                    max_similarity = sim
                    if sim >= 0.75: # Close typo/variation (e.g. paypa1 vs paypal)
                        detected_brand = brand_name
                        is_impersonating = 1

            # Check if brand alias appears in subdomains of a different registered domain
            subdomains = ".".join(domain_labels[:-2]) if len(domain_labels) > 2 else ""
            if subdomains and alias in subdomains:
                brand_in_subdomain = 1
                detected_brand = brand_name
                is_impersonating = 1

            # Check if brand alias appears in path of an unrelated domain
            path_part = full_url_lower.split(domain_lower, 1)[-1] if (domain_lower and domain_lower in full_url_lower) else ""
            if alias in path_part:
                brand_in_path = 1
                if not detected_brand:
                    detected_brand = brand_name

    return {
        "brand_max_similarity": round(max_similarity, 4),
        "brand_impersonation_flag": is_impersonating,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "impersonated_brand": detected_brand
    }
