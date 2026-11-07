import re
from urllib.parse import urlparse
from src.features.entropy_features import extract_entropy_features
from src.features.unicode_features import extract_unicode_features
from src.features.domain_features import extract_domain_features
from src.features.brand_detection import extract_brand_impersonation_features

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "banking", "update",
    "password", "credential", "auth", "confirm", "wallet", "support", "kyc",
    "free", "gift", "airdrop", "claim", "billing", "recover"
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_special_chars",
    "num_suspicious_keywords",
    "num_subdomains",
    "num_params",
    "num_percent_symbols",
    "has_at_symbol",
    "has_equal_symbol",
    "is_ip_address",
    "is_known_shortener",
    "is_suspicious_tld",
    "has_embedded_domain_in_path",
    "entropy_url",
    "entropy_hostname",
    "entropy_path",
    "entropy_query",
    "is_punycode",
    "is_mixed_script",
    "homoglyph_count",
    "brand_impersonation_flag"
]

def extract_url_feature_dict(url: str, brand_reference: list = None) -> dict:
    """Extract complete hierarchical feature dictionary for explainability and diagnostics."""
    clean_url = url.strip()
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Lexical features
    url_len = len(clean_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = clean_url.count(".")
    num_hyphens = clean_url.count("-")
    num_underscores = clean_url.count("_")
    num_slashes = clean_url.count("/")
    num_digits = sum(c.isdigit() for c in clean_url)
    num_special = sum(not c.isalnum() and c not in [":", "/", ".", "-", "_", "?", "=", "&"] for c in clean_url)

    url_lower = clean_url.lower()
    num_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    num_params = len(query.split("&")) if query else 0
    num_percent = clean_url.count("%")
    has_at = 1 if "@" in clean_url else 0
    has_equal = 1 if "=" in clean_url else 0

    # Modular components
    entropy_feats = extract_entropy_features(clean_url)
    domain_feats = extract_domain_features(clean_url)
    unicode_feats = extract_unicode_features(hostname)
    brand_feats = extract_brand_impersonation_features(hostname, clean_url, brand_reference)

    raw_dict = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_digits": num_digits,
        "num_special_chars": num_special,
        "num_suspicious_keywords": num_keywords,
        "num_subdomains": domain_feats["num_subdomains"],
        "num_params": num_params,
        "num_percent_symbols": num_percent,
        "has_at_symbol": has_at,
        "has_equal_symbol": has_equal,
        "is_ip_address": domain_feats["is_ip_address"],
        "is_known_shortener": domain_feats["is_known_shortener"],
        "is_suspicious_tld": domain_feats["is_suspicious_tld"],
        "has_embedded_domain_in_path": domain_feats["has_embedded_domain_in_path"],
        "entropy_url": entropy_feats["entropy_url"],
        "entropy_hostname": entropy_feats["entropy_hostname"],
        "entropy_path": entropy_feats["entropy_path"],
        "entropy_query": entropy_feats["entropy_query"],
        "is_punycode": unicode_feats["is_punycode"],
        "is_mixed_script": unicode_feats["is_mixed_script"],
        "homoglyph_count": unicode_feats["homoglyph_count"],
        "brand_impersonation_flag": brand_feats["brand_impersonation_flag"]
    }

    # Include qualitative metadata
    raw_dict["_meta"] = {
        "hostname": hostname,
        "tld": domain_feats["tld"],
        "impersonated_brand": brand_feats.get("impersonated_brand"),
        "brand_max_similarity": brand_feats.get("brand_max_similarity", 0.0)
    }

    return raw_dict

def extract_url_vector(url: str, brand_reference: list = None) -> list:
    """Extract ordered numeric feature vector matching FEATURE_NAMES."""
    feats = extract_url_feature_dict(url, brand_reference)
    return [float(feats[name]) for name in FEATURE_NAMES]
