import re
from urllib.parse import urlparse
from src.features.entropy_features import extract_entropy_features, calculate_shannon_entropy
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


PHISHING_NGRAM_TOKENS = [
    "-login", "login-", "-verify", "verify-", "-secure", "secure-", "auth-",
    "-auth", "account-", "-account", "update-", "-update", ".com-", ".net-",
    "support-", "webscr", "signin-", "-signin", "cmd=", "session="
]


def extract_advanced_url_features(url: str, redirect_info: dict = None) -> dict:
    """
    Extract advanced obfuscation, DGA gibberish, payload encoding, shortener slug,
    and redirect-chain telemetry features for high-accuracy shortener and long-URL detection.
    """
    clean_url = (url or "").strip()
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = clean_url.lower()

    # 1. Path segment entropy & shortener slug analysis
    segments = [seg for seg in path.split("/") if seg]
    segment_entropies = [calculate_shannon_entropy(seg) for seg in segments]
    max_path_token_entropy = max(segment_entropies) if segment_entropies else 0.0
    shortener_slug_entropy = segment_entropies[0] if len(segments) >= 1 else 0.0

    # 2. Encoded payload detection (Base64 blobs or long Hex strings in path/query)
    path_query = f"{path}?{query}" if query else path
    has_hex_blob = bool(re.search(r"[0-9a-f]{24,}", path_query, re.IGNORECASE))
    has_b64_blob = bool(re.search(r"(eyJ[A-Za-z0-9_-]{10,}|aHR0c[A-Za-z0-9_-]{8,}|[A-Za-z0-9+/]{28,}={1,2})", path_query))
    has_encoded_payload = 1 if (has_hex_blob or has_b64_blob) else 0

    # 3. Consonant cluster / DGA gibberish anomaly in domain core
    host_labels = [lbl for lbl in hostname.split(".") if lbl and lbl != "www"]
    core_domain = host_labels[-2] if len(host_labels) >= 2 else (host_labels[0] if host_labels else "")
    alpha_chars = re.sub(r"[^a-z]", "", core_domain)
    consonant_clusters = re.findall(r"[bcdfghjklmnpqrstvwxyz]{5,}", alpha_chars)
    vowels = sum(1 for c in alpha_chars if c in "aeiou")
    vowel_ratio = (vowels / len(alpha_chars)) if alpha_chars else 0.4
    consonant_cluster_anomaly = 1 if (len(consonant_clusters) > 0 or (len(alpha_chars) >= 8 and vowel_ratio < 0.15)) else 0

    # 4. Digit run length in URL/domain
    digit_runs = re.findall(r"\d+", clean_url)
    max_consecutive_digits = max((len(run) for run in digit_runs), default=0)

    # 5. Non-standard port obfuscation & user@host credential masking
    port = parsed.port
    has_port_obfuscation = 1 if (port is not None and port not in (80, 443)) else 0
    has_userinfo_at_obfuscation = 1 if (parsed.username is not None or "@" in parsed.netloc) else 0

    # 6. Double extension or script lure combined with query/path traps
    has_double_extension_or_script = 1 if re.search(
        r"\.(com|net|org|pdf|doc|docx)\.(php|html|htm|exe|apk|zip|js)\b|/(login|signin|verify|auth)\.(php|asp|aspx|jsp)\b",
        url_lower
    ) else 0

    # 6b. Direct executable / malware binary payload drop detection (.exe, .scr, .bin, .msi, .apk, .bat, etc.)
    is_executable_drop = 1 if re.search(
        r"\.(exe|scr|bin|msi|apk|bat|cmd|vbs|vbe|dll|iso|hta|elf|sh|pif|dmg|pkg)(\?|$)",
        path.lower()
    ) else 0

    # 6c. Suspicious upload / file drop directory
    is_upload_drop_dir = 1 if re.search(
        r"/(uploads?|drop|files?|temp|attachments?|wp-content/uploads?|dl|download|bin)/",
        path.lower()
    ) else 0

    # 6d. Randomized hash / algorithmic token filename
    filename = segments[-1] if segments else ""
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    has_random_hash_filename = 1 if (
        len(stem) >= 8 and (
            bool(re.search(r"[0-9a-f]{16,}", stem, re.IGNORECASE))
            or (any(c.isdigit() for c in stem) and any(c.isalpha() for c in stem) and calculate_shannon_entropy(stem) >= 3.0)
        )
    ) else 0

    is_malware_drop_composite = 1 if (is_executable_drop and (is_upload_drop_dir or has_random_hash_filename)) else is_executable_drop
    is_http_non_ssl = 1 if parsed.scheme.lower() == "http" else 0

    # 7. Structural character n-gram phishing score
    ngram_hits = sum(1 for tok in PHISHING_NGRAM_TOKENS if tok in url_lower)
    char_ngram_phishing_score = round(min(1.0, ngram_hits * 0.25), 4)

    # 8. Redirect chain telemetry
    r_info = redirect_info or {}
    redirect_hop_count = int(r_info.get("hop_count", 0))
    cross_domain_redirect_count = int(r_info.get("cross_domain_redirects", 0))
    protocol_downgrade_flag = 1 if r_info.get("protocol_downgrade") else 0
    resolved_ok = bool(r_info.get("resolved_successfully", False))
    domain_feats = extract_domain_features(clean_url)
    is_shortener = bool(domain_feats.get("is_known_shortener"))

    return {
        "redirect_hop_count": redirect_hop_count,
        "cross_domain_redirect_count": cross_domain_redirect_count,
        "protocol_downgrade_flag": protocol_downgrade_flag,
        "shortener_resolved_flag": 1 if (is_shortener and resolved_ok) else 0,
        "shortener_unresolved_flag": 1 if (is_shortener and not resolved_ok) else 0,
        "shortener_slug_entropy": shortener_slug_entropy,
        "max_path_token_entropy": max_path_token_entropy,
        "has_encoded_payload": has_encoded_payload,
        "consonant_cluster_anomaly": consonant_cluster_anomaly,
        "max_consecutive_digits": max_consecutive_digits,
        "has_port_obfuscation": has_port_obfuscation,
        "has_double_extension_or_script": has_double_extension_or_script,
        "is_executable_drop": is_executable_drop,
        "is_upload_drop_dir": is_upload_drop_dir,
        "has_random_hash_filename": has_random_hash_filename,
        "is_malware_drop_composite": is_malware_drop_composite,
        "is_http_non_ssl": is_http_non_ssl,
        "has_userinfo_at_obfuscation": has_userinfo_at_obfuscation,
        "char_ngram_phishing_score": char_ngram_phishing_score,
        "vowel_ratio": round(vowel_ratio, 4)
    }

