import re
import ipaddress
from urllib.parse import urlparse

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "adf.ly"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "info", "cc", "pw", "work", "loan", "site", "online",
    "vip", "click", "rest", "buzz", "gq", "ml", "cf", "tk", "ga"
}

def is_ip_address(hostname: str) -> bool:
    """Check if hostname is a raw IPv4 or IPv6 address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        # Check for port suffix
        clean = hostname.split(":")[0]
        try:
            ipaddress.ip_address(clean)
            return True
        except ValueError:
            return False

def extract_domain_features(url: str) -> dict:
    """Extract domain-level structural and reputational indicators."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    
    # Check IP host
    ip_host = 1 if is_ip_address(hostname) else 0

    # Shortener check
    is_shortener = 1 if hostname in KNOWN_SHORTENERS else 0

    # Subdomain depth
    labels = hostname.split(".")
    num_subdomains = max(0, len(labels) - 2) if len(labels) >= 2 else 0

    # TLD analysis
    tld = labels[-1] if len(labels) >= 1 else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Embedded domain inside path (e.g. example.com/login/paypal.com)
    path = parsed.path.lower()
    embedded_domain = 1 if any(ext in path for ext in [".com", ".net", ".org", ".xyz", ".top"]) else 0

    return {
        "hostname_length": len(hostname),
        "is_ip_address": ip_host,
        "is_known_shortener": is_shortener,
        "num_subdomains": num_subdomains,
        "is_suspicious_tld": is_suspicious_tld,
        "has_embedded_domain_in_path": embedded_domain,
        "tld": tld,
        "hostname": hostname
    }
