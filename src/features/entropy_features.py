import math
from collections import Counter
from urllib.parse import urlparse

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per symbol)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_entropy_features(url: str) -> dict:
    """Extract Shannon entropy across URL segments: full URL, hostname, path, query."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return {
        "entropy_url": calculate_shannon_entropy(url),
        "entropy_hostname": calculate_shannon_entropy(parsed.hostname or ""),
        "entropy_path": calculate_shannon_entropy(parsed.path or ""),
        "entropy_query": calculate_shannon_entropy(parsed.query or "")
    }
