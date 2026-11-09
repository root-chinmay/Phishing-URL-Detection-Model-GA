import os
import re
import pandas as pd
from urllib.parse import urlparse

def canonicalize_url(url: str) -> str:
    """Canonicalize URL: normalize scheme, lower-case host, remove default port, strip trailing slash."""
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")
    canonical = f"{scheme}://{hostname}{path}"
    if parsed.query:
        canonical += f"?{parsed.query}"
    return canonical

def extract_registered_domain(url: str) -> str:
    """Extract base registered domain for domain-disjoint splitting."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return hostname
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname

def load_and_validate_dataset(csv_path: str = "data/raw/dataset.csv") -> pd.DataFrame:
    """Load dataset, validate schema, canonicalize URLs, and remove exact duplicates."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found at: {csv_path}")

    df = pd.read_csv(csv_path)

    # Normalize column names
    col_map = {c: c.strip().lower() for c in df.columns}
    df = df.rename(columns=col_map)

    # Identify URL and label columns
    url_col = "url" if "url" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else ("result" if "result" in df.columns else df.columns[1])

    # Filter out empty rows
    df = df.dropna(subset=[url_col, label_col])
    
    # Canonicalize
    df["canonical_url"] = df[url_col].apply(canonicalize_url)
    df["registered_domain"] = df["canonical_url"].apply(extract_registered_domain)
    
    # Standardize label (0 = benign, 1 = malicious)
    def normalize_label(val):
        if str(val).lower() in ["1", "1.0", "malicious", "phishing", "bad"]:
            return 1
        return 0

    df["target"] = df[label_col].apply(normalize_label)
    
    # Drop duplicate canonical URLs
    initial_len = len(df)
    df = df.drop_duplicates(subset=["canonical_url"]).reset_index(drop=True)
    dedup_len = len(df)

    print(f"Loaded {initial_len} records. Deduplicated to {dedup_len} unique URLs.")
    return df
