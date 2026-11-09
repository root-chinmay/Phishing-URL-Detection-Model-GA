import os
import sys
import pytest
import pandas as pd

sys.path.insert(0, os.path.abspath("."))
from src.data.loader import load_and_validate_dataset, canonicalize_url, extract_registered_domain
from src.data.splitting import create_random_stratified_split, create_domain_disjoint_split

def test_canonicalize_url():
    assert canonicalize_url("HTTP://Example.COM/Path/") == "http://example.com/Path"
    assert canonicalize_url("https://sub.domain.org?a=1&b=2") == "https://sub.domain.org?a=1&b=2"
    assert canonicalize_url("google.com") == "http://google.com"

def test_extract_registered_domain():
    assert extract_registered_domain("http://sub.domain.co.uk/page") == "co.uk"
    assert extract_registered_domain("https://login.paypal.com") == "paypal.com"
    assert extract_registered_domain("http://192.168.1.1/admin") == "192.168.1.1"

def test_load_dataset_integrity():
    df = load_and_validate_dataset("data/raw/dataset.csv")
    assert len(df) > 1000
    assert "canonical_url" in df.columns
    assert "registered_domain" in df.columns
    assert "target" in df.columns
    assert set(df["target"].unique()).issubset({0, 1})

def test_domain_disjoint_split():
    df = load_and_validate_dataset("data/raw/dataset.csv")
    sample_df = df.head(500)
    train_df, test_df = create_domain_disjoint_split(sample_df, test_size=0.30, random_state=42)
    
    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, f"Domain overlap detected: {overlap}"
