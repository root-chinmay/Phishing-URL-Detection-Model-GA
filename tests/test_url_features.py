import pytest
import os
import sys

sys.path.insert(0, os.path.abspath("."))
from src.features.url_features import extract_url_feature_dict, extract_url_vector, FEATURE_NAMES
from src.features.entropy_features import calculate_shannon_entropy
from src.features.unicode_features import is_punycode, count_homoglyphs
from src.features.brand_detection import extract_brand_impersonation_features

def test_feature_vector_dimension():
    vec = extract_url_vector("https://www.google.com/search?q=test")
    assert len(vec) == len(FEATURE_NAMES)
    assert len(vec) == 28

def test_entropy_calculation():
    # Identical string has 0 entropy
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    # High diversity string has high entropy
    assert calculate_shannon_entropy("a8!b9@c0#d1$") > 3.0

def test_punycode_detection():
    assert is_punycode("xn--pypal-4ve.com") is True
    assert is_punycode("paypal.com") is False

def test_homoglyph_detection():
    # Cyrillic 'а'
    assert count_homoglyphs("pаypal.com") > 0
    assert count_homoglyphs("paypal.com") == 0

def test_brand_impersonation_detection():
    # Impersonation attempt
    res = extract_brand_impersonation_features("paypa1-secure-login.xyz", "https://paypa1-secure-login.xyz")
    assert res["brand_impersonation_flag"] == 1
    assert res["impersonated_brand"] == "PayPal"

    # Official domain should not be flagged
    res_official = extract_brand_impersonation_features("paypal.com", "https://www.paypal.com")
    assert res_official["brand_impersonation_flag"] == 0
