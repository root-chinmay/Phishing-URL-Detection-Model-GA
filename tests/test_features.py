import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))
from src.features.url_features import extract_url_vector, extract_url_feature_dict, FEATURE_NAMES
from src.features.entropy_features import calculate_shannon_entropy, extract_entropy_features
from src.features.unicode_features import count_homoglyphs, extract_unicode_features, is_punycode
from src.features.brand_detection import extract_brand_impersonation_features

def test_extract_url_vector_length():
    url = "https://www.example.com/test?param=1"
    vec = extract_url_vector(url)
    assert len(vec) == len(FEATURE_NAMES)
    assert len(vec) == 28

def test_entropy_computation():
    ent_low = calculate_shannon_entropy("aaaaaa")
    ent_high = calculate_shannon_entropy("a8!d9#Z1?q")
    assert ent_low == 0.0
    assert ent_high > 3.0

def test_homoglyph_detection():
    # Cyrillic 'а' (U+0430) mimicking Latin 'a'
    homoglyph_str = "pаypal.com"
    count = count_homoglyphs(homoglyph_str)
    assert count >= 1

def test_punycode_detection():
    assert is_punycode("xn--pypal-4ve.com") == 1
    assert is_punycode("paypal.com") == 0

def test_brand_impersonation_flags():
    brand_url = "https://login-paypal-verify.com.attacker.xyz/auth"
    feats = extract_brand_impersonation_features("login-paypal-verify.com.attacker.xyz", brand_url)
    assert feats["brand_impersonation_flag"] == 1
