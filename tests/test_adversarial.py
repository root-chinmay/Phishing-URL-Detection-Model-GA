import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))
from src.security.adversarial import AdversarialURLPerturber

def test_adversarial_mutations():
    perturber = AdversarialURLPerturber()
    url = "https://paypal-security-update.com/login"

    suite = perturber.generate_adversarial_suite(url)
    assert "homoglyph_attack" in suite
    assert "subdomain_injection" in suite
    assert "percent_obfuscation" in suite
    assert "typosquatting" in suite
    assert "nested_redirect" in suite

    # Verify mutations modified URL string
    assert suite["homoglyph_attack"] != url or "xn--" in suite["homoglyph_attack"]
    assert "paypal" in suite["subdomain_injection"]
