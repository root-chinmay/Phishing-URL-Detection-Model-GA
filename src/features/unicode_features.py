import unicodedata
import re

# Cyrillic, Greek, and other Unicode characters that visually resemble Latin ASCII letters
CONFUSABLE_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    'α': 'a', 'β': 'b', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'ω': 'w',
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9'
}

def is_punycode(domain: str) -> bool:
    """Check if domain contains Punycode prefix (xn--)."""
    return "xn--" in domain.lower()

def detect_mixed_scripts(text: str) -> bool:
    """Detect presence of mixed Latin and non-Latin scripts (e.g. Cyrillic + Latin)."""
    scripts = set()
    for char in text:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            elif "HEBREW" in name:
                scripts.add("HEBREW")
            elif "DEVANAGARI" in name:
                scripts.add("DEVANAGARI")
        except ValueError:
            pass
    return len(scripts) > 1

def count_homoglyphs(text: str) -> int:
    """Count number of known confusable homoglyphic characters."""
    count = 0
    for char in text:
        if char in CONFUSABLE_MAP:
            count += 1
    return count

def extract_unicode_features(domain: str) -> dict:
    """Extract all Unicode, Punycode and homoglyph risk indicators."""
    has_punycode = 1 if is_punycode(domain) else 0
    has_mixed_script = 1 if detect_mixed_scripts(domain) else 0
    homoglyph_cnt = count_homoglyphs(domain)
    has_non_ascii = 1 if any(ord(c) > 127 for c in domain) else 0

    return {
        "is_punycode": has_punycode,
        "is_mixed_script": has_mixed_script,
        "homoglyph_count": homoglyph_cnt,
        "has_non_ascii": has_non_ascii
    }
