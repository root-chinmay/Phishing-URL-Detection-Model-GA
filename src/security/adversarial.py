import random
from urllib.parse import urlparse

# Homoglyph substitution map for adversarial perturbation
ADVERSARIAL_HOMOGLYPHS = {
    'a': 'а',  # Cyrillic small letter a
    'e': 'е',  # Cyrillic small letter ie
    'o': 'о',  # Cyrillic small letter o
    'p': 'р',  # Cyrillic small letter er
    'c': 'с',  # Cyrillic small letter es
    'y': 'у',  # Cyrillic small letter u
    'x': 'х',  # Cyrillic small letter ha
    'i': 'і',  # Ukrainian i
}

class AdversarialURLPerturber:
    """
    Controlled adversarial URL perturbation generator.
    Produces realistic evasion transformations for robustness benchmarking.
    Does NOT deploy active malicious infrastructure; uses reserved .test domains when creating samples.
    """
    def __init__(self, seed: int = 42):
        random.seed(seed)

    def apply_homoglyph_attack(self, url: str) -> str:
        """Substitute Latin characters in domain with visually identical Cyrillic homoglyphs."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        new_chars = []
        replaced = False
        for c in host:
            if not replaced and c.lower() in ADVERSARIAL_HOMOGLYPHS and random.random() < 0.6:
                new_chars.append(ADVERSARIAL_HOMOGLYPHS[c.lower()])
                replaced = True
            else:
                new_chars.append(c)
        perturbed_host = "".join(new_chars)
        return url.replace(host, perturbed_host, 1)

    def apply_subdomain_injection(self, url: str) -> str:
        """Inject trusted brand names as prefix subdomains to fool naive lexical matchers."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        trusted_prefix = random.choice(["login.google.com", "secure.paypal.com", "account.apple.com"])
        perturbed_host = f"{trusted_prefix}.{host}"
        return url.replace(host, perturbed_host, 1)

    def apply_percent_encoding_obfuscation(self, url: str) -> str:
        """Encode common characters in URL path into percent hex representations (%2f, %2e)."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        path = parsed.path
        if not path or path == "/":
            path = "/verify-account"
        obfuscated_path = path.replace("e", "%65").replace("a", "%61").replace("o", "%6f")
        return url.replace(parsed.path, obfuscated_path, 1)

    def apply_typosquatting(self, url: str) -> str:
        """Introduce single-character typo/omission/transposition in registered domain."""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        parts = host.split(".")
        if len(parts) >= 2:
            target = parts[-2]
            if len(target) > 3:
                # Transpose two characters or swap character
                idx = random.randint(1, len(target) - 2)
                mutated = target[:idx] + target[idx+1] + target[idx] + target[idx+2:]
                parts[-2] = mutated
                new_host = ".".join(parts)
                return url.replace(host, new_host, 1)
        return url

    def apply_nested_redirect(self, url: str) -> str:
        """Wrap target inside open-redirect query parameter on intermediary domain."""
        intermediary = "https://safe-gateway.test/redirect?dest="
        return f"{intermediary}{url}"

    def generate_adversarial_suite(self, url: str) -> dict:
        """Generate full suite of adversarial perturbations for a given URL."""
        return {
            "original": url,
            "homoglyph_attack": self.apply_homoglyph_attack(url),
            "subdomain_injection": self.apply_subdomain_injection(url),
            "percent_obfuscation": self.apply_percent_encoding_obfuscation(url),
            "typosquatting": self.apply_typosquatting(url),
            "nested_redirect": self.apply_nested_redirect(url)
        }
