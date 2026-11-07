import re
from urllib.parse import urlparse

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "adf.ly"
}

def analyze_redirect_risk_offline(url: str) -> dict:
    """
    Offline analysis of redirect risks: detects known URL shorteners,
    suspicious open redirect parameters (url=, redirect=, dest=, target=, link=),
    and cross-domain forwarding patterns without sending network requests.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()
    query = parsed.query or ""

    is_shortener = hostname in KNOWN_SHORTENERS

    # Check for redirect query parameters
    redirect_params = ["url", "redirect", "dest", "target", "link", "next", "return", "goto"]
    found_params = []
    embedded_target = None

    for param in redirect_params:
        pattern = re.compile(rf"[?&]{param}=([^&]+)", re.IGNORECASE)
        match = pattern.search(url)
        if match:
            found_params.append(param)
            embedded_target = match.group(1)

    has_redirect_lure = len(found_params) > 0

    return {
        "is_shortener": is_shortener,
        "has_redirect_parameters": has_redirect_lure,
        "redirect_parameters_found": found_params,
        "potential_embedded_target": embedded_target,
        "risk_explanation": (
            "URL uses a known link shortener which masks the final destination." if is_shortener
            else ("URL contains potential open-redirect parameters." if has_redirect_lure
            else "No suspicious redirect parameters identified in URL structure.")
        )
    }
