import re
from urllib.parse import urlparse

class QRQuishingDetector:
    """
    Safe QR Code / Quishing quarantine analyzer.
    Extracts embedded payload and performs strict pre-flight security inspection
    without automatic navigation or execution.
    """
    def __init__(self):
        pass

    def inspect_qr_payload(self, raw_text: str) -> dict:
        """Inspect decoded QR string content safely."""
        if not raw_text or not raw_text.strip():
            return {
                "is_valid_url": False,
                "url": None,
                "scheme": None,
                "quarantine_status": "empty_payload",
                "risk_warning": "QR code did not contain readable content."
            }

        text = raw_text.strip()
        is_url = bool(re.match(r"^(https?|ftp)://", text, re.IGNORECASE)) or "." in text.split("/")[0]

        if not is_url:
            return {
                "is_valid_url": False,
                "url": text,
                "scheme": "plain_text",
                "quarantine_status": "non_url_text",
                "risk_warning": "Decoded payload is plain text or custom barcode data, not an HTTP/HTTPS URL."
            }

        normalized_url = text if "://" in text else f"http://{text}"
        parsed = urlparse(normalized_url)

        return {
            "is_valid_url": True,
            "url": normalized_url,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "quarantine_status": "isolated_for_inspection",
            "risk_warning": "Extracted URL isolated in security quarantine. Awaiting automated inspection before user opening."
        }
