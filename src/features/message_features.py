import re

# Threat, urgency, and credential lure keywords
URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "suspended", "disabled", "unauthorized",
    "24 hours", "expired", "expire", "critical", "warning", "locked", "freeze", "compromised"
]

CREDENTIAL_KEYWORDS = [
    "verify", "login", "password", "pin", "otp", "ssn", "credentials", "authenticate",
    "security question", "confirm your account", "update account", "validate"
]

FINANCIAL_PRIZE_KEYWORDS = [
    "won", "winner", "prize", "lottery", "claim", "refund", "bitcoin", "crypto",
    "bonus", "payout", "unpaid fee", "tracking fee", "package fee", "redelivery"
]

def extract_message_features(message_text: str = None) -> dict:
    """
    Extract linguistic and contextual features from user-provided message text (SMS, WhatsApp, email).
    If no text is supplied, returns non-informative zeros without fabricating indicators.
    """
    if not message_text or not message_text.strip():
        return {
            "has_message_context": 0,
            "urgency_score": 0.0,
            "credential_request_score": 0.0,
            "financial_lure_score": 0.0,
            "composite_message_risk": 0.0,
            "detected_urgency_tokens": [],
            "detected_credential_tokens": []
        }

    text_lower = message_text.lower()

    detected_urgency = [w for w in URGENCY_KEYWORDS if w in text_lower]
    detected_creds = [w for w in CREDENTIAL_KEYWORDS if w in text_lower]
    detected_prizes = [w for w in FINANCIAL_PRIZE_KEYWORDS if w in text_lower]

    urgency_score = min(len(detected_urgency) * 0.25, 1.0)
    cred_score = min(len(detected_creds) * 0.30, 1.0)
    prize_score = min(len(detected_prizes) * 0.25, 1.0)

    composite = round(0.4 * urgency_score + 0.4 * cred_score + 0.2 * prize_score, 4)

    return {
        "has_message_context": 1,
        "urgency_score": round(urgency_score, 4),
        "credential_request_score": round(cred_score, 4),
        "financial_lure_score": round(prize_score, 4),
        "composite_message_risk": composite,
        "detected_urgency_tokens": detected_urgency,
        "detected_credential_tokens": detected_creds
    }
