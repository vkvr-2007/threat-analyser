def scan_content(text: str) -> dict:
    """
    Lightweight content scanning (non-ML)
    """

    text = text.lower()

    credential_keywords = ["login", "signin", "verify", "password", "account"]
    urgency_keywords = ["urgent", "immediately", "suspended", "action required"]

    credential_hits = [k for k in credential_keywords if k in text]
    urgency_hits = [k for k in urgency_keywords if k in text]

    return {
        "credential_indicators": credential_hits,
        "urgency_indicators": urgency_hits,
        "has_suspicious_content": bool(credential_hits or urgency_hits)
    }
