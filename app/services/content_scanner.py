import base64
import binascii
import re





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


def is_base64_string(s: str) -> bool:
    s = s.strip()
    if len(s) < 8:
        return False
    if len(s) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=]+", s) is not None


def try_decode_base64(s: str):
    try:
        decoded = base64.b64decode(s, validate=True)
        decoded_text = decoded.decode("utf-8", errors="ignore")
        if decoded_text.strip():
            return decoded_text
    except Exception:
        pass
    return None


def is_hex_string(s: str) -> bool:
    s = s.strip()
    if len(s) < 8 or len(s) % 2 != 0:
        return False
    return re.fullmatch(r"[0-9a-fA-F]+", s) is not None


def try_decode_hex(s: str):
    try:
        decoded = bytes.fromhex(s)
        decoded_text = decoded.decode("utf-8", errors="ignore")
        if decoded_text.strip():
            return decoded_text
    except Exception:
        pass
    return None




def scan_text_for_encodings(text: str) -> dict:
    """
    Detects and safely decodes reversible encodings.
    DOES NOT execute anything.
    """

    decoded_payloads = []

    lines = text.splitlines()

    for line in lines:
        s = line.strip()

        # --- BASE64 ---
        if len(s) >= 8 and len(s) % 4 == 0:
            if re.fullmatch(r"[A-Za-z0-9+/=]+", s):
                try:
                    decoded = base64.b64decode(s, validate=True)
                    decoded_text = decoded.decode("utf-8", errors="ignore")
                    if decoded_text.strip():
                        decoded_payloads.append({
                            "encoding": "base64",
                            "original": s,
                            "decoded": decoded_text
                        })
                except Exception:
                    pass

        # --- HEX ---
        if len(s) >= 8 and len(s) % 2 == 0:
            if re.fullmatch(r"[0-9a-fA-F]+", s):
                try:
                    decoded = bytes.fromhex(s)
                    decoded_text = decoded.decode("utf-8", errors="ignore")
                    if decoded_text.strip():
                        decoded_payloads.append({
                            "encoding": "hex",
                            "original": s,
                            "decoded": decoded_text
                        })
                except Exception:
                    pass

    return {
        "payload_detected": bool(decoded_payloads),
        "decoded_payloads": decoded_payloads
    }