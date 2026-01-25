import re
import base64
import binascii


# Regex patterns
BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
HEX_REGEX = re.compile(r"(?:[0-9a-fA-F]{2}\s*){12,}")

SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "bash", "curl", "wget",
    "http://", "https://", "ftp://",
    "install", "execute", "payload", "c2", "connect"
]


def extract_ascii_strings(data: bytes, min_len=6):
    """
    Extract readable ASCII strings from binary data
    """
    results = []
    current = b""

    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                results.append(current.decode(errors="ignore"))
            current = b""

    if len(current) >= min_len:
        results.append(current.decode(errors="ignore"))

    return results


def analyze_text_binary_steganography(file_path: str) -> dict:
    findings = {
        "ascii_strings": [],
        "base64_detected": False,
        "hex_detected": False,
        "suspicious_keywords": [],
        "confidence": "Low"
    }

    with open(file_path, "rb") as f:
        raw = f.read()

    # 1️⃣ Extract readable strings
    strings = extract_ascii_strings(raw)
    findings["ascii_strings"] = strings[:10]

    # 2️⃣ Look for suspicious keywords
    for s in strings:
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in s.lower():
                findings["suspicious_keywords"].append(kw)

    # 3️⃣ Detect Base64 blobs
    if BASE64_REGEX.search(raw.decode(errors="ignore")):
        findings["base64_detected"] = True

    # 4️⃣ Detect Hex blobs
    if HEX_REGEX.search(raw.decode(errors="ignore")):
        findings["hex_detected"] = True

    # 5️⃣ Confidence logic (STRICT)
    if findings["suspicious_keywords"]:
        findings["confidence"] = "High"
    elif findings["base64_detected"] or findings["hex_detected"]:
        findings["confidence"] = "Medium"
    else:
        findings["confidence"] = "Low"

    return findings
