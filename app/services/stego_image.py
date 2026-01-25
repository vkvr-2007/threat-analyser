import re
import math
from PIL import Image
import exifread


PRINTABLE_REGEX = re.compile(rb"[A-Za-z0-9+/=]{6,}|[ -~]{6,}")


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0
    length = len(data)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def extract_strings(data: bytes, min_len=6):
    matches = PRINTABLE_REGEX.findall(data)
    return [m.decode(errors="ignore") for m in matches]


def analyze_image_steganography(file_path: str) -> dict:
    findings = {
        "metadata_text": [],
        "raw_strings": [],
        "entropy": 0.0,
        "suspicious": False,
        "confidence": "Low"
    }

    # read raw bytes
    with open(file_path, "rb") as f:
        raw = f.read()

    findings["entropy"] = calculate_entropy(raw)

    # extract EXIF metadata
    try:
        with open(file_path, "rb") as img:
            tags = exifread.process_file(img, details=False)
            for tag, value in tags.items():
                val = str(value)
                if len(val) > 10:
                    findings["metadata_text"].append(val)
    except Exception:
        pass

    # extract readable strings from raw bytes
    strings = extract_strings(raw)
    findings["raw_strings"] = strings[:10]  # limit output

    # detection logic
    suspicious_hits = []

    for s in strings:
        if "http" in s.lower() or "cmd" in s.lower() or "powershell" in s.lower():
            suspicious_hits.append(s)

    # Explicit payload indicators = strong signal
    if suspicious_hits:
        findings["suspicious"] = True
        findings["confidence"] = "High"

    # High entropy alone is NOT steganography
    elif findings["entropy"] > 7.8:
        findings["suspicious"] = False
        findings["confidence"] = "Medium"

    else:
        findings["suspicious"] = False
        findings["confidence"] = "Low"

    return findings
